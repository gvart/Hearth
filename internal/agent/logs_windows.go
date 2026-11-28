// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"context"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// wevtapi.dll, the Windows Event Log API. x/sys/windows has no wrapper for
// it, so these are called by hand; the DLL loads on the first stream.
var (
	wevtapi                      = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe             = wevtapi.NewProc("EvtSubscribe")
	procEvtQuery                 = wevtapi.NewProc("EvtQuery")
	procEvtNext                  = wevtapi.NewProc("EvtNext")
	procEvtRender                = wevtapi.NewProc("EvtRender")
	procEvtFormatMessage         = wevtapi.NewProc("EvtFormatMessage")
	procEvtOpenPublisherMetadata = wevtapi.NewProc("EvtOpenPublisherMetadata")
	procEvtClose                 = wevtapi.NewProc("EvtClose")
)

const (
	evtSubscribeToFutureEvents = 1
	evtQueryChannelPath        = 0x1
	evtQueryReverseDirection   = 0x200
	evtRenderEventXML          = 1
	evtFormatMessageEvent      = 1

	errorNoMoreItems              = windows.Errno(259)
	errorInsufficientBuffer       = windows.Errno(122)
	errorEvtChannelNotFound       = windows.Errno(15007)
	errorEvtUnresolvedValueInsert = windows.Errno(15029)

	// eventBatch is how many events one EvtNext call takes.
	eventBatch = 16
	// maxEventXML caps an event's rendered XML, in bytes, and
	// maxEventMessage its formatted message, in UTF-16 units: an event
	// over either is shown without it.
	maxEventXML     = 256 << 10
	maxEventMessage = 32 << 10
	// maxPublishers caps the providers whose message metadata one stream
	// keeps open.
	maxPublishers = 32
)

type evtHandle uintptr

func evtClose(h evtHandle) {
	if h != 0 {
		_, _, _ = procEvtClose.Call(uintptr(h))
	}
}

// readEventLog follows the event log channel, first adding its last tail
// events, until ctx is done; it returns nil then. It subscribes before it
// reads the tail, and drops the subscription's events the tail already had
// (by record number), so no event falls between the two.
func readEventLog(ctx context.Context, channel string, tail int, add func(*agentv1.LogLine)) error {
	if !validEventChannel(channel) {
		return fmt.Errorf("event log channel %q: not a channel name", channel)
	}
	if err := wevtapi.Load(); err != nil {
		return fmt.Errorf("load wevtapi.dll: %w", err)
	}
	path, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return fmt.Errorf("event log channel %q: %w", channel, err)
	}
	query, _ := windows.UTF16PtrFromString("*")

	// Manual reset, set at first, as Microsoft's pull subscription sample.
	signal, err := windows.CreateEvent(nil, 1, 1, nil)
	if err != nil {
		return fmt.Errorf("create an event: %w", err)
	}
	defer windows.CloseHandle(signal) //nolint:errcheck // closing
	stop, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		return fmt.Errorf("create an event: %w", err)
	}
	defer windows.CloseHandle(stop) //nolint:errcheck // closing

	r1, _, callErr := procEvtSubscribe.Call(0, uintptr(signal), uintptr(unsafe.Pointer(path)),
		uintptr(unsafe.Pointer(query)), 0, 0, 0, evtSubscribeToFutureEvents)
	if r1 == 0 {
		return channelError(channel, "subscribe to", callErr)
	}
	sub := evtHandle(r1)
	defer evtClose(sub)

	r := &eventReader{publishers: map[string]evtHandle{}}
	defer r.close()

	var last uint64
	if tail > 0 {
		r1, _, callErr = procEvtQuery.Call(0, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(query)),
			evtQueryChannelPath|evtQueryReverseDirection)
		if r1 == 0 {
			return channelError(channel, "read", callErr)
		}
		results := evtHandle(r1)
		var newestFirst []*agentv1.LogLine
		err := r.next(results, windows.INFINITE, func(line *agentv1.LogLine, id uint64) bool {
			newestFirst = append(newestFirst, line)
			last = max(last, id)
			return len(newestFirst) < tail
		})
		evtClose(results)
		if err != nil {
			return fmt.Errorf("read event log %s: %w", channel, err)
		}
		for i := len(newestFirst) - 1; i >= 0; i-- {
			add(newestFirst[i])
		}
	}

	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = windows.SetEvent(stop)
		case <-done:
		}
	}()
	for {
		ev, err := windows.WaitForMultipleObjects([]windows.Handle{signal, stop}, false, windows.INFINITE)
		if err != nil {
			return fmt.Errorf("wait for events: %w", err)
		}
		if ev != windows.WAIT_OBJECT_0 || ctx.Err() != nil {
			return nil
		}
		// Reset before draining: an event that comes during the drain sets
		// it again.
		_ = windows.ResetEvent(signal)
		err = r.next(sub, 0, func(line *agentv1.LogLine, id uint64) bool {
			if id == 0 || id > last {
				add(line)
				last = max(last, id)
			}
			return ctx.Err() == nil
		})
		if err != nil {
			return fmt.Errorf("read event log %s: %w", channel, err)
		}
	}
}

// channelError explains a failed EvtSubscribe or EvtQuery of channel.
func channelError(channel, what string, err error) error {
	if errors.Is(err, errorEvtChannelNotFound) {
		return fmt.Errorf("no event log channel %q on this device", channel)
	}
	return fmt.Errorf("%s event log %s: %w", what, channel, err)
}

// eventReader renders events, keeping the message metadata of their
// providers open for the stream.
type eventReader struct {
	publishers map[string]evtHandle
	xml        []uint16
	msg        []uint16
}

func (r *eventReader) close() {
	for _, h := range r.publishers {
		evtClose(h)
	}
	clear(r.publishers)
}

// next passes each event of results to each, rendered, until it returns
// false or results has none left (waiting up to timeout ms for more).
func (r *eventReader) next(results evtHandle, timeout uint32, each func(*agentv1.LogLine, uint64) bool) error {
	var handles [eventBatch]evtHandle
	for {
		var n uint32
		r1, _, err := procEvtNext.Call(uintptr(results), eventBatch, uintptr(unsafe.Pointer(&handles[0])),
			uintptr(timeout), 0, uintptr(unsafe.Pointer(&n)))
		if r1 == 0 {
			if errors.Is(err, errorNoMoreItems) || errors.Is(err, windows.ERROR_TIMEOUT) {
				return nil
			}
			return fmt.Errorf("EvtNext: %w", err)
		}
		more := true
		for i := range handles[:n] {
			if more {
				line, id := r.render(handles[i])
				more = each(line, id)
			}
			evtClose(handles[i])
		}
		if !more {
			return nil
		}
	}
}

// render is the line of event and its record number.
func (r *eventReader) render(event evtHandle) (*agentv1.LogLine, uint64) {
	raw, err := r.renderXML(event)
	if err != nil {
		return &agentv1.LogLine{Text: "(unreadable event: " + err.Error() + ")"}, 0
	}
	ev, err := parseEvent([]byte(windows.UTF16ToString(raw)))
	if err != nil {
		return &agentv1.LogLine{Text: "(unreadable event: " + err.Error() + ")"}, 0
	}
	return ev.line(r.message(ev.System.Provider.Name, event)), ev.System.EventRecordID
}

// renderXML renders event as XML, at most maxEventXML bytes of it.
func (r *eventReader) renderXML(event evtHandle) ([]uint16, error) {
	if r.xml == nil {
		r.xml = make([]uint16, 4<<10)
	}
	for {
		var used, props uint32
		r1, _, err := procEvtRender.Call(0, uintptr(event), evtRenderEventXML, uintptr(len(r.xml)*2),
			uintptr(unsafe.Pointer(&r.xml[0])), uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r1 != 0 {
			return r.xml[:min(int(used/2), len(r.xml))], nil
		}
		if !errors.Is(err, errorInsufficientBuffer) {
			return nil, fmt.Errorf("EvtRender: %w", err)
		}
		if used > maxEventXML {
			return nil, fmt.Errorf("event of %d bytes, over %d", used, maxEventXML)
		}
		r.xml = make([]uint16, used/2+1)
	}
}

// message is event's message from the metadata of its provider; "" when
// there is none.
func (r *eventReader) message(provider string, event evtHandle) string {
	pub := r.publisher(provider)
	if pub == 0 {
		return ""
	}
	if r.msg == nil {
		r.msg = make([]uint16, 2<<10)
	}
	for {
		var used uint32
		r1, _, err := procEvtFormatMessage.Call(uintptr(pub), uintptr(event), 0, 0, 0, evtFormatMessageEvent,
			uintptr(len(r.msg)), uintptr(unsafe.Pointer(&r.msg[0])), uintptr(unsafe.Pointer(&used)))
		switch {
		case r1 != 0, errors.Is(err, errorEvtUnresolvedValueInsert) && used > 0 && int(used) <= len(r.msg):
			return windows.UTF16ToString(r.msg[:min(int(used), len(r.msg))])
		case errors.Is(err, errorInsufficientBuffer) && used <= maxEventMessage:
			r.msg = make([]uint16, used)
		default:
			return ""
		}
	}
}

// publisher is the open message metadata of provider, 0 if it has none.
func (r *eventReader) publisher(provider string) evtHandle {
	if provider == "" {
		return 0
	}
	if h, ok := r.publishers[provider]; ok {
		return h
	}
	if len(r.publishers) >= maxPublishers {
		r.close()
	}
	var h evtHandle
	if p, err := windows.UTF16PtrFromString(provider); err == nil {
		r1, _, _ := procEvtOpenPublisherMetadata.Call(0, uintptr(unsafe.Pointer(p)), 0, 0, 0)
		h = evtHandle(r1)
	}
	r.publishers[provider] = h // 0 too: not looked up again
	return h
}
