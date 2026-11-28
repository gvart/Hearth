// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"crypto/rand"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/gvart/hearth/internal/policy"
)

// A terminal session is recorded only when the person who opens it asks
// for it (?record=1), for a runbook draft. A recording keeps what the
// terminal shows, never what is typed: the shell echoes a command as it is
// typed, and a password prompt turns the echo off, so what is typed there
// is never on the screen and never recorded. It is held in this hub's
// memory only, never in the store (so neither replicated nor backed up) or
// any log, until a draft is made from it, it is discarded, or recordingTTL
// after its session ended.
const (
	// maxRecordingBytes bounds what one recording keeps; the rest of the
	// session is not recorded, and the terminal says so.
	maxRecordingBytes = 256 << 10
	// recordingTTL is how long a recording is kept after its session ends.
	recordingTTL = time.Hour
	// maxRecordings bounds the recordings this hub holds, live or not.
	maxRecordings = 8
)

var (
	// errRecordAIOff refuses a recorded session while AI is off: nothing
	// could be made of it.
	errRecordAIOff = fmt.Errorf("recording a session for a runbook needs AI: set it up in Settings, AI: %w", policy.ErrDenied)
	// errRecordingsFull refuses a recorded session while this hub holds
	// maxRecordings.
	errRecordingsFull = fmt.Errorf("this hub already holds %d recordings: make runbooks from them or discard them first: %w", maxRecordings, policy.ErrDenied)
)

// recording is one recorded terminal session.
type recording struct {
	id, device, deviceName string
	started                time.Time
	// ended is when the session ended; zero while it runs.
	ended time.Time
	out   []byte
	// full is set once out reached maxRecordingBytes.
	full bool
}

// recordings are the recordings this hub holds, by id.
type recordings struct {
	mu sync.Mutex
	// ttl is recordingTTL; tests shorten it.
	ttl time.Duration
	m   map[string]*recording
	// expiry deletes each ended recording when its ttl has passed.
	expiry map[string]*time.Timer
}

func newRecordings() *recordings {
	return &recordings{ttl: recordingTTL, m: map[string]*recording{}, expiry: map[string]*time.Timer{}}
}

// begin starts a recording of a session on device, or refuses it with
// errRecordingsFull.
func (rs *recordings) begin(device, name string, now time.Time) (*recording, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if len(rs.m) >= maxRecordings {
		return nil, errRecordingsFull
	}
	rec := &recording{id: strings.ToLower(rand.Text())[:16], device: device, deviceName: name, started: now}
	rs.m[rec.id] = rec
	return rec, nil
}

// room refuses a new recording while the hub holds maxRecordings.
func (rs *recordings) room() error {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if len(rs.m) >= maxRecordings {
		return errRecordingsFull
	}
	return nil
}

// write adds what the terminal showed to rec, up to maxRecordingBytes. It
// reports whether this write filled it.
func (rs *recordings) write(rec *recording, b []byte) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rec.full || rs.m[rec.id] != rec {
		return false
	}
	if room := maxRecordingBytes - len(rec.out); len(b) >= room {
		rec.out = append(rec.out, b[:room]...)
		rec.full = true
		return true
	}
	rec.out = append(rec.out, b...)
	return false
}

// finish marks rec's session ended, and deletes rec ttl later.
func (rs *recordings) finish(rec *recording, now time.Time) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if rs.m[rec.id] != rec {
		return
	}
	rec.ended = now
	id := rec.id
	rs.expiry[id] = time.AfterFunc(rs.ttl, func() { rs.drop(id) })
}

// drop deletes the recording id, and reports whether there was one.
func (rs *recordings) drop(id string) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rec, ok := rs.m[id]
	if !ok {
		return false
	}
	if t := rs.expiry[id]; t != nil {
		t.Stop()
	}
	delete(rs.expiry, id)
	delete(rs.m, id)
	// What the session showed goes with it: nothing keeps a reference.
	clear(rec.out)
	rec.out = nil
	return true
}

// get is a copy of the recording id of device.
func (rs *recordings) get(device, id string) (recording, bool) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rec, ok := rs.m[id]
	if !ok || rec.device != device {
		return recording{}, false
	}
	c := *rec
	c.out = slices.Clone(rec.out)
	return c, true
}

// RecordingJSON describes a recording, never what it holds.
type RecordingJSON struct {
	ID      string    `json:"id"`
	Device  string    `json:"device"`
	Started time.Time `json:"started"`
	// Ended is when its session ended; absent while it is recording.
	Ended *time.Time `json:"ended,omitempty"`
	// Expires is when it is deleted if no runbook is made from it.
	Expires *time.Time `json:"expires,omitempty"`
	Bytes   int        `json:"bytes"`
	Full    bool       `json:"full"`
}

// list describes the recordings of device, newest first.
func (rs *recordings) list(device string) []RecordingJSON {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	out := []RecordingJSON{}
	for _, rec := range rs.m {
		if rec.device == device {
			out = append(out, rec.describe(rs.ttl))
		}
	}
	slices.SortFunc(out, func(a, b RecordingJSON) int { return b.Started.Compare(a.Started) })
	return out
}

func (rec *recording) describe(ttl time.Duration) RecordingJSON {
	j := RecordingJSON{ID: rec.id, Device: rec.device, Started: rec.started, Bytes: len(rec.out), Full: rec.full}
	if !rec.ended.IsZero() {
		ended, expires := rec.ended, rec.ended.Add(ttl)
		j.Ended, j.Expires = &ended, &expires
	}
	return j
}

// recordingRoutes serves the recordings of a device: who may open its
// terminal may see that they exist and discard them, never what they hold.
// They are served by the hub holding the device's stream, which served its
// terminal and holds its recordings.
func (a *api) recordingRoutes(mux *http.ServeMux) {
	mux.Handle("GET /api/v1/devices/{id}/recordings", a.auth(a.proxyStream(a.listRecordings)))
	mux.Handle("DELETE /api/v1/devices/{id}/recordings/{rec}", a.auth(a.proxyStream(a.discardRecording)))
}

func (a *api) listRecordings(w http.ResponseWriter, r *http.Request) {
	dev, ok := a.recordingDevice(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recordings": a.recordings.list(dev)})
}

// discardRecording deletes a recording at once.
func (a *api) discardRecording(w http.ResponseWriter, r *http.Request) {
	dev, ok := a.recordingDevice(w, r)
	if !ok {
		return
	}
	if _, found := a.recordings.get(dev, r.PathValue("rec")); !found || !a.recordings.drop(r.PathValue("rec")) {
		writeNoRecording(w)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// recordingDevice is the id of the device in the path, or an answer and
// false.
func (a *api) recordingDevice(w http.ResponseWriter, r *http.Request) (string, bool) {
	dev, err := a.store.Devices().Get(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "no such device")
		return "", false
	}
	return dev.ID, true
}

func writeNoRecording(w http.ResponseWriter) {
	writeError(w, http.StatusNotFound, "not_found",
		"no such recording on this hub: a recording is kept only in the memory of the hub that served its terminal, "+
			"for an hour after the session, and goes once a runbook is made from it")
}

// screenText is what a terminal showed, as plain text: escape sequences
// (colours, cursor moves, titles) removed, a backspace taking back the
// character before it, and a carriage return without a line feed starting
// its line over, as a shell's line editor redraws it.
func screenText(b []byte) string {
	var out strings.Builder
	var line []rune
	flush := func() {
		out.WriteString(strings.TrimRight(string(line), " \t"))
		out.WriteByte('\n')
		line = line[:0]
	}
	for i := 0; i < len(b); {
		c := b[i]
		switch {
		case c == 0x1b && i+1 < len(b):
			i = skipEscape(b, i)
			continue
		case c == '\n':
			flush()
		case c == '\r':
			if i+1 >= len(b) || b[i+1] != '\n' {
				line = line[:0]
			}
		case c == '\b':
			if len(line) > 0 {
				line = line[:len(line)-1]
			}
		case c == '\t':
			line = append(line, '\t')
		case c < 0x20 || c == 0x7f:
			// Other control characters show nothing.
		default:
			r, n := utf8.DecodeRune(b[i:])
			if r != utf8.RuneError || n > 1 {
				line = append(line, r)
			}
			i += n
			continue
		}
		i++
	}
	if len(line) > 0 {
		flush()
	}
	// Runs of blank lines are one blank line.
	text := out.String()
	for strings.Contains(text, "\n\n\n") {
		text = strings.ReplaceAll(text, "\n\n\n", "\n\n")
	}
	return strings.TrimLeft(text, "\n")
}

// skipEscape returns the index after the escape sequence at b[i] (ESC).
func skipEscape(b []byte, i int) int {
	j := i + 1
	switch b[j] {
	case '[': // CSI: parameters, then one final byte
		for j++; j < len(b); j++ {
			if b[j] >= 0x40 && b[j] <= 0x7e {
				return j + 1
			}
		}
		return j
	case ']', 'P', '_', '^': // OSC, DCS, APC, PM: up to BEL or ESC \
		for j++; j < len(b); j++ {
			if b[j] == 0x07 {
				return j + 1
			}
			if b[j] == 0x1b && j+1 < len(b) && b[j+1] == '\\' {
				return j + 2
			}
		}
		return j
	case '(', ')', '*', '+', '#': // a character set: one more byte
		return min(j+2, len(b))
	}
	return j + 1
}
