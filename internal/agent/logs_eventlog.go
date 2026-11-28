// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"
	"unicode"

	"google.golang.org/protobuf/types/known/timestamppb"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// The Windows event log (eventlog:CHANNEL, #397) is read by readEventLog:
// on Windows through wevtapi.dll (logs_windows.go), elsewhere it refuses.
// What follows is the part that is the same on every platform: the
// channel's check, and an event's line out of its XML and message.

// maxEventChannel caps a channel's name: Windows allows 255 characters.
const maxEventChannel = 255

// validEventChannel reports whether name can be an event log channel:
// Application, System, Microsoft-Windows-Sysmon/Operational. The name is
// handed to EvtSubscribe and EvtQuery as the channel path, never put into
// a query.
func validEventChannel(name string) bool {
	if name == "" || len(name) > maxEventChannel {
		return false
	}
	for _, r := range name {
		if unicode.IsControl(r) || strings.ContainsRune(`\"<>|`, r) {
			return false
		}
	}
	return true
}

// eventXML is what an event's line takes from its XML (EvtRenderEventXml).
type eventXML struct {
	System struct {
		Provider struct {
			Name string `xml:"Name,attr"`
		} `xml:"Provider"`
		EventID     string `xml:"EventID"`
		Level       string `xml:"Level"`
		TimeCreated struct {
			SystemTime string `xml:"SystemTime,attr"`
		} `xml:"TimeCreated"`
		// EventRecordID only grows within a channel.
		EventRecordID uint64 `xml:"EventRecordID"`
	} `xml:"System"`
	// Data are the EventData values, and UserData its XML: the text of an
	// event whose provider has no message for it.
	Data     []string `xml:"EventData>Data"`
	UserData struct {
		Inner []byte `xml:",innerxml"`
	} `xml:"UserData"`
}

// eventLevels are the names of the standard event levels; 0 (LogAlways) is
// information.
var eventLevels = map[string]string{
	"0": "Information", "1": "Critical", "2": "Error", "3": "Warning", "4": "Information", "5": "Verbose",
}

// parseEvent reads an event's XML (EvtRenderEventXml).
func parseEvent(rendered []byte) (*eventXML, error) {
	var ev eventXML
	if err := xml.Unmarshal(rendered, &ev); err != nil {
		return nil, fmt.Errorf("read an event: %w", err)
	}
	return &ev, nil
}

// line is the event's log line, with message its formatted message (""
// when its provider has none): level, provider and event ID, then the text.
func (ev *eventXML) line(message string) *agentv1.LogLine {
	s := ev.System
	line := &agentv1.LogLine{}
	if t, err := time.Parse(time.RFC3339Nano, s.TimeCreated.SystemTime); err == nil {
		line.Ts = timestamppb.New(t)
	}
	level := eventLevels[strings.TrimSpace(s.Level)]
	if level == "" {
		level = "Level " + strings.TrimSpace(s.Level)
	}
	text := strings.TrimSpace(strings.ReplaceAll(message, "\r\n", "\n"))
	if text == "" {
		text = eventDataText(ev)
	}
	head := level
	if s.Provider.Name != "" {
		head += " " + s.Provider.Name
	}
	if id := strings.TrimSpace(s.EventID); id != "" {
		head += " " + id
	}
	line.Text = clipLine(strings.ToValidUTF8(head+": "+text, "�"))
	return line
}

// eventDataText is the text of an event without a message: its data
// values, or its UserData's XML.
func eventDataText(ev *eventXML) string {
	var data []string
	for _, d := range ev.Data {
		if d = strings.TrimSpace(d); d != "" {
			data = append(data, d)
		}
	}
	if len(data) > 0 {
		return "(no message) " + strings.Join(data, "; ")
	}
	if u := strings.TrimSpace(string(ev.UserData.Inner)); u != "" {
		return "(no message) " + u
	}
	return "(no message)"
}
