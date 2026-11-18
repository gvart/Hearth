// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"fmt"
	"strings"
)

// NewDeviceAlertsID is the id of the built-in new-device alert automation.
const NewDeviceAlertsID = "new-device-alerts"

// newDeviceAlertsYAML is the built-in automation; CHANNEL is replaced with
// the channel's name. It is queued, so every host one scan finds gets its
// notification.
const newDeviceAlertsYAML = `id: new-device-alerts
description: Notify about every host that joins the network, unless it is marked known or ignored.
mode: queued
triggers:
  - id: new
    type: network
    event: new
  - id: returned
    type: network
    event: returned
actions:
  - id: notify
    type: notify
    channel: CHANNEL
    title: '{{ if eq .Trigger.Event "new" }}New device on your network{{ else }}Device back on your network{{ end }}'
    message: '{{ with .Trigger.Name }}{{ . }} {{ end }}{{ .Trigger.IP }} ({{ .Trigger.MAC }}{{ with .Trigger.Vendor }}, {{ . }}{{ end }}{{ if .Trigger.Private }}, private address{{ end }}). Mark it known or ignored on the Devices page to silence it.'
`

// NewDeviceAlerts returns the built-in automation that notifies channel
// about every host network discovery finds for the first time, or back after
// an absence, unless it is marked known or ignored. It is rejected, like a
// file, if channel is not one of the hub's notification channels.
func NewDeviceAlerts(channel string, kinds Kinds) (*Automation, error) {
	if !idPattern.MatchString(channel) {
		return nil, fmt.Errorf("new-device alerts: %q is not a channel name", channel)
	}
	return Parse("built-in "+NewDeviceAlertsID, []byte(strings.Replace(newDeviceAlertsYAML, "CHANNEL", channel, 1)), kinds)
}
