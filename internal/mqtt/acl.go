// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"strings"

	mochi "github.com/mochi-mqtt/server/v2"
)

// validFilter reports whether f is a valid MQTT topic filter.
func validFilter(f string) bool {
	return f != "" && mochi.IsValidFilter(f, false)
}

// allowed reports whether rules grant reading (subscribing to a filter, or
// receiving a message on a topic) or writing (publishing to a topic) topic.
// Nothing is allowed unless a rule grants it.
func allowed(rules []Rule, topic string, write bool) bool {
	if !write {
		// A shared subscription reads the filter after its group.
		if rest, ok := strings.CutPrefix(topic, "$share/"); ok {
			_, filter, found := strings.Cut(rest, "/")
			if !found {
				return false
			}
			topic = filter
		}
	}
	for _, r := range rules {
		grants := r.Access == ReadWrite || (write && r.Access == Write) || (!write && r.Access == Read)
		if grants && covers(r.Topic, topic) {
			return true
		}
	}
	return false
}

// covers reports whether everything filter matches is also matched by
// pattern. A topic is a filter without wildcards, so this also tells whether
// pattern matches a topic.
func covers(pattern, filter string) bool {
	p, f := strings.Split(pattern, "/"), strings.Split(filter, "/")
	// Wildcards at the first level never match a topic starting with $
	// [MQTT-4.7.2-1], such as $SYS: only a rule naming it does.
	if strings.HasPrefix(filter, "$") && (p[0] == "#" || p[0] == "+") {
		return false
	}
	for i, pl := range p {
		if pl == "#" {
			return true // the rest, including the parent level itself
		}
		if i >= len(f) {
			return false
		}
		switch fl := f[i]; {
		case fl == "#":
			return false // wider than this level of the pattern
		case pl == "+":
			continue // fl is one level, a name or +
		case fl == "+" || pl != fl:
			return false
		}
	}
	return len(f) == len(p)
}
