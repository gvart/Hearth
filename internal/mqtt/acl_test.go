// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestCovers(t *testing.T) {
	tests := []struct {
		pattern, filter string
		want            bool
	}{
		{"sensors/#", "sensors/kitchen/temp", true},
		{"sensors/#", "sensors", true}, // # matches the parent level too
		{"sensors/#", "sensors/#", true},
		{"sensors/#", "sensors/+/temp", true},
		{"sensors/#", "sensorsX/a", false},
		{"sensors/#", "#", false},
		{"sensors/#", "+/temp", false},
		{"sensors/#", "other/a", false},
		{"sensors/+/temp", "sensors/kitchen/temp", true},
		{"sensors/+/temp", "sensors/+/temp", true},
		{"sensors/+/temp", "sensors/#", false},
		{"sensors/+/temp", "sensors/kitchen/humidity", false},
		{"sensors/+/temp", "sensors/kitchen/temp/x", false},
		{"sensors/+/temp", "sensors/kitchen", false},
		{"a/b", "a/b", true},
		{"a/b", "a/+", false},
		{"a/b", "a/b/c", false},
		{"+", "a", true},
		{"+", "a/b", false},
		{"#", "anything/at/all", true},
		{"#", "#", true},
		{"#", "$SYS/broker/clients", false},
		{"+/broker", "$SYS/broker", false},
		{"$SYS/#", "$SYS/broker/clients", true},
	}
	for _, tt := range tests {
		if got := covers(tt.pattern, tt.filter); got != tt.want {
			t.Errorf("covers(%q, %q) = %v, want %v", tt.pattern, tt.filter, got, tt.want)
		}
	}
}

func TestAllowed(t *testing.T) {
	rules := []Rule{
		{Topic: "sensors/#", Access: ReadWrite},
		{Topic: "cmd/lamp", Access: Write},
		{Topic: "status/#", Access: Read},
	}
	tests := []struct {
		topic string
		write bool
		want  bool
	}{
		{"sensors/a", true, true},
		{"sensors/a", false, true},
		{"cmd/lamp", true, true},
		{"cmd/lamp", false, false}, // write only
		{"status/lamp", false, true},
		{"status/lamp", true, false}, // read only
		{"other", false, false},
		{"other", true, false},
		{"$share/g/sensors/#", false, true},
		{"$share/g/other/#", false, false},
		{"$share/g", false, false},
	}
	for _, tt := range tests {
		if got := allowed(rules, tt.topic, tt.write); got != tt.want {
			t.Errorf("allowed(%q, write=%v) = %v, want %v", tt.topic, tt.write, got, tt.want)
		}
	}
	if allowed(nil, "a", false) || allowed(nil, "a", true) {
		t.Error("no rules must allow nothing")
	}
}

func TestParseClients(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	good := "users:\n  - name: sensors\n    password_hash: " + string(hash) +
		"\n    allow:\n      - topic: sensors/#\n        access: readwrite\n" +
		"devices:\n  - id: abc\n    allow:\n      - topic: hearth/abc/#\n        access: write\n"
	c, err := ParseClients([]byte(good))
	if err != nil {
		t.Fatalf("ParseClients: %v", err)
	}
	if len(c.Users) != 1 || len(c.Devices) != 1 || c.Users[0].Allow[0].Access != ReadWrite {
		t.Fatalf("parsed %+v", c)
	}
	if c, err := ParseClients(nil); err != nil || len(c.Users) != 0 {
		t.Fatalf("empty file: %+v, %v", c, err)
	}

	user := func(name, h, rules string) string {
		return "users:\n  - name: " + name + "\n    password_hash: " + h + "\n    allow:\n" + rules
	}
	rule := func(topic, access string) string {
		return "      - topic: " + topic + "\n        access: " + access + "\n"
	}
	bad := map[string]string{
		"no name":         user(`""`, string(hash), ""),
		"colon in name":   user("device:abc", string(hash), ""),
		"slash in name":   user("a/b", string(hash), ""),
		"plain password":  user("u", "hunter2", ""),
		"no hash":         user("u", `""`, ""),
		"bad access":      user("u", string(hash), rule("a/#", "all")),
		"no access":       user("u", string(hash), rule("a/#", `""`)),
		"bad filter":      user("u", string(hash), rule("a/#/b", "read")),
		"empty filter":    user("u", string(hash), rule(`""`, "read")),
		"duplicate user":  user("u", string(hash), "") + "  - name: u\n    password_hash: " + string(hash) + "\n",
		"unknown field":   "users:\n  - name: u\n    password: hunter2\n",
		"device no id":    "devices:\n  - allow: []\n",
		"duplicate dev":   "devices:\n  - id: a\n  - id: a\n",
		"dev bad access":  "devices:\n  - id: a\n    allow:\n" + rule("a", "rw"),
		"not a list":      "users: 3\n",
		"top-level field": "anonymous: true\n",
	}
	for name, in := range bad {
		if _, err := ParseClients([]byte(in)); err == nil {
			t.Errorf("%s: ParseClients accepted\n%s", name, in)
		} else if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%s: error leaks the password: %v", name, err)
		}
	}
}
