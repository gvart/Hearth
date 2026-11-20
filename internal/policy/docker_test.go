// SPDX-License-Identifier: AGPL-3.0-only

package policy

import (
	"errors"
	"strings"
	"testing"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

func TestValidContainer(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		ref string
		ok  bool
	}{
		{"web", true},
		{"hearth-t64-test", true},
		{"stack_web_1", true},
		{"my.app", true},
		{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", true},
		{strings.Repeat("a", 128), true},
		{strings.Repeat("a", 129), false},
		{"", false},
		{"-web", false},
		{".web", false},
		{"_web", false},
		{"../images/json", false},
		{"..", false},
		{"a/b", false},
		{"/web", false},
		{"web?all=1", false},
		{"web#x", false},
		{"web%2fexec", false},
		{"web exec", false},
		{"web\n", false},
		{"wéb", false},
	} {
		if got := ValidContainer(tc.ref); got != tc.ok {
			t.Errorf("ValidContainer(%q) = %v, want %v", tc.ref, got, tc.ok)
		}
	}
}

func TestDockerWithinCeiling(t *testing.T) {
	t.Parallel()
	on := &agentv1.Ceiling{Docker: true}
	list := &agentv1.DockerRequest{Op: &agentv1.DockerRequest_List{List: &agentv1.DockerList{}}}
	action := func(verb, c string) *agentv1.DockerRequest {
		return &agentv1.DockerRequest{Op: &agentv1.DockerRequest_Action{Action: &agentv1.DockerAction{Verb: verb, Container: c}}}
	}
	logs := func(c string) *agentv1.DockerRequest {
		return &agentv1.DockerRequest{Op: &agentv1.DockerRequest_Logs{Logs: &agentv1.DockerLogs{Container: c, Tail: 10}}}
	}
	for _, tc := range []struct {
		name    string
		c       *agentv1.Ceiling
		req     *agentv1.DockerRequest
		beyond  bool // ErrBeyondCeiling
		invalid bool // ErrDenied, not beyond the ceiling
	}{
		{"list", on, list, false, false},
		{"start", on, action("start", "web"), false, false},
		{"stop", on, action("stop", "web"), false, false},
		{"restart", on, action("restart", "web"), false, false},
		{"logs", on, logs("web"), false, false},
		{"nil ceiling", nil, list, true, false},
		{"ceiling off", &agentv1.Ceiling{Logs: []string{"docker:*"}, Restart: []string{"docker:web"}}, action("restart", "web"), true, false},
		{"ceiling off logs", &agentv1.Ceiling{}, logs("web"), true, false},
		{"exec verb", on, action("exec", "web"), false, true},
		{"remove verb", on, action("remove", "web"), false, true},
		{"kill verb", on, action("kill", "web"), false, true},
		{"empty verb", on, action("", "web"), false, true},
		{"path in action", on, action("start", "../../images/create"), false, true},
		{"query in logs", on, logs("web?follow=1"), false, true},
		{"empty container", on, logs(""), false, true},
		{"no op", on, &agentv1.DockerRequest{}, false, true},
	} {
		err := DockerWithinCeiling(tc.c, tc.req)
		switch {
		case !tc.beyond && !tc.invalid:
			if err != nil {
				t.Errorf("%s: %v, want allowed", tc.name, err)
			}
		case tc.beyond:
			if !errors.Is(err, ErrBeyondCeiling) {
				t.Errorf("%s: %v, want beyond the ceiling", tc.name, err)
			}
		default:
			if !errors.Is(err, ErrDenied) || errors.Is(err, ErrBeyondCeiling) {
				t.Errorf("%s: %v, want denied as invalid", tc.name, err)
			}
		}
	}
	for a, want := range map[Action]Class{
		DeviceDockerList: Read, DeviceDockerLogs: Read,
		DeviceDockerStart: Safe, DeviceDockerStop: Safe, DeviceDockerRestart: Safe,
	} {
		if class, ok := ClassOf(a); !ok || class != want {
			t.Errorf("class of %s = %s, want %s", a, class, want)
		}
	}
}
