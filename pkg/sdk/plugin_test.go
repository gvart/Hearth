// SPDX-License-Identifier: Apache-2.0

package sdk

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestServe(t *testing.T) {
	var p *Plugin
	p = &Plugin{
		Name: "lamp", Version: "1.0",
		Discover: func(context.Context) ([]Device, error) {
			return []Device{{ID: "l", Name: "L", Entities: []Entity{{ID: "on", Name: "On", State: false}}}}, nil
		},
		Command: func(_ context.Context, c Command) (string, error) {
			if c.Name == "fail" {
				return "", errors.New("broken")
			}
			if err := p.SetState("l", "on", true); err != nil {
				return "", err
			}
			return c.Name + " " + c.Device + " " + string(c.Args), nil
		},
	}
	if err := p.SetState("l", "on", true); !errors.Is(err, ErrNotStarted) {
		t.Errorf("SetState before hello = %v", err)
	}
	in := strings.Join([]string{
		`{"type":"hello","protocol":1}`,
		``,
		`{"type":"ping","id":"1"}`,
		`{"type":"discover","id":"2"}`,
		`{"type":"command","id":"3","command":"turn_on","device":"l","args":{"x":1}}`,
		`{"type":"command","id":"4","command":"fail"}`,
		`{"type":"something-new","id":"5"}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	if err := p.Serve(t.Context(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"type":"hello","protocol":1,"name":"lamp","version":"1.0"}`,
		`{"type":"pong","id":"1"}`,
		`{"type":"devices","id":"2","devices":[{"id":"l","name":"L","entities":[{"id":"on","name":"On","state":false}]}]}`,
		`{"type":"state","device":"l","entity":"on","state":true}`,
		`{"type":"result","id":"3","ok":true,"output":"turn_on l {\"x\":1}"}`,
		`{"type":"result","id":"4","error":"broken"}`,
	}
	if got := strings.Split(strings.TrimSpace(out.String()), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestServeWithoutHandlers(t *testing.T) {
	t.Setenv("HEARTH_PLUGIN", "from-env")
	p := &Plugin{}
	var out bytes.Buffer
	in := `{"type":"hello","protocol":1}` + "\n" + `{"type":"discover","id":"1"}` + "\n" + `{"type":"command","id":"2","command":"x"}` + "\n"
	if err := p.Serve(t.Context(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	var hello, devs, res map[string]any
	for i, v := range []*map[string]any{&hello, &devs, &res} {
		if err := json.Unmarshal([]byte(lines[i]), v); err != nil {
			t.Fatal(err)
		}
	}
	if hello["name"] != "from-env" {
		t.Errorf("hello = %v", hello)
	}
	if d, ok := devs["devices"].([]any); !ok || len(d) != 0 {
		t.Errorf("devices = %v, want an empty list", devs)
	}
	if res["ok"] != nil || res["error"] == "" {
		t.Errorf("result = %v", res)
	}
}

func TestServeErrors(t *testing.T) {
	tests := []struct {
		name, in string
		cancel   bool
		wantErr  string
	}{
		{"not JSON", "nope\n", false, "not JSON"},
		{"too long", strings.Repeat("x", maxLine+2) + "\n", false, "longer than"},
		{"cancelled", `{"type":"ping","id":"1"}` + "\n", true, "context canceled"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			if tt.cancel {
				cancel()
			}
			defer cancel()
			err := (&Plugin{}).Serve(ctx, strings.NewReader(tt.in), &bytes.Buffer{})
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}
