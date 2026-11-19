// SPDX-License-Identifier: AGPL-3.0-only

package proxmox

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/proxmox/pvemock"
	"github.com/gvart/hearth/internal/policy"
)

// noPoll keeps the hub from reading the server again during a test.
const noPoll = time.Hour

var actionModes = map[string]policy.Mode{"held": policy.ModeConfirm, "not held": policy.ModeAllow}

// stopAfter stops guest 100 under mode, calling change once the hub's last
// poll is over and, for a held action, before it is approved.
func (f *fixture) stopAfter(t *testing.T, id string, mode policy.Mode, change func()) error {
	t.Helper()
	changeUnseen := func() {
		t.Helper()
		change()
		s, err := f.m.Snapshot(id)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(s.Guests, func(g Guest) bool { return g.VMID == 100 })
		if i < 0 || s.Guests[i].Name != "home-assistant" || s.Guests[i].Node != "pve1" {
			t.Fatalf("the hub polled during the test: %+v", s.Guests)
		}
	}
	if mode != policy.ModeConfirm {
		changeUnseen()
		_, err := f.m.Act(t.Context(), policy.ActorWeb, webActor, id, ActionRequest{Action: ActionStop, VMID: 100})
		return err
	}
	held, done := f.holdStop(t, id)
	changeUnseen()
	if err := f.pol.Decide(t.Context(), policy.ActorAdmin, "admin", held.ID, true); err != nil {
		t.Fatal(err)
	}
	return actResult(t, done)
}

func TestActionRefusedByAFreshRead(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*pvemock.Server)
		want   error
	}{
		"another guest": {func(s *pvemock.Server) { s.ReplaceGuest(100, KindLXC, "prod-database", "pve2") }, ErrGuestChanged},
		"renamed":       {func(s *pvemock.Server) { s.ReplaceGuest(100, KindVM, "prod-database", "pve1") }, ErrGuestChanged},
		"another kind":  {func(s *pvemock.Server) { s.ReplaceGuest(100, KindLXC, "home-assistant", "pve1") }, ErrGuestChanged},
		"gone":          {func(s *pvemock.Server) { s.RemoveGuest(100) }, ErrGuestNotFound},
		"read fails":    {func(s *pvemock.Server) { s.FailWith(http.StatusInternalServerError, "boom") }, ErrUnavailable},
		"token refused": {func(s *pvemock.Server) { s.FailWith(http.StatusUnauthorized, "") }, ErrUnavailable},
	} {
		for modeName, mode := range actionModes {
			t.Run(name+"/"+modeName, func(t *testing.T) {
				f := newPolledFixture(t, policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: mode}}, noPoll)
				info := f.add(t)

				err := f.stopAfter(t, info.ID, mode, func() { tc.change(f.mock) })

				if !errors.Is(err, tc.want) {
					t.Errorf("Act = %v, want %v", err, tc.want)
				}
				if got := f.mock.Posts(); len(got) != 0 {
					t.Errorf("the action was sent: %v", got)
				}
				if e := f.releaseEntry(t); !strings.HasPrefix(e.Result, "error:") {
					t.Errorf("audit result = %q, want the refusal", e.Result)
				}
			})
		}
	}
}

func TestEveryActionReadsTheGuestFirst(t *testing.T) {
	for action, vmid := range map[string]int{ActionStart: 101, ActionStop: 100, ActionReboot: 100} {
		t.Run(action, func(t *testing.T) {
			f := newPolledFixture(t, policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeAllow}}, noPoll)
			info := f.add(t)
			f.mock.ReplaceGuest(vmid, KindLXC, "prod-database", "pve2")

			_, err := f.m.Act(t.Context(), policy.ActorWeb, webActor, info.ID, ActionRequest{Action: action, VMID: vmid})

			if !errors.Is(err, ErrGuestChanged) {
				t.Errorf("Act = %v, want ErrGuestChanged", err)
			}
			if got := f.mock.Posts(); len(got) != 0 {
				t.Errorf("the action was sent: %v", got)
			}
		})
	}
}

func TestActionUsesTheNodeOfTheFreshRead(t *testing.T) {
	for modeName, mode := range actionModes {
		t.Run(modeName, func(t *testing.T) {
			f := newPolledFixture(t, policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: mode}}, noPoll)
			info := f.add(t)

			err := f.stopAfter(t, info.ID, mode, func() { f.mock.ReplaceGuest(100, KindVM, "home-assistant", "pve2") })
			if err != nil {
				t.Fatal(err)
			}

			const post = "/api2/json/nodes/pve2/qemu/100/status/stop"
			if got := f.mock.Posts(); !slices.Equal(got, []string{post}) {
				t.Errorf("POSTs = %v, want %s", got, post)
			}
			reqs := f.mock.Requests()
			i := slices.IndexFunc(reqs, func(r pvemock.Request) bool { return r.Method == http.MethodPost })
			if i < 1 || reqs[i-1].Method != http.MethodGet || reqs[i-1].Path != "/api2/json/cluster/resources" {
				t.Errorf("the request before the POST was not a read: %+v", reqs)
			}
			var detail struct {
				Node         string `json:"node"`
				ApprovedNode string `json:"approved_node"`
			}
			if err := json.Unmarshal(f.releaseEntry(t).Detail, &detail); err != nil {
				t.Fatal(err)
			}
			if detail.Node != "pve2" || detail.ApprovedNode != "pve1" {
				t.Errorf("audit detail = %+v, want node pve2, approved on pve1", detail)
			}
		})
	}
}

func TestReadGuestGivesUp(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)
	c := clientFor(t, srv)

	cancelled, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)
	t.Cleanup(cancel)
	for name, tc := range map[string]struct {
		ctx     context.Context
		timeout time.Duration
	}{
		"its timeout":           {t.Context(), 50 * time.Millisecond},
		"the request's context": {cancelled, time.Minute},
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, err := readGuest(tc.ctx, c, 100, tc.timeout)
			if !errors.Is(err, ErrUnavailable) {
				t.Errorf("readGuest = %v, want ErrUnavailable", err)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("readGuest took %s", d)
			}
		})
	}
}
