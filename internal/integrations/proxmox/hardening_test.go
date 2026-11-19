// SPDX-License-Identifier: AGPL-3.0-only

package proxmox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/integrations/proxmox/pvemock"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// waitGuest waits until the hub's last read of guest vmid satisfies ok.
func (f *fixture) waitGuest(t *testing.T, id string, vmid int, ok func(Guest) bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, err := f.m.Snapshot(id)
		if err != nil {
			t.Fatal(err)
		}
		if i := slices.IndexFunc(s.Guests, func(g Guest) bool { return g.VMID == vmid }); i >= 0 && ok(s.Guests[i]) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("guest %d never reached the expected state: %+v", vmid, s.Guests)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// holdStop asks to stop guest 100 and waits until it is held for approval.
func (f *fixture) holdStop(t *testing.T, id string) (store.Approval, <-chan error) {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		_, err := f.m.Act(t.Context(), policy.ActorWeb, webActor, id, ActionRequest{Action: ActionStop, VMID: 100})
		done <- err
	}()
	return f.waitHeld(t), done
}

func actResult(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatal("the held action did not end")
		return nil
	}
}

// releaseEntry is the audit entry that ended the hold of a stop.
func (f *fixture) releaseEntry(t *testing.T) store.AuditEntry {
	t.Helper()
	for _, e := range f.audit(t, policy.ProxmoxGuestStop) {
		if e.Decision == policy.Allow {
			return e
		}
	}
	t.Fatal("no audit entry released the hold")
	return store.AuditEntry{}
}

func TestApprovedActionRefusesAnotherGuest(t *testing.T) {
	confirm := policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeConfirm}}
	for name, tc := range map[string]struct{ kind, guest, node string }{
		"another kind, name and node": {KindLXC, "prod-database", "pve2"},
		"another name on the node":    {KindVM, "prod-database", "pve1"},
		"another kind, same name":     {KindLXC, "home-assistant", "pve1"},
		"another name after a move":   {KindVM, "prod-database", "pve2"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, confirm)
			info := f.add(t)
			held, done := f.holdStop(t, info.ID)

			f.mock.ReplaceGuest(100, tc.kind, tc.guest, tc.node)
			f.waitGuest(t, info.ID, 100, func(g Guest) bool { return g.Name == tc.guest && g.Kind == tc.kind })
			if err := f.pol.Decide(t.Context(), policy.ActorAdmin, "admin", held.ID, true, func(context.Context) error { return nil }); err != nil {
				t.Fatal(err)
			}

			if err := actResult(t, done); !errors.Is(err, ErrGuestChanged) {
				t.Errorf("Act = %v, want ErrGuestChanged", err)
			}
			if got := f.mock.Posts(); len(got) != 0 {
				t.Errorf("the action reached another guest: %v", got)
			}
			if e := f.releaseEntry(t); !strings.HasPrefix(e.Result, "error:") {
				t.Errorf("audit result = %q, want the refusal", e.Result)
			}
		})
	}
}

func TestApprovedActionFollowsAMigration(t *testing.T) {
	f := newFixture(t, policy.Config{Classes: map[policy.Class]policy.Mode{policy.Dangerous: policy.ModeConfirm}})
	info := f.add(t)
	held, done := f.holdStop(t, info.ID)

	f.mock.ReplaceGuest(100, KindVM, "home-assistant", "pve2")
	f.waitGuest(t, info.ID, 100, func(g Guest) bool { return g.Node == "pve2" })
	if err := f.pol.Decide(t.Context(), policy.ActorAdmin, "admin", held.ID, true, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := actResult(t, done); err != nil {
		t.Fatal(err)
	}

	if got, want := f.mock.Posts(), []string{"/api2/json/nodes/pve2/qemu/100/status/stop"}; !slices.Equal(got, want) {
		t.Errorf("POSTs = %v, want %v", got, want)
	}
	var detail struct {
		Node         string `json:"node"`
		ApprovedNode string `json:"approved_node"`
	}
	if err := json.Unmarshal(f.releaseEntry(t).Detail, &detail); err != nil {
		t.Fatal(err)
	}
	if detail.Node != "pve2" || detail.ApprovedNode != "pve1" {
		t.Errorf("audit detail = %+v, want the node used (pve2) and the node approved (pve1)", detail)
	}
}

// resourcesBody is a /cluster/resources answer with n entries.
func resourcesBody(n int) []byte {
	var b bytes.Buffer
	b.WriteString(`{"data":[`)
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{}`)
	}
	b.WriteString(`]}`)
	return b.Bytes()
}

func serveBody(t *testing.T, body []byte) *client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return clientFor(t, srv)
}

func TestResourcesCapsTheEntries(t *testing.T) {
	if got, err := serveBody(t, resourcesBody(maxResources)).resources(t.Context()); err != nil || len(got) != maxResources {
		t.Errorf("at the cap: %d entries, %v", len(got), err)
	}
	if got, err := serveBody(t, resourcesBody(maxResources+1)).resources(t.Context()); err == nil {
		t.Errorf("over the cap: %d entries and no error", len(got))
	}
}

func TestResourcesOfAHostileBodyStaySmall(t *testing.T) {
	// Valid JSON that fits maxBody: a cut-off body fails before it is decoded.
	c := serveBody(t, resourcesBody((maxBody-32)/3))

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := c.resources(t.Context())
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Error("a body of millions of entries was accepted")
	}
	const limit = 64 << 20
	if got := after.TotalAlloc - before.TotalAlloc; got > limit {
		t.Errorf("reading it allocated %d MiB, want at most %d MiB", got>>20, limit>>20)
	}
}

func TestResourcesReadsTheAnswerAroundData(t *testing.T) {
	for name, tc := range map[string]struct {
		body string
		want int
		ok   bool
	}{
		"fields before and after": {`{"message":"x","data":[{"type":"node"}],"success":1}`, 1, true},
		"no entries":              {`{"data":[]}`, 0, true},
		"null data":               {`{"data":null}`, 0, true},
		"no data":                 {`{"success":1}`, 0, false},
		"trailing garbage":        {`{"data":[]} x`, 0, false},
		"data is not a list":      {`{"data":{"a":1}}`, 0, false},
		"cut short":               {`{"data":[{"type":"node"}`, 0, false},
		"not JSON":                {`<html>`, 0, false},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := serveBody(t, []byte(tc.body)).resources(t.Context())
			if (err == nil) != tc.ok || len(got) != tc.want {
				t.Errorf("resources = %d entries, %v", len(got), err)
			}
		})
	}
}

func TestConvertRunsOutsideTheManagerLock(t *testing.T) {
	f := newFixture(t, policy.Config{})
	var blocked, calls atomic.Int32
	m := NewManager(Config{Store: f.st, Sealer: f.sealer, Policy: f.pol, PollInterval: time.Hour, SyncInterval: time.Hour})
	m.toEntities = func(res []resource) ([]Node, []Guest, []Storage) {
		free := make(chan struct{})
		go func() {
			m.Servers()
			close(free)
		}()
		select {
		case <-free:
		case <-time.After(500 * time.Millisecond):
			blocked.Add(1)
		}
		calls.Add(1)
		return convert(res)
	}
	r := &running{info: ServerInfo{Name: "lab"}, state: StateConnecting}
	var err error
	if r.client, err = newClient(Connection{URL: f.srv.URL, Token: pvemock.Token, Fingerprint: fingerprintOf(f.srv)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(r.client.close)
	m.read(context.Background(), r)
	if calls.Load() != 1 || blocked.Load() != 0 {
		t.Errorf("convert ran %d times, and held the manager's lock in %d of them", calls.Load(), blocked.Load())
	}
}

func TestNonFiniteNumbersStayServable(t *testing.T) {
	var res []resource
	body := `[{"type":"node","node":"pve1","status":"online","cpu":"NaN","mem":"Inf","maxmem":"-Infinity"},
		{"type":"qemu","vmid":100,"node":"pve1","name":"vm","cpu":"NaN"}]`
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatal(err)
	}
	nodes, guests, storage := convert(res)
	if _, err := json.Marshal(Snapshot{Nodes: nodes, Guests: guests, Storage: storage}); err != nil {
		t.Errorf("the snapshot cannot be served: %v", err)
	}
}

func TestConvertDropsOverlongFields(t *testing.T) {
	long := strings.Repeat("x", maxFieldLength+1)
	fits := strings.Repeat("x", maxFieldLength)
	guest := func(name, node, status string) resource {
		return resource{Type: KindVM, VMID: 100, Name: name, Node: node, Status: status}
	}
	for name, tc := range map[string]struct {
		res                   resource
		nodes, guests, stores int
	}{
		"a guest name that fits":  {guest(fits, "pve1", "running"), 0, 1, 0},
		"an overlong guest name":  {guest(long, "pve1", "running"), 0, 0, 0},
		"a guest's overlong node": {guest("vm", long, "running"), 0, 0, 0},
		"an overlong status":      {guest("vm", "pve1", long), 0, 0, 0},
		"an overlong node name":   {resource{Type: "node", Node: long, Status: "online"}, 0, 0, 0},
		"a node name that fits":   {resource{Type: "node", Node: fits, Status: "online"}, 1, 0, 0},
		"an overlong storage":     {resource{Type: "storage", Storage: long, Node: "pve1"}, 0, 0, 0},
		"overlong storage text":   {resource{Type: "storage", Storage: "nas", Node: "pve1", Content: long}, 0, 0, 0},
		"a storage that fits":     {resource{Type: "storage", Storage: fits, Node: "pve1"}, 0, 0, 1},
	} {
		t.Run(name, func(t *testing.T) {
			nodes, guests, storage := convert([]resource{tc.res})
			if len(nodes) != tc.nodes || len(guests) != tc.guests || len(storage) != tc.stores {
				t.Errorf("convert = %d nodes, %d guests, %d storage; want %d, %d, %d",
					len(nodes), len(guests), len(storage), tc.nodes, tc.guests, tc.stores)
			}
		})
	}
}

func TestOverlongGuestNameNeverReachesTheAuditLog(t *testing.T) {
	f := newFixture(t, policy.Config{})
	info := f.add(t)
	f.mock.ReplaceGuest(100, KindVM, strings.Repeat("x", 1<<20), "pve1")
	deadline := time.Now().Add(5 * time.Second)
	for {
		s, err := f.m.Snapshot(info.ID)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.ContainsFunc(s.Guests, func(g Guest) bool { return g.VMID == 100 }) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a guest with a 1 MiB name is still listed: %d guests", len(s.Guests))
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := f.m.Act(t.Context(), policy.ActorWeb, webActor, info.ID, ActionRequest{Action: ActionStop, VMID: 100}); !errors.Is(err, ErrGuestNotFound) {
		t.Errorf("Act = %v, want ErrGuestNotFound", err)
	}
	if a := f.audit(t, policy.ProxmoxGuestStop); len(a) != 0 {
		t.Errorf("audit entries = %d, want none", len(a))
	}
}
