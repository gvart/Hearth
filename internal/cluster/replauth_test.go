// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/hlc"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// newGateNet starts master m, which holds the hub CA key, and storage
// members s and s2, which do not. Every member still announces the roles of
// a master on the gossip: what a member says of its roles proves nothing.
func newGateNet(t *testing.T) *apNet {
	t.Helper()
	return newAPNetWith(t, 0, func(c *ReplicatorConfig) {
		if c.NodeID != "m" {
			c.Master = testMasterKey{}
		}
	}, "m", "s", "s2")
}

const evilCeiling = `{"terminal":true,"exec":true}`

// forgeCeiling writes, on mem's own database only, a ceiling for device pi,
// stamped as if master m wrote it, and returns its rows: what a compromised
// storage member would send.
func forgeCeiling(t *testing.T, mem *apMember) []store.Mutation {
	t.Helper()
	now := time.Now()
	_, ms, err := mem.st.ApplyLocalMutations(t.Context(), store.SetDeviceCeiling{
		Stamp:    store.Stamp{HLC: hlc.New(now), Origin: "m"},
		DeviceID: "pi", Ceiling: evilCeiling, UpdatedAt: now.UnixMilli(), UpdatedBy: "user/admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) == 0 || !store.GlobalTable(ms[0].Table) {
		t.Fatalf("forged rows %+v, want a global row", ms)
	}
	return ms
}

// localCeiling is device pi's ceiling in mem's own database, "" if none.
func localCeiling(t *testing.T, mem *apMember) string {
	t.Helper()
	rows, err := mem.st.ReadLocal(t.Context(), `SELECT ceiling FROM device_ceilings WHERE device_id = ?`, store.Values{"pi"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows.Vals) == 0 {
		return ""
	}
	s, _ := rows.Vals[0][0].(string)
	return s
}

var ceilingRef = []store.RowRef{{Table: "device_ceilings", Key: store.Values{"pi"}}}

// TestStorageMemberMergeOfGlobalRowsRefused: a member without the hub CA key
// sends global rows (a capability ceiling) straight to a master and to
// another storage member, as a merge (a write's copy, a hint, a hand-off or
// a read repair all arrive so): both refuse them. The sharded rows it relays
// are still taken.
func TestStorageMemberMergeOfGlobalRowsRefused(t *testing.T) {
	an := newGateNet(t)
	ctx := t.Context()
	forged := forgeCeiling(t, an.m("s"))
	for _, to := range []string{"m", "s2"} {
		_, err := an.m("s").rep.call(ctx, to, apRequest{Op: opMerge, Muts: forged})
		if !errors.Is(err, errNotMaster) || !strings.Contains(err.Error(), "older version") {
			t.Fatalf("merge of a forged ceiling into %s: %v, want errNotMaster", to, err)
		}
		if got := localCeiling(t, an.m(to)); got != "" {
			t.Fatalf("%s took the forged ceiling: %s", to, got)
		}
	}

	// A device the master wrote: a storage member relays its rows.
	if err := an.m("m").st.Devices().Upsert(ctx, device("pi", "pi")); err != nil {
		t.Fatal(err)
	}
	rows, err := an.m("m").st.ReadRows(ctx, []store.RowRef{{Table: "devices", Key: store.Values{"pi"}}})
	if err != nil || len(rows) != 1 {
		t.Fatalf("read the device: %v, %v", rows, err)
	}
	for _, to := range []string{"m", "s2"} {
		if _, err := an.m("s").rep.call(ctx, to, apRequest{Op: opMerge, Muts: rows}); err != nil {
			t.Fatalf("relay a device row to %s: %v", to, err)
		}
	}
	if _, ok := localDevice(t, an.m("s2"), "pi"); !ok {
		t.Fatal("s2 did not take the relayed device row")
	}
}

// TestStorageMemberCommandRefused: a member without the hub CA key cannot
// have another coordinate a command, which would write it in that member's
// name: not a global write, not a sharded one.
func TestStorageMemberCommandRefused(t *testing.T) {
	an := newGateNet(t)
	ctx := t.Context()
	for _, cmd := range []store.Command{
		store.SetDeviceCeiling{DeviceID: "pi", Ceiling: evilCeiling, UpdatedAt: time.Now().UnixMilli(), UpdatedBy: "user/admin"},
		store.SetPasswordHash{Hash: "evil"},
		store.MarkSeen{ID: "pi", Now: time.Now().UnixMilli()},
	} {
		b, err := store.EncodeCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		for _, to := range []string{"m", "s2"} {
			if _, err := an.m("s").rep.call(ctx, to, apRequest{Op: opApply, Cmd: b}); !errors.Is(err, errNotMaster) {
				t.Fatalf("%s sent to %s: %v, want errNotMaster", cmd.Op(), to, err)
			}
		}
	}
	if got := localCeiling(t, an.m("m")); got != "" {
		t.Fatalf("m wrote the ceiling: %s", got)
	}
	// Nor does it write a global row itself, through its store.
	err := an.m("s").st.DeviceCeilings().Set(ctx, "pi", []byte(evilCeiling), "user/admin", time.Now())
	if !errors.Is(err, errNotMaster) {
		t.Fatalf("storage member set a ceiling: %v, want errNotMaster", err)
	}
}

// TestStorageMemberHintsOfGlobalRowsDropped: global rows in the hints of a
// member without the key (kept while it was a master) are not delivered;
// its other hints are.
func TestStorageMemberHintsOfGlobalRowsDropped(t *testing.T) {
	an := newGateNet(t)
	ctx := t.Context()
	forged := forgeCeiling(t, an.m("s"))
	if err := an.m("m").st.Devices().Upsert(ctx, device("pi", "pi")); err != nil {
		t.Fatal(err)
	}
	rows, err := an.m("m").st.ReadRows(ctx, []store.RowRef{{Table: "devices", Key: store.Values{"pi"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := an.m("s").hints.Add("m", append(forged, rows...)); err != nil {
		t.Fatal(err)
	}
	an.m("s").rep.deliverHints(ctx)
	if got := localCeiling(t, an.m("m")); got != "" {
		t.Fatalf("m took a forged ceiling from a hint: %s", got)
	}
	if n, err := an.m("s").hints.Count(ctx, "m"); err != nil || n != 0 {
		t.Fatalf("hints left for m: %d, %v", n, err)
	}
}

// TestAntiEntropyTakesGlobalRowsFromMastersOnly: a global row only a
// storage member holds is not pulled by a master or by another storage
// member, nor pushed by it. A master's global row reaches the storage
// members, from the master.
func TestAntiEntropyTakesGlobalRowsFromMastersOnly(t *testing.T) {
	an := newGateNet(t)
	ctx := t.Context()
	forgeCeiling(t, an.m("s"))
	for _, p := range [][2]string{{"m", "s"}, {"s2", "s"}, {"s", "m"}, {"s", "s2"}} {
		if err := an.m(p[0]).rep.SyncWith(ctx, p[1]); err != nil {
			t.Fatalf("anti-entropy of %s with %s: %v", p[0], p[1], err)
		}
	}
	an.m("s2").rep.SetLocal(true, true) // a promotion's catch-up pulls too
	an.m("s2").rep.CatchUp(ctx)
	for _, id := range []string{"m", "s2"} {
		if got := localCeiling(t, an.m(id)); got != "" {
			t.Fatalf("%s took the forged ceiling by anti-entropy: %s", id, got)
		}
	}

	// The master's own ceiling, written while s2 was down, reaches s2 from
	// the master, and replaces the forged copy on s.
	an.setDown("s2", true)
	if err := an.m("m").st.DeviceCeilings().Set(ctx, "pi", []byte(`{"terminal":false}`), "user/admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	an.setDown("s2", false)
	if err := an.m("s2").rep.SyncWith(ctx, "m"); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"m", "s", "s2"} {
		if got := localCeiling(t, an.m(id)); got != `{"terminal":false}` {
			t.Fatalf("%s's ceiling = %q, want the master's", id, got)
		}
	}
}

// TestRepairAndRevocationTakeGlobalRowsFromMastersOnly: a read repair or a
// revocation that names a storage member as its writer fetches the rows
// from it, and drops its global ones: a master does not copy them on in its
// own name.
func TestRepairAndRevocationTakeGlobalRowsFromMastersOnly(t *testing.T) {
	an := newGateNet(t)
	ctx := t.Context()
	if err := an.m("m").st.DeviceCeilings().Set(ctx, "pi", []byte(`{"terminal":false}`), "user/admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	forgeCeiling(t, an.m("s")) // newer than the master's
	if err := an.m("m").rep.repair(ctx, ceilingRef); err != nil {
		t.Fatal(err)
	}
	if err := an.m("m").rep.takeRevocation(ctx, revocationMsg{Kind: msgRevoked, From: "s", Refs: ceilingRef}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"m", "s2"} {
		if got := localCeiling(t, an.m(id)); got != `{"terminal":false}` {
			t.Fatalf("%s's ceiling = %q, want the master's", id, got)
		}
	}
}

// TestPasswordResetWithStorageOnlyMembers: a password reset, which runs on
// every storage member, works when the storage members are not masters,
// and its admin row reaches a master that is not a storage member.
func TestPasswordResetWithStorageOnlyMembers(t *testing.T) {
	for _, masterStores := range []bool{true, false} {
		t.Run(map[bool]string{true: "master stores", false: "master off the ring"}[masterStores], func(t *testing.T) {
			an := newGateNet(t)
			ctx := t.Context()
			an.mu.Lock()
			an.roles["s"], an.roles["s2"] = storageOnly, storageOnly
			if !masterStores {
				an.roles["m"] = masterOnly
			}
			an.mu.Unlock()
			if !masterStores {
				an.m("m").rep.SetLocal(false, false)
			}
			if err := an.m("m").st.Admin().SetPasswordHash(ctx, "h2"); err != nil {
				t.Fatal(err)
			}
			for _, id := range []string{"m", "s", "s2"} {
				rows, err := an.m(id).st.ReadLocal(ctx, `SELECT password_hash FROM admin`, nil)
				if err != nil || len(rows.Vals) != 1 || rows.Vals[0][0] != "h2" {
					t.Fatalf("%s's admin row = %v, %v; want h2", id, rows.Vals, err)
				}
			}
		})
	}
}

// TestCAMasterKey: a hub with the CA key proves it; a hub with the CA
// certificate only (a storage member) proves nothing and checks the proofs;
// a proof is good for one side of one connection, and another CA's is not.
func TestCAMasterKey(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	ca, err := pki.LoadOrCreateCA(dir, now)
	if err != nil {
		t.Fatal(err)
	}
	keyless := t.TempDir()
	if err := pki.InstallCACert(keyless, ca.Cert().Raw, ca.Fingerprint()); err != nil {
		t.Fatal(err)
	}
	storageCA, err := pki.LoadCA(keyless, now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := pki.LoadOrCreateCA(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	master, storage := CAMasterKey(ca), CAMasterKey(storageCA)
	binding := []byte("binding of one connection")
	msg := append([]byte(proofDialer), binding...)
	sig, ok := master.Prove(msg)
	if !master.Holds() || !ok {
		t.Fatal("the master proves nothing")
	}
	if !storage.Verify(msg, sig) || !master.Verify(msg, sig) {
		t.Fatal("a master's proof does not verify")
	}
	if storage.Verify(append([]byte(proofServer), binding...), sig) {
		t.Fatal("a dialer's proof verifies as the server's")
	}
	if storage.Verify(append([]byte(proofDialer), "another connection"...), sig) {
		t.Fatal("a proof verifies for another connection")
	}
	if _, ok := storage.Prove(msg); ok || storage.Holds() {
		t.Fatal("a member without the CA key proves it")
	}
	if osig, _ := CAMasterKey(other).Prove(msg); storage.Verify(msg, osig) {
		t.Fatal("another CA's proof verifies")
	}
}

// TestReplicaMasterProofOverTLS: over the members' real mutual TLS, a
// master proves the hub CA key on a replication connection and a
// storage-only member does not, whatever roles it announces: its global
// rows are refused, and a master's reach it.
func TestReplicaMasterProofOverTLS(t *testing.T) {
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"c", storageOnly, storageMaster},
	)
	a, cc := c["a"], c["c"]
	ctx := t.Context()
	if err := a.st.DeviceCeilings().Set(ctx, "pi", []byte(`{"terminal":false}`), "user/admin", time.Now()); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, "a's ceiling on c", func() bool {
		got, err := cc.st.DeviceCeilings().Get(ctx, "pi")
		return err == nil && string(got.Ceiling) == `{"terminal":false}`
	})
	resp, err := cc.node.rep.call(ctx, "a", apRequest{Op: opFetch, Refs: ceilingRef})
	if err != nil || !resp.fromMaster {
		t.Fatalf("a's answer to c: master %v, %v; want a proven master", resp.fromMaster, err)
	}
	resp, err = a.node.rep.call(ctx, "c", apRequest{Op: opFetch, Refs: ceilingRef})
	if err != nil || resp.fromMaster {
		t.Fatalf("c's answer to a: master %v, %v; want no proof", resp.fromMaster, err)
	}
	now := time.Now()
	_, forged, err := cc.st.ApplyLocalMutations(ctx, store.SetDeviceCeiling{
		Stamp:    store.Stamp{HLC: hlc.New(now), Origin: "a"},
		DeviceID: "pi", Ceiling: evilCeiling, UpdatedAt: now.UnixMilli(), UpdatedBy: "user/admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cc.node.rep.call(ctx, "a", apRequest{Op: opMerge, Muts: forged}); !errors.Is(err, errNotMaster) {
		t.Fatalf("c's forged ceiling sent to a: %v, want errNotMaster", err)
	}
	if err := a.node.rep.SyncWith(ctx, "c"); err != nil {
		t.Fatal(err)
	}
	got, err := a.st.DeviceCeilings().Get(context.WithoutCancel(ctx), "pi")
	if err != nil || string(got.Ceiling) != `{"terminal":false}` {
		t.Fatalf("a's ceiling = %s, %v; want its own", got.Ceiling, err)
	}
}

// switchKey is a MasterKey a test hands over or takes away, as a promotion
// to master or a demotion does.
type switchKey struct{ held atomic.Bool }

func (k *switchKey) Holds() bool { return k.held.Load() }

func (k *switchKey) Prove(msg []byte) ([]byte, bool) {
	return testMasterKey{holds: k.held.Load()}.Prove(msg)
}

func (*switchKey) Verify(msg, sig []byte) bool { return testMasterKey{}.Verify(msg, sig) }

// TestPromotedMemberDropsUnprovedConns: the connections a member pooled
// before it got the hub CA key are not used once it has it, so its global
// writes are taken at once; nor are those it pooled while it held the key,
// once it lost it.
func TestPromotedMemberDropsUnprovedConns(t *testing.T) {
	key := &switchKey{}
	an := newAPNetWith(t, 0, func(c *ReplicatorConfig) {
		if c.NodeID == "s" {
			c.Master = key
		}
	}, "m", "s")
	ctx := t.Context()
	// Pool connections to m while s holds no key.
	for range 3 {
		if _, err := an.m("s").rep.call(ctx, "m", apRequest{Op: opRead, Query: `SELECT 1`}); err != nil {
			t.Fatal(err)
		}
	}
	key.held.Store(true)
	if err := an.m("s").st.DeviceCeilings().Set(ctx, "pi", []byte(`{"terminal":false}`), "user/admin", time.Now()); err != nil {
		t.Fatalf("s, promoted, sets a ceiling: %v", err)
	}
	if got := localCeiling(t, an.m("m")); got != `{"terminal":false}` {
		t.Fatalf("m's ceiling = %q, want s's", got)
	}
	key.held.Store(false)
	_, err := an.m("s").rep.call(ctx, "m", apRequest{Op: opMerge, Muts: forgeCeiling(t, an.m("s"))})
	if !errors.Is(err, errNotMaster) {
		t.Fatalf("s, demoted, merges a global row: %v, want errNotMaster", err)
	}
}

// liarKey checks proofs as every member does, and makes up its own.
type liarKey struct{}

func (liarKey) Holds() bool { return true }

func (liarKey) Prove([]byte) ([]byte, bool) { return []byte("not a CA signature"), true }

func (liarKey) Verify(msg, sig []byte) bool { return testMasterKey{}.Verify(msg, sig) }

// TestMasterLinkOverTLS: over the members' real mutual TLS, a master calls
// another master on the master link, but not a storage-only member, which
// cannot prove it holds the hub CA key (a call forwarded to a device's
// stream must not reach a member that only says it is a master); and the
// storage member cannot call a master.
func TestMasterLinkOverTLS(t *testing.T) {
	c := newAPTestCluster(t, 2,
		apSpec{"a", storageMaster, storageMaster},
		apSpec{"b", storageMaster, storageMaster},
		apSpec{"c", storageOnly, storageMaster},
	)
	get := func(from *apTestNode, to string) error {
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+to+"/no-such-path", nil)
		if err != nil {
			return err
		}
		resp, err := from.node.link.Client().Do(req)
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
	if err := get(c["a"], "b"); err != nil {
		t.Fatalf("a master calls another: %v", err)
	}
	if err := get(c["a"], "c"); err == nil {
		t.Fatal("a master's call reached a storage-only member")
	}
	if err := get(c["c"], "a"); err == nil {
		t.Fatal("a storage-only member called a master")
	}
}

// TestMasterLinkNeedsTheCAKey: a member that announces the master role on
// the gossip but does not hold the hub CA key cannot call a master over the
// master link (forwarded agent calls, role changes); a master can.
func TestMasterLinkNeedsTheCAKey(t *testing.T) {
	members := func() []MemberInfo {
		return []MemberInfo{
			{ID: "m", Roles: HubRoles, State: MemberAlive},
			{ID: "s", Roles: HubRoles, State: MemberAlive}, // claims master
		}
	}
	served := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok") })
	srv := NewMasterLink("m", nil, members, testMasterKey{holds: true}, served, testLogger(t))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	dial := func(context.Context, string) (net.Conn, error) {
		a, b := net.Pipe()
		binding := []byte(rand.Text())
		go srv.Accept(boundConn{b, binding}, "s")
		return boundConn{a, binding}, nil
	}
	get := func(key MasterKey) (string, error) {
		cl := NewMasterLink("s", dial, members, key, nil, testLogger(t))
		defer cl.transport.CloseIdleConnections()
		resp, err := cl.Client().Get("http://m/x")
		if err != nil {
			return "", err
		}
		defer func() { _ = resp.Body.Close() }()
		b, err := io.ReadAll(resp.Body)
		return string(b), err
	}
	if got, err := get(testMasterKey{holds: true}); err != nil || got != "ok" {
		t.Fatalf("a master's call: %q, %v", got, err)
	}
	if _, err := get(testMasterKey{}); err == nil {
		t.Fatal("a member without the key called a master")
	}
	// A member that says it is a master, and answers a master's call with
	// a proof it cannot make, is not called.
	liar := NewMasterLink("s", nil, members, liarKey{}, served, testLogger(t))
	lctx, lcancel := context.WithCancel(t.Context())
	ldone := make(chan error, 1)
	go func() { ldone <- liar.Run(lctx) }()
	t.Cleanup(func() {
		lcancel()
		if err := <-ldone; err != nil {
			t.Error(err)
		}
	})
	toLiar := NewMasterLink("m", func(context.Context, string) (net.Conn, error) {
		a, b := net.Pipe()
		binding := []byte(rand.Text())
		go liar.Accept(boundConn{b, binding}, "m")
		return boundConn{a, binding}, nil
	}, members, testMasterKey{holds: true}, nil, testLogger(t))
	defer toLiar.transport.CloseIdleConnections()
	if resp, err := toLiar.Client().Get("http://s/x"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("a master called a member that could not prove the key")
	}
	// One that sends a forged proof anyway is hung up on.
	c, err := dial(ctx, "m")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := writeFrame(c, masterHello{Proof: []byte("forged")}); err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(c, "GET /x HTTP/1.1\r\nHost: m\r\nConnection: close\r\n\r\n")
	if b, _ := io.ReadAll(c); len(b) > 0 {
		t.Fatalf("a forged proof was served: %q", b)
	}
}
