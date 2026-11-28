// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

// allCommands has one value of every Command type, with every field set.
func allCommands() []Command {
	boot := int64(1_699_999_000_000)
	exp := int64(31)
	return []Command{
		UpsertDevice{
			ID: "pi", Name: "Pi", Hostname: "pi.lan", OS: "linux", Arch: "arm64",
			Facts: `{ "cpu": 4 }`, Labels: `{"room":"attic"}`, FirstSeen: 1, LastSeen: 2, Status: StatusOnline, BootTime: &boot,
		},
		ReportFacts{ID: "pi", Hostname: "pi.lan", OS: "linux", Arch: "arm64", Facts: `{"cpu":4}`, Now: 3},
		MarkSeen{Stamp: Stamp{HLC: 1 << 40, Origin: "hub-a"}, ID: "pi", Now: 4},
		SetBootTime{ID: "pi", BootTime: &boot},
		MarkOffline{Cutoff: 5},
		MarkDevicesOffline{IDs: []string{"nas", "pi"}},
		SetHubURL{NodeID: "hub-a", AgentURL: "https://hub-a:7443"},
		RecordHubCert{Serial: "0b", NodeID: "hub-a", Fingerprint: "f0", CAFP: "c0"},
		RevokeHubCerts{NodeID: "hub-a", Now: 16},
		CreateToken{Hash: []byte{1, 2, 3}, Labels: `{}`, ExpiresAt: 6},
		ConsumeToken{Hash: []byte{1, 2, 3}, Now: 7},
		CreateJoinToken{Hash: []byte{7, 8}, ExpiresAt: 12},
		ConsumeJoinToken{Hash: []byte{7, 8}, Now: 13},
		CreateCert{Serial: "0a", DeviceID: "pi", Fingerprint: "f1", CAFP: "c0"},
		PinCert{Serial: "0a", DeviceID: "pi", Fingerprint: "f1", CAFP: "c0", Now: 19},
		StartCARotation{NewCAFP: "c1", OldCAFP: "c0", NewCACert: "pem", Pins: `{"hub-a":"f0b"}`, Now: 20},
		AdvanceCARotation{NewCAFP: "c1", From: CAStageStarted, To: CAStageCutover, Now: 21},
		ResealSecrets{NewCAFP: "c1", Secrets: []SealedSecret{{Table: SealedKubeClusters, ID: "k1", Sealed: []byte{1}, Resealed: []byte{9}}}},
		RevokeCACerts{CAFP: "c1", Now: 22},
		RevokeDevice{DeviceID: "pi", Now: 8},
		AppendAudit{
			TS: 9, ActorKind: "agent", ActorID: "pi", Action: "agent.enroll", Target: "pi",
			Decision: "allow", Result: "ok", Detail: `{"a": 1}`,
		},
		AppendAuditOnce{
			AppendAudit: AppendAudit{
				Stamp: Stamp{HLC: 1<<40 + 1, Origin: "hub-b"},
				TS:    9, ActorKind: "hub", ActorID: "n1", Action: "device.revoke", Target: "pi",
				Decision: "allow", Result: "ok", Detail: `{"audit_outcome_of":"op1"}`,
			},
			Key: "k1",
		},
		SetPasswordHash{Hash: "$argon2id$..."},
		CreateSession{Hash: []byte{4, 5}, Now: 10, ExpiresAt: 11},
		DeleteSession{Hash: []byte{4, 5}},
		RecordAutomationRun{
			ID: "r1", AutomationID: "a", TriggerID: "manual", StartedAt: 17, FinishedAt: 18,
			Status: "succeeded", Error: "", Steps: `[{"id":"x"}]`, Keep: 100,
		},
		AddKubeCluster{ID: "k1", Name: "lab", Sealed: []byte{9, 9}, CreatedAt: 17},
		RemoveKubeCluster{ID: "k1"},
		AddProxmoxServer{ID: "p1", Name: "rack", Sealed: []byte{9, 9}, CreatedAt: 17},
		RemoveProxmoxServer{ID: "p1"},
		CreateApproval{
			ID: "ap1", CreatedAt: 19, ExpiresAt: 20, ActorKind: "automation", ActorID: "a",
			Action: "automation.exec", Class: "dangerous", Target: "pi", Detail: `{"run":"r1"}`,
		},
		DecideApproval{ID: "ap1", Status: "approved", By: "admin/root", At: 19},
		CreateApprovalLink{Hash: []byte{6, 7}, ApprovalID: "ap1", ExpiresAt: 20},
		UseApprovalLink{Hash: []byte{6, 7}, Now: 19},
		CreateMCPToken{Name: "claude", Hash: []byte{3, 3}, Scope: "safe", CreatedAt: 21},
		RevokeMCPToken{Name: "claude", At: 22},
		RecordNetworkScan{At: 23, AbsentAfter: 3_600_000, Hosts: []ScannedHost{
			{MAC: "2c:cf:67:00:00:01", IP: "192.168.2.171", Hostname: "pi5.local", Vendor: "Raspberry Pi"},
			{MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.2.50"},
		}},
		SetNetworkHostState{MAC: "aa:bb:cc:dd:ee:ff", State: HostAdopted, Name: "Living room TV"},
		SetTelemetry{Enabled: true, InstallID: "0123456789abcdef", At: 25},
		MarkTelemetrySent{InstallID: "0123456789abcdef", At: 26},
		CreatePanel{ID: "p1", Name: "Hall", Widgets: `[{"id":"w1"}]`, At: 27},
		UpdatePanel{ID: "p1", Name: "Hallway", Widgets: `[]`, At: 28},
		DeletePanel{ID: "p1"},
		CreatePanelLink{ID: "l1", PanelID: "p1", Hash: []byte{1, 2}, CreatedAt: 29, ExpiresAt: &exp},
		RevokePanelLink{PanelID: "p1", ID: "l1", At: 30},
		CreateDashboardToken{ID: "d1", Name: "homepage", Hash: []byte{4, 4}, CreatedAt: 31, ExpiresAt: &exp},
		RevokeDashboardToken{ID: "d1", At: 32},
		RecordNetworkImport{At: 24, Hosts: []ImportedHost{
			{
				MAC: "2c:cf:67:00:00:01", IP: "192.168.2.171", Hostname: "pi5", HostnameSource: SourcePihole,
				Sources: []string{SourceDHCP, SourcePihole}, Seen: 24,
			},
			{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.20.5", Sources: []string{SourceDHCP}},
		}},
		PutConfigDocs{
			Docs:   []ConfigDocWrite{{Kind: ConfigRunbook, Name: "r.yaml", Content: []byte("steps: []"), Digest: "d0"}},
			IfNone: true, By: "admin/root", Now: 33,
		},
		DeleteConfigDoc{Kind: ConfigRunbook, Name: "r.yaml"},
		SetDeviceRoute{DeviceID: "pi", Master: "hub-a", At: 34},
		SetDeviceCeiling{DeviceID: "pi", Ceiling: `{"logs":["docker:*"]}`, UpdatedAt: 37, UpdatedBy: "web/10.0.0.1"},
		AddESPHomeDevice{ID: "e1", Name: "kitchen", Sealed: []byte{9, 9}, CreatedAt: 38},
		RemoveESPHomeDevice{ID: "e1"},
		AddOpenWrtRouter{ID: "o1", Name: "gateway", Sealed: []byte{7}, CreatedAt: 39},
		RemoveOpenWrtRouter{ID: "o1"},
		AddOPNsenseFirewall{ID: "f1", Name: "edge", Sealed: []byte{6}, CreatedAt: 40},
		RemoveOPNsenseFirewall{ID: "f1"},
		AddUniFiController{ID: "u1", Name: "console", Sealed: []byte{6}, CreatedAt: 41},
		RemoveUniFiController{ID: "u1"},
		SetDevicePlugin{
			ID: "p1", Name: "lamp", OS: "linux", Arch: "arm64", Version: "1", SHA256: "ab", Size: 3,
			Manifest: `{}`, Holder: "hub-a", UploadedAt: 42, UploadedBy: "web/10.0.0.1",
		},
		RemoveDevicePlugin{ID: "p1"},
		CreateRunbookRun{
			ID: "rr1", RunbookID: "rb", Status: "running", StartedBy: "admin/root", StartedAt: 35,
			Source: []byte("steps: []"), State: `{"step":0}`, Keep: 100,
		},
		SaveRunbookRun{ID: "rr1", Version: 1, Status: "succeeded", UpdatedAt: 36, FinishedAt: 36, State: `{"step":1}`},
	}
}

func TestCommandEncodeDecodeRoundTrip(t *testing.T) {
	seen := map[string]bool{}
	for _, cmd := range allCommands() {
		t.Run(cmd.Op(), func(t *testing.T) {
			if seen[cmd.Op()] {
				t.Fatalf("duplicate op %q", cmd.Op())
			}
			seen[cmd.Op()] = true
			b, err := EncodeCommand(cmd)
			if err != nil {
				t.Fatal(err)
			}
			got, err := DecodeCommand(b)
			if err != nil {
				t.Fatalf("DecodeCommand(%s): %v", b, err)
			}
			if !reflect.DeepEqual(got, cmd) {
				t.Fatalf("round trip = %#v, want %#v", got, cmd)
			}
		})
	}
}

// allCommands lists every type of the package that implements Command, so
// the round trip above proves each one decodes: a command added without a
// DecodeCommand case fails here, not when a member forwards it.
func TestAllCommandsListsEveryCommand(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var declared []string
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Name.Name != "apply" || fn.Recv == nil || len(fn.Recv.List) != 1 {
				continue
			}
			if id, ok := fn.Recv.List[0].Type.(*ast.Ident); ok {
				declared = append(declared, id.Name)
			}
		}
	}
	listed := map[string]bool{}
	for _, cmd := range allCommands() {
		listed[reflect.TypeOf(cmd).Name()] = true
	}
	if len(declared) < 50 {
		t.Fatalf("found only %d command types in the sources: %v", len(declared), declared)
	}
	for _, name := range declared {
		if !listed[name] {
			t.Errorf("command %s is missing from allCommands", name)
		}
	}
}

func TestDecodeCommandRejects(t *testing.T) {
	tests := map[string]string{
		"not json":       `nope`,
		"unknown op":     `{"v":1,"op":"drop_table","cmd":{}}`,
		"old version":    `{"v":0,"op":"mark_seen","cmd":{"id":"pi","now":1}}`,
		"new version":    `{"v":2,"op":"mark_seen","cmd":{"id":"pi","now":1}}`,
		"unknown field":  `{"v":1,"op":"mark_seen","cmd":{"id":"pi","now":1,"status":"offline"}}`,
		"envelope extra": `{"v":1,"op":"mark_seen","cmd":{"id":"pi","now":1},"x":1}`,
		"trailing data":  `{"v":1,"op":"mark_seen","cmd":{"id":"pi","now":1}} {}`,
		"wrong type":     `{"v":1,"op":"mark_seen","cmd":{"id":"pi","now":"soon"}}`,
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			if cmd, err := DecodeCommand([]byte(in)); err == nil {
				t.Fatalf("DecodeCommand(%s) = %#v, want error", in, cmd)
			}
		})
	}
}

// recording is a store whose Applier encodes every command into log (as a
// replicated log would) before applying it locally.
type recording struct {
	*Store
	log  [][]byte
	errs []error
}

func openRecording(t *testing.T) *recording {
	t.Helper()
	rec := &recording{}
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"), WithApplier(func(s *Store) Applier {
		return ApplierFunc(func(ctx context.Context, cmd Command) (Result, error) {
			b, err := EncodeCommand(cmd)
			if err != nil {
				return Result{}, err
			}
			rec.log = append(rec.log, b)
			res, err := s.ApplyLocal(ctx, cmd)
			rec.errs = append(rec.errs, err)
			return res, err
		})
	}))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	rec.Store = s
	return rec
}

// runScenario drives s through every repository write, including the ones
// that fail, roughly in the order a hub sees them.
func runScenario(t *testing.T, s *Store) {
	t.Helper()
	ctx := t.Context()
	base := time.UnixMilli(1_700_000_000_000).UTC()
	at := func(d time.Duration) time.Time { return base.Add(d) }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	wantErr := func(err, target error) {
		t.Helper()
		if !errors.Is(err, target) {
			t.Fatalf("err = %v, want %v", err, target)
		}
	}

	// Admin setup and a first login.
	must(s.Admin().SetPasswordHash(ctx, "$argon2id$one"))
	must(s.Admin().CreateSession(ctx, "session-1", at(0), at(time.Hour)))
	_, err := s.Audit().Append(ctx, AuditEntry{
		TS: at(0), ActorKind: "user", ActorID: "admin",
		Action: "admin.login", Decision: "allow", Result: "ok",
	})
	must(err)
	// An entry retried with its key lands once.
	for range 2 {
		_, err = s.Audit().Append(ctx, AuditEntry{
			TS: at(0), ActorKind: "user", ActorID: "admin",
			Action: "admin.logout", Decision: "allow", Result: "ok", Key: "logout-1",
		})
		must(err)
	}

	// Tokens: one used, one left to expire.
	must(s.Tokens().Create(ctx, "tok-1", map[string]string{"room": "attic"}, at(10*time.Minute)))
	must(s.Tokens().Create(ctx, "tok-2", nil, at(time.Minute)))
	got, err := s.Tokens().Consume(ctx, "tok-1", at(time.Minute))
	must(err)
	if got.Labels["room"] != "attic" || got.Name != "" {
		t.Fatalf("consume tok-1 = %+v, want room=attic and no name", got)
	}
	_, err = s.Tokens().Consume(ctx, "tok-1", at(2*time.Minute))
	wantErr(err, ErrTokenUsed)
	_, err = s.Tokens().Consume(ctx, "tok-2", at(5*time.Minute))
	wantErr(err, ErrTokenExpired)
	_, err = s.Tokens().Consume(ctx, "tok-unknown", at(5*time.Minute))
	wantErr(err, ErrNotFound)
	// A named token gives its name once, and is single use and expires like
	// any other.
	must(s.Tokens().CreateNamed(ctx, "tok-named", "garage-pi", nil, at(10*time.Minute)))
	must(s.Tokens().CreateNamed(ctx, "tok-named-old", "attic-pi", nil, at(time.Minute)))
	got, err = s.Tokens().Consume(ctx, "tok-named", at(time.Minute))
	must(err)
	if got.Name != "garage-pi" {
		t.Fatalf("consume tok-named name = %q, want garage-pi", got.Name)
	}
	_, err = s.Tokens().Consume(ctx, "tok-named", at(2*time.Minute))
	wantErr(err, ErrTokenUsed)
	_, err = s.Tokens().Consume(ctx, "tok-named-old", at(5*time.Minute))
	wantErr(err, ErrTokenExpired)

	// Cluster join tokens: one used, one left to expire. An enrollment token
	// is not a join token.
	// The roles a token grants come back when it is spent.
	must(s.JoinTokens().Create(ctx, "join-1", at(10*time.Minute), "storage"))
	must(s.JoinTokens().Create(ctx, "join-2", at(time.Minute), "storage,master"))
	if roles, err := s.JoinTokens().Consume(ctx, "join-1", at(time.Minute)); err != nil || roles != "storage" {
		t.Fatalf("consume join-1 = %q, %v; want storage", roles, err)
	}
	_, err = s.JoinTokens().Consume(ctx, "join-1", at(2*time.Minute))
	wantErr(err, ErrTokenUsed)
	_, err = s.JoinTokens().Consume(ctx, "join-2", at(5*time.Minute))
	wantErr(err, ErrTokenExpired)
	_, err = s.JoinTokens().Consume(ctx, "tok-1", at(time.Minute))
	wantErr(err, ErrNotFound)
	if err := s.JoinTokens().Create(ctx, "join-3", at(10*time.Minute), ""); err == nil {
		t.Fatal("a join token without roles was created")
	}

	// Enrollment of two devices.
	for _, id := range []string{"pi", "nas"} {
		must(s.Devices().Upsert(ctx, Device{
			ID: id, Name: id, Labels: map[string]string{"room": "attic"},
			Facts: json.RawMessage(`{ "spaces": [1, 2] }`), FirstSeen: at(time.Minute), LastSeen: at(time.Minute),
			Status: StatusOnline,
		}))
		must(s.Certs().Create(ctx, "serial-"+id, id))
		// A zero TS is filled in when the command is built, so replay keeps it.
		_, err = s.Audit().Append(ctx, AuditEntry{
			ActorKind: "agent", ActorID: id, Action: "agent.enroll",
			Target: id, Decision: "allow", Detail: json.RawMessage(`{"token": "tok-1"}`),
		})
		must(err)
	}

	// Heartbeats.
	_, _, err = s.Devices().ReportFacts(ctx, "pi", DeviceFacts{
		Hostname: "pi.lan", OS: "linux", Arch: "arm64",
		Facts: json.RawMessage(`{"cpu":4}`),
	}, at(2*time.Minute))
	must(err)
	for i := range 3 {
		_, _, err = s.Devices().MarkSeen(ctx, "pi", at(time.Duration(3+i)*time.Minute))
		must(err)
	}
	_, err = s.Devices().SetBootTime(ctx, "pi", at(-time.Hour))
	must(err)
	_, err = s.Devices().SetBootTime(ctx, "nas", time.Time{})
	must(err)
	_, _, err = s.Devices().MarkSeen(ctx, "ghost", at(3*time.Minute))
	wantErr(err, ErrNotFound)

	// The sweeper marks the silent device offline.
	off, err := s.Devices().MarkOffline(ctx, at(4*time.Minute))
	must(err)
	if len(off) != 1 || off[0].ID != "nas" {
		t.Fatalf("MarkOffline = %v, want nas", off)
	}

	// A master names the devices it marks offline.
	off, err = s.Devices().MarkDevicesOffline(ctx, []string{"pi", "nas", "ghost"})
	must(err)
	if len(off) != 1 || off[0].ID != "pi" {
		t.Fatalf("MarkDevicesOffline = %v, want pi (nas already offline)", off)
	}

	// Cluster hubs announce their agent URLs, and may change them.
	must(s.Hubs().SetAgentURL(ctx, "hub-a", "https://hub-a:7443"))
	must(s.Hubs().SetAgentURL(ctx, "hub-b", "https://hub-b:7443"))
	must(s.Hubs().SetAgentURL(ctx, "hub-a", "https://hub-a.lan:7443"))

	// Hub certificates are recorded and a removed hub's revoked.
	must(s.Hubs().RecordCert(ctx, "0b", "hub-a"))
	must(s.Hubs().RecordCert(ctx, "0c", "hub-b"))
	// A recorded hub certificate gets its fingerprint filled in, and a
	// device certificate is pinned on first use.
	must(s.Hubs().Record(ctx, HubCert{Serial: "0b", NodeID: "hub-a", Fingerprint: "f0b", CAFP: "ca"}))
	if got, err := s.Certs().Pin(ctx, "serial-pi", "pi", "f-pi", "ca", at(6*time.Minute)); err != nil || got != Pinned {
		t.Fatalf("Pin = %v, %v; want Pinned", got, err)
	}
	n, err := s.Hubs().RevokeCerts(ctx, "hub-b", at(6*time.Minute))
	must(err)
	if n != 1 {
		t.Fatalf("revoked %d hub certs, want 1", n)
	}

	// Revocation, repeated and unknown.
	n, err = s.Certs().RevokeDevice(ctx, "pi", at(6*time.Minute))
	must(err)
	if n != 1 {
		t.Fatalf("revoked %d, want 1", n)
	}
	_, err = s.Certs().RevokeDevice(ctx, "pi", at(7*time.Minute))
	must(err)
	_, err = s.Certs().RevokeDevice(ctx, "ghost", at(7*time.Minute))
	wantErr(err, ErrNotFound)
	_, err = s.Audit().Append(ctx, AuditEntry{
		TS: at(6 * time.Minute), ActorKind: "user", ActorID: "admin",
		Action: "device.revoke", Target: "pi", Decision: "allow", Result: "ok",
	})
	must(err)

	// A later login prunes the expired session; logout; a password reset.
	must(s.Admin().CreateSession(ctx, "session-2", at(2*time.Hour), at(3*time.Hour)))
	must(s.Admin().CreateSession(ctx, "session-3", at(2*time.Hour), at(3*time.Hour)))
	must(s.Admin().DeleteSession(ctx, "session-2"))
	must(s.Admin().DeleteSession(ctx, "session-unknown"))
	must(s.Admin().SetPasswordHash(ctx, "$argon2id$two"))
	must(s.Admin().CreateSession(ctx, "session-4", at(4*time.Hour), at(5*time.Hour)))

	// Automation runs, pruned to the newest RunsKept of each automation.
	for i := range RunsKept + 2 {
		must(s.AutomationRuns().Record(ctx, AutomationRun{
			ID: fmt.Sprintf("run-%d", i), AutomationID: "a", TriggerID: "manual",
			StartedAt: at(time.Duration(i) * time.Second), FinishedAt: at(time.Duration(i) * time.Second),
			Status: "succeeded",
		}))
	}
	// Kubernetes clusters: added, a duplicate name refused, one removed.
	must(s.KubeClusters().Add(ctx, KubeCluster{ID: "k1", Name: "lab", Sealed: []byte{1}, CreatedAt: at(5 * time.Hour)}))
	must(s.KubeClusters().Add(ctx, KubeCluster{ID: "k2", Name: "edge", Sealed: []byte{2}, CreatedAt: at(5 * time.Hour)}))
	if err := s.KubeClusters().Add(ctx, KubeCluster{ID: "k3", Name: "lab", Sealed: []byte{3}, CreatedAt: at(5 * time.Hour)}); !IsDomainError(err) {
		t.Fatalf("duplicate kube cluster name = %v, want a constraint violation", err)
	}
	must(s.KubeClusters().Remove(ctx, "k2"))
	wantErr(s.KubeClusters().Remove(ctx, "k2"), ErrNotFound)
	must(s.ProxmoxServers().Add(ctx, ProxmoxServer{ID: "p1", Name: "rack", Sealed: []byte{1}, CreatedAt: at(5 * time.Hour)}))
	must(s.ProxmoxServers().Add(ctx, ProxmoxServer{ID: "p2", Name: "attic", Sealed: []byte{2}, CreatedAt: at(5 * time.Hour)}))
	if err := s.ProxmoxServers().Add(ctx, ProxmoxServer{ID: "p3", Name: "rack", Sealed: []byte{3}, CreatedAt: at(5 * time.Hour)}); !IsDomainError(err) {
		t.Fatalf("duplicate proxmox server name = %v, want a domain error", err)
	}
	must(s.ProxmoxServers().Remove(ctx, "p2"))
	wantErr(s.ProxmoxServers().Remove(ctx, "p2"), ErrNotFound)
	must(s.ESPHomeDevices().Add(ctx, ESPHomeDevice{ID: "e1", Name: "kitchen", Sealed: []byte{1}, CreatedAt: at(5 * time.Hour)}))
	must(s.ESPHomeDevices().Add(ctx, ESPHomeDevice{ID: "e2", Name: "porch", Sealed: []byte{2}, CreatedAt: at(5 * time.Hour)}))
	must(s.ESPHomeDevices().Remove(ctx, "e2"))
	wantErr(s.ESPHomeDevices().Remove(ctx, "e2"), ErrNotFound)
	must(s.OpenWrtRouters().Add(ctx, OpenWrtRouter{ID: "o1", Name: "gateway", Sealed: []byte{1}, CreatedAt: at(5 * time.Hour)}))
	must(s.OpenWrtRouters().Add(ctx, OpenWrtRouter{ID: "o2", Name: "attic", Sealed: []byte{2}, CreatedAt: at(5 * time.Hour)}))
	must(s.OpenWrtRouters().Remove(ctx, "o2"))
	wantErr(s.OpenWrtRouters().Remove(ctx, "o2"), ErrNotFound)
	must(s.OPNsenseFirewalls().Add(ctx, OPNsenseFirewall{ID: "f1", Name: "edge", Sealed: []byte{1}, CreatedAt: at(5 * time.Hour)}))
	must(s.OPNsenseFirewalls().Add(ctx, OPNsenseFirewall{ID: "f2", Name: "lab", Sealed: []byte{2}, CreatedAt: at(5 * time.Hour)}))
	must(s.OPNsenseFirewalls().Remove(ctx, "f2"))
	wantErr(s.OPNsenseFirewalls().Remove(ctx, "f2"), ErrNotFound)
	must(s.UniFiControllers().Add(ctx, UniFiController{ID: "u1", Name: "console", Sealed: []byte{1}, CreatedAt: at(5 * time.Hour)}))
	must(s.UniFiControllers().Add(ctx, UniFiController{ID: "u2", Name: "office", Sealed: []byte{2}, CreatedAt: at(5 * time.Hour)}))
	must(s.UniFiControllers().Remove(ctx, "u2"))
	wantErr(s.UniFiControllers().Remove(ctx, "u2"), ErrNotFound)
	lamp := DevicePlugin{Name: "lamp", OS: "linux", Arch: "arm64", Version: "1", SHA256: "ab", Size: 3, Manifest: []byte(`{}`), UploadedAt: at(5 * time.Hour)}
	must(s.DevicePlugins().Set(ctx, lamp))
	lamp.Arch = "amd64"
	must(s.DevicePlugins().Set(ctx, lamp))
	must(s.DevicePlugins().Remove(ctx, DevicePluginID("lamp", "linux", "amd64")))
	wantErr(s.DevicePlugins().Remove(ctx, DevicePluginID("lamp", "linux", "amd64")), ErrNotFound)

	// A hub CA rotation: started, a second refused, cut over, its secrets
	// re-sealed (a stale one refused), finished.
	rot := CARotation{NewCAFP: "c1", OldCAFP: "ca", NewCACert: "pem", Pins: map[string]string{"hub-a": "f0b"}}
	must(s.CARotations().Start(ctx, rot, at(5*time.Hour)))
	wantErr(s.CARotations().Start(ctx, CARotation{NewCAFP: "c2", OldCAFP: "ca"}, at(5*time.Hour)), ErrCARotationActive)
	wantErr(s.CARotations().Advance(ctx, "c1", CAStageCutover, CAStageFinished, at(5*time.Hour)), ErrCARotationConflict)
	must(s.CARotations().Advance(ctx, "c1", CAStageStarted, CAStageCutover, at(5*time.Hour)))
	wantErr(s.CARotations().Reseal(ctx, "c1", []SealedSecret{{Table: SealedKubeClusters, ID: "k1", Sealed: []byte{7}, Resealed: []byte{8}}}), ErrCARotationConflict)
	must(s.CARotations().Reseal(ctx, "c1", []SealedSecret{
		{Table: SealedKubeClusters, ID: "k1", Sealed: []byte{1}, Resealed: []byte{11}},
		{Table: SealedProxmoxServers, ID: "p1", Sealed: []byte{1}, Resealed: []byte{12}},
	}))
	sealed, err := s.CARotations().Sealed(ctx)
	must(err)
	must(s.CARotations().Finish(ctx, "c1", SealedDigest(sealed), at(5*time.Hour)))
	revoked, err := s.CARotations().RevokeCerts(ctx, "c2", at(5*time.Hour))
	must(err)
	if revoked != 0 {
		t.Errorf("RevokeCerts of a CA that issued none = %d", revoked)
	}

	// An approval held, then decided; deciding it again is refused.
	must(s.Approvals().Create(ctx, Approval{
		ID: "ap-1", CreatedAt: at(time.Hour), ExpiresAt: at(2 * time.Hour), ActorKind: "automation",
		ActorID: "a", Action: "automation.exec", Class: "dangerous", Target: "pi",
	}))
	must(s.Approvals().Decide(ctx, "ap-1", ApprovalApproved, "admin/root", at(time.Hour+time.Minute)))
	wantErr(s.Approvals().Decide(ctx, "ap-1", ApprovalDenied, "admin/root", at(time.Hour+time.Minute)), ErrApprovalClosed)

	// An approval link made, used once, and refused the second time.
	must(s.ApprovalLinks().Create(ctx, "link-1", "ap-1", at(2*time.Hour)))
	_, err = s.ApprovalLinks().Use(ctx, "link-1", at(time.Hour))
	must(err)
	_, err = s.ApprovalLinks().Use(ctx, "link-1", at(time.Hour))
	wantErr(err, ErrTokenUsed)
	must(s.MCPTokens().Create(ctx, "claude", "mcp-secret", "safe", at(2*time.Hour)))
	must(s.MCPTokens().Create(ctx, "old", "mcp-old", "read", at(2*time.Hour)))
	must(s.MCPTokens().Revoke(ctx, "old", at(2*time.Hour+time.Minute)))
	wantErr(s.MCPTokens().Revoke(ctx, "old", at(2*time.Hour+time.Minute)), ErrNotFound)
	pi := NetworkHost{MAC: "2c:cf:67:00:00:01", IP: "192.168.2.171", Hostname: "pi5.local", Vendor: "Raspberry Pi"}
	_, err = s.NetworkHosts().RecordScan(ctx, at(3*time.Hour), time.Hour, []NetworkHost{pi})
	must(err)
	pi.IP = "192.168.2.172"
	_, err = s.NetworkHosts().RecordScan(ctx, at(5*time.Hour), time.Hour, []NetworkHost{pi, {MAC: "aa:bb:cc:dd:ee:ff", IP: "192.168.2.50"}})
	must(err)
	must(s.NetworkHosts().SetState(ctx, "aa:bb:cc:dd:ee:ff", HostKnown))
	wantErr(s.NetworkHosts().SetState(ctx, "00:00:00:00:00:01", HostIgnored), ErrNotFound)
	must(s.NetworkHosts().RecordImport(ctx, at(6*time.Hour), []ImportedHost{
		{MAC: pi.MAC, IP: pi.IP, Hostname: "pi5", HostnameSource: SourcePihole, Sources: []string{SourcePihole}, Seen: at(6 * time.Hour).UnixMilli()},
		{MAC: "aa:bb:cc:dd:ee:01", IP: "192.168.20.5", Hostname: "tv", HostnameSource: SourceDHCP, Sources: []string{SourceDHCP}},
	}))
	// Telemetry turned on, sent once, then off: a send for the old ID is refused.
	must(s.Telemetry().Set(ctx, true, "0123456789abcdef", at(7*time.Hour)))
	must(s.Telemetry().MarkSent(ctx, "0123456789abcdef", at(7*time.Hour+time.Minute)))
	must(s.Telemetry().Set(ctx, false, "", at(8*time.Hour)))
	wantErr(s.Telemetry().MarkSent(ctx, "0123456789abcdef", at(8*time.Hour)), ErrNotFound)
	// A panel shared by two links, one revoked; a second panel deleted with its link.
	must(s.Panels().Create(ctx, Panel{ID: "p1", Name: "Hall", Widgets: `[]`, CreatedAt: at(9 * time.Hour)}))
	must(s.Panels().Update(ctx, Panel{ID: "p1", Name: "Hallway", Widgets: `[{"id":"w1"}]`}, at(9*time.Hour+time.Minute)))
	wantErr(s.Panels().Update(ctx, Panel{ID: "nope", Name: "x", Widgets: `[]`}, at(9*time.Hour)), ErrNotFound)
	must(s.Panels().CreateLink(ctx, PanelLink{ID: "l1", PanelID: "p1", CreatedAt: at(9 * time.Hour)}, "panel-secret-1"))
	must(s.Panels().CreateLink(ctx, PanelLink{ID: "l2", PanelID: "p1", CreatedAt: at(9 * time.Hour), ExpiresAt: at(10 * time.Hour)}, "panel-secret-2"))
	wantErr(s.Panels().CreateLink(ctx, PanelLink{ID: "l3", PanelID: "nope", CreatedAt: at(9 * time.Hour)}, "panel-secret-3"), ErrNotFound)
	must(s.Panels().RevokeLink(ctx, "p1", "l1", at(9*time.Hour+2*time.Minute)))
	wantErr(s.Panels().RevokeLink(ctx, "p1", "l1", at(9*time.Hour+3*time.Minute)), ErrNotFound)
	must(s.Panels().Create(ctx, Panel{ID: "p2", Name: "Gone", Widgets: `[]`, CreatedAt: at(9 * time.Hour)}))
	must(s.Panels().CreateLink(ctx, PanelLink{ID: "l4", PanelID: "p2", CreatedAt: at(9 * time.Hour)}, "panel-secret-4"))
	must(s.Panels().Delete(ctx, "p2"))
	wantErr(s.Panels().Delete(ctx, "p2"), ErrNotFound)
	// Two dashboard tokens, one revoked; revoking it again is refused.
	must(s.DashboardTokens().Create(ctx, DashboardToken{ID: "d1", Name: "homepage", CreatedAt: at(11 * time.Hour)}, "dash-secret-1"))
	must(s.DashboardTokens().Create(ctx, DashboardToken{ID: "d2", Name: "wall", CreatedAt: at(11 * time.Hour), ExpiresAt: at(12 * time.Hour)}, "dash-secret-2"))
	must(s.DashboardTokens().Revoke(ctx, "d1", at(11*time.Hour+time.Minute)))
	wantErr(s.DashboardTokens().Revoke(ctx, "d1", at(11*time.Hour+2*time.Minute)), ErrNotFound)
	// Config documents imported once, a second import refused, a runbook deleted.
	runbook := ConfigDoc{Kind: ConfigRunbook, Name: "r.yaml", Content: []byte("steps: []")}
	must(s.ConfigDocs().ImportFirst(ctx, "admin/root", []ConfigDoc{runbook}, at(13*time.Hour)))
	wantErr(s.ConfigDocs().ImportFirst(ctx, "admin/root", []ConfigDoc{runbook}, at(13*time.Hour)), ErrExists)
	must(s.ConfigDocs().Put(ctx, "admin/root", []ConfigDoc{{Kind: ConfigAutomation, Name: "a.yaml", Content: []byte("id: a")}}, at(13*time.Hour)))
	must(s.ConfigDocs().Delete(ctx, ConfigRunbook, "r.yaml"))
	// A runbook run started, saved once, and a save from its old version refused.
	run := RunbookRun{
		ID: "rr1", RunbookID: "rb", Status: "running", StartedBy: "admin/root",
		StartedAt: at(14 * time.Hour), Source: []byte("steps: []"), State: json.RawMessage(`{"step":0}`),
	}
	must(s.RunbookRuns().Create(ctx, run))
	run.Version, run.Status, run.UpdatedAt = 1, "succeeded", at(14*time.Hour)
	_, err = s.RunbookRuns().Save(ctx, run)
	must(err)
	_, err = s.RunbookRuns().Save(ctx, run)
	wantErr(err, ErrRunbookRunConflict)
	// The master holding pi's stream, recorded twice.
	must(s.DeviceRoutes().Set(ctx, "pi", "hub-a", at(14*time.Hour)))
	must(s.DeviceRoutes().Set(ctx, "pi", "hub-b", at(14*time.Hour+time.Minute)))
	// The ceiling the hub sets for pi.
	must(s.DeviceCeilings().Set(ctx, "pi", []byte(`{"logs":["docker:*"]}`), "web/10.0.0.1", at(14*time.Hour+2*time.Minute)))
	if c, err := s.DeviceCeilings().Get(ctx, "pi"); err != nil || string(c.Ceiling) != `{"logs":["docker:*"]}` || c.UpdatedBy != "web/10.0.0.1" {
		t.Fatalf("device ceiling = %+v, %v", c, err)
	}
	if _, err := s.DeviceCeilings().Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ceiling of an unknown device: %v, want ErrNotFound", err)
	}
}

// dumpTables returns every row of every table (sqlite_sequence included,
// goose_db_version excluded since it records wall-clock apply times), in
// rowid order.
func dumpTables(t *testing.T, db *sql.DB) map[string][][]any {
	t.Helper()
	ctx := t.Context()
	var names []string
	rows, err := db.QueryContext(ctx,
		`SELECT name FROM sqlite_master WHERE type = 'table' AND name != 'goose_db_version' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	out := map[string][][]any{}
	for _, n := range names {
		rows, err := db.QueryContext(ctx, `SELECT * FROM "`+n+`" ORDER BY rowid`) //nolint:gosec // table names from sqlite_master
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		out[n] = [][]any{}
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				t.Fatal(err)
			}
			out[n] = append(out[n], vals)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestReplayIsDeterministic(t *testing.T) {
	src := openRecording(t)
	runScenario(t, src.Store)

	// Every write in the scenario went through the seam, and the scenario
	// exercises every command type.
	var ops []string
	for _, b := range src.log {
		cmd, err := DecodeCommand(b)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(ops, cmd.Op()) {
			ops = append(ops, cmd.Op())
		}
	}
	for _, cmd := range allCommands() {
		if !slices.Contains(ops, cmd.Op()) {
			t.Errorf("scenario never applied %s", cmd.Op())
		}
	}

	// Replay the encoded log into a fresh store: same outcomes, same rows.
	dst := openTest(t)
	for i, b := range src.log {
		cmd, err := DecodeCommand(b)
		if err != nil {
			t.Fatal(err)
		}
		_, err = dst.ApplyLocal(t.Context(), cmd)
		if want := src.errs[i]; (err == nil) != (want == nil) || (err != nil && err.Error() != want.Error()) {
			t.Fatalf("replay %d (%s): err = %v, want %v", i, cmd.Op(), err, want)
		}
	}
	want, got := dumpTables(t, src.db), dumpTables(t, dst.db)
	for _, table := range []string{"admin", "audit_log", "automation_runs", "certs", "cluster_hubs", "config_docs", "device_ceilings", "device_routes", "devices", "join_tokens", "mcp_tokens", "network_hosts", "runbook_runs", "sessions", "sqlite_sequence", "tokens"} {
		if len(want[table]) == 0 {
			t.Errorf("scenario left %s empty; the comparison would prove nothing", table)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("replayed tables differ\n got: %v\nwant: %v", got, want)
	}
}

func TestConsumeTokenSingleUseUnderReplay(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	h := hashSecret("tok")
	now := toMillis(time.Now())
	if _, err := s.ApplyLocal(ctx, CreateToken{Hash: h[:], Labels: `{"a":"b"}`, ExpiresAt: now + 60_000}); err != nil {
		t.Fatal(err)
	}
	// The same command, applied again (a duplicate log entry), loses.
	cmd := ConsumeToken{Hash: h[:], Now: now}
	res, err := s.ApplyLocal(ctx, cmd)
	if err != nil || res.Labels["a"] != "b" {
		t.Fatalf("first consume = %v, %v", res, err)
	}
	if _, err := s.ApplyLocal(ctx, cmd); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("replayed consume err = %v, want ErrTokenUsed", err)
	}
}

func TestApplierSeesEveryWrite(t *testing.T) {
	// A custom Applier that refuses everything: no write may reach the
	// database behind its back, and reads still work.
	refuse := errors.New("not the leader")
	s, err := Open(t.Context(), filepath.Join(t.TempDir(), "hearth.db"), WithApplier(func(*Store) Applier {
		return ApplierFunc(func(context.Context, Command) (Result, error) { return Result{}, refuse })
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := t.Context()
	now := time.Now()
	writes := map[string]error{
		"Upsert": s.Devices().Upsert(ctx, Device{ID: "pi"}),
		"Token":  s.Tokens().Create(ctx, "tok", nil, now),
		"Cert":   s.Certs().Create(ctx, "0a", "pi"),
		"Pw":     s.Admin().SetPasswordHash(ctx, "h"),
		"Sess":   s.Admin().CreateSession(ctx, "s", now, now),
		"Del":    s.Admin().DeleteSession(ctx, "s"),
		"Join":   s.JoinTokens().Create(ctx, "j", now, "storage"),
	}
	_, writes["UseJn"] = s.JoinTokens().Consume(ctx, "j", now)
	_, writes["Consume"] = s.Tokens().Consume(ctx, "tok", now)
	_, writes["Revoke"] = s.Certs().RevokeDevice(ctx, "pi", now)
	_, writes["Audit"] = s.Audit().Append(ctx, AuditEntry{ActorKind: "a", ActorID: "b", Action: "c", Decision: "d"})
	_, _, writes["Facts"] = s.Devices().ReportFacts(ctx, "pi", DeviceFacts{}, now)
	_, _, writes["Seen"] = s.Devices().MarkSeen(ctx, "pi", now)
	_, writes["Boot"] = s.Devices().SetBootTime(ctx, "pi", now)
	_, writes["Offline"] = s.Devices().MarkOffline(ctx, now)
	for name, err := range writes {
		if !errors.Is(err, refuse) {
			t.Errorf("%s: err = %v, want the applier's error", name, err)
		}
	}
	for table, rows := range dumpTables(t, s.db) {
		// sqlite_sequence only holds goose's own counter here.
		if table != "sqlite_sequence" && len(rows) != 0 {
			t.Errorf("%s has rows %v; a write bypassed the applier", table, rows)
		}
	}
	if devs, err := s.Devices().List(ctx); err != nil || len(devs) != 0 {
		t.Fatalf("List = %v, %v", devs, err)
	}
}
