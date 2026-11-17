// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"testing"
	"time"

	"github.com/gvart/hearth/internal/store"
)

// TestAppliedEvents maps applied commands to the events a follower publishes.
func TestAppliedEvents(t *testing.T) {
	ms := func(s int) int64 { return time.Unix(1_700_000_000+int64(s), 0).UnixMilli() }
	boot := ms(-3600)
	tests := []struct {
		name  string
		cmd   store.Command
		local bool
		want  []string // "type id"
	}{
		{"enrollment publishes nothing", store.UpsertDevice{
			ID: "pi", Name: "pi", Facts: "{}", Labels: "{}", FirstSeen: ms(0), LastSeen: ms(0), Status: store.StatusUnknown,
		}, false, nil},
		{"first facts: online", store.ReportFacts{ID: "pi", Facts: "{}", Now: ms(1)}, false, []string{"device.online pi"}},
		{"facts again: updated", store.ReportFacts{ID: "pi", Facts: "{}", Now: ms(2)}, false, []string{"device.updated pi"}},
		{"boot time: updated", store.SetBootTime{ID: "pi", BootTime: &boot}, false, []string{"device.updated pi"}},
		{"batch moving last_seen: updated", store.MarkSeenBatch{Seen: []store.Seen{{ID: "pi", LastSeen: ms(5)}, {ID: "gone", LastSeen: ms(5)}}}, false, []string{"device.updated pi"}},
		{"batch not moving it: nothing", store.MarkSeenBatch{Seen: []store.Seen{{ID: "pi", LastSeen: ms(4)}}}, false, nil},
		{"local entries are the leader's own", store.MarkDevicesOffline{IDs: []string{"pi"}}, true, nil},
		{"back online", store.MarkSeen{ID: "pi", Now: ms(6)}, false, []string{"device.online pi"}},
		{"named offline: offline", store.MarkDevicesOffline{IDs: []string{"pi"}}, false, []string{"device.offline pi"}},
		{"already offline: nothing", store.MarkDevicesOffline{IDs: []string{"pi"}}, false, nil},
		{"facts once more", store.ReportFacts{ID: "pi", Facts: "{}", Now: ms(7)}, false, []string{"device.online pi"}},
		{"cutoff offline: offline", store.MarkOffline{Cutoff: ms(8)}, false, []string{"device.offline pi"}},
		{"revocation publishes nothing", store.RevokeDevice{DeviceID: "pi", Now: ms(9)}, false, nil},
	}
	st := newTestStore(t)
	reg := NewRegistry(RegistryConfig{Store: st, Replicated: true})
	ch, unsubscribe := reg.Subscribe()
	defer unsubscribe()
	for i, tt := range tests {
		res, err := st.ApplyLocal(t.Context(), tt.cmd)
		if err != nil {
			t.Fatalf("%s: apply: %v", tt.name, err)
		}
		if i == 0 { // a certificate for the revocation at the end
			if err := st.Certs().Create(t.Context(), "01", "pi"); err != nil {
				t.Fatal(err)
			}
		}
		reg.Applied(tt.cmd, res, tt.local)
		var got []string
		for len(ch) > 0 {
			e := <-ch
			got = append(got, e.Type+" "+e.Device.ID)
			if e.Device.ID == "" || e.Device.Status == "" {
				t.Errorf("%s: event without the device row: %+v", tt.name, e)
			}
		}
		if len(got) != len(tt.want) || (len(got) > 0 && got[0] != tt.want[0]) {
			t.Errorf("%s: events %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestAppliedStandaloneAndRestore: a standalone registry ignores applies,
// and a snapshot restore ends every subscription so clients resync.
func TestAppliedStandaloneAndRestore(t *testing.T) {
	st := newTestStore(t)
	enrollDevice(t, st, "pi")
	cmd := store.ReportFacts{ID: "pi", Facts: "{}", Now: time.Now().UnixMilli()}
	res, err := st.ApplyLocal(t.Context(), cmd)
	if err != nil {
		t.Fatal(err)
	}
	solo := NewRegistry(RegistryConfig{Store: st})
	ch, unsubscribe := solo.Subscribe()
	defer unsubscribe()
	solo.Applied(cmd, res, false)
	if len(ch) != 0 {
		t.Errorf("standalone registry published %d events from an apply", len(ch))
	}

	clustered := NewRegistry(RegistryConfig{Store: st, Replicated: true})
	a, _ := clustered.Subscribe()
	b, _ := clustered.Subscribe()
	clustered.Restored()
	for _, c := range []<-chan Event{a, b} {
		if _, ok := <-c; ok {
			t.Error("subscription open after a restore")
		}
	}
	clustered.Restored() // no subscribers: a no-op
}
