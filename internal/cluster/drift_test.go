// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/pki"
	clusterv1 "github.com/gvart/hearth/internal/proto/hearth/cluster/v1"
	"github.com/gvart/hearth/internal/proto/hearth/cluster/v1/clusterv1connect"
)

// digestMark starts every fake digest, so a test can see one leak.
const digestMark = "fakedigest-"

// hubConfig is a hub's configuration digests, which a test can change while
// the hub runs.
type hubConfig struct {
	mu      sync.Mutex
	digests map[string]string
}

func (c *hubConfig) source() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return maps.Clone(c.digests)
}

func (c *hubConfig) set(item, content string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.digests[item] = digestMark + content
}

// sameConfig gives every hub the same configuration.
func sameConfig(hubs []*testHub) map[string]*hubConfig {
	out := map[string]*hubConfig{}
	for _, h := range hubs {
		c := &hubConfig{digests: map[string]string{}}
		for _, item := range configItems {
			c.set(item, "shared")
		}
		h.SetConfigSource(c.source)
		out[h.ID()] = c
	}
	return out
}

func driftOf(t *testing.T, n *testNode) DriftReport {
	t.Helper()
	r, err := n.ConfigDrift(t.Context())
	if err != nil {
		t.Fatalf("ConfigDrift on %s: %v", n.ID(), err)
	}
	return r
}

func itemOf(t *testing.T, r DriftReport, item string) DriftItem {
	t.Helper()
	i := slices.IndexFunc(r.Items, func(it DriftItem) bool { return it.Item == item })
	if i < 0 {
		t.Fatalf("no item %s in %+v", item, r)
	}
	return r.Items[i]
}

func hubOf(t *testing.T, r DriftReport, id string) DriftHub {
	t.Helper()
	i := slices.IndexFunc(r.Hubs, func(h DriftHub) bool { return h.ID == id })
	if i < 0 {
		t.Fatalf("no hub %s in %+v", id, r)
	}
	return r.Hubs[i]
}

func wantItem(t *testing.T, got DriftItem, status string, groups [][]string, unknown []string) {
	t.Helper()
	want := DriftItem{Item: got.Item, Status: status, Groups: groups, Unknown: unknown}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s = %+v, want %+v", got.Item, got, want)
	}
}

var allThree = [][]string{{"n1", "n2", "n3"}}

// TestConfigDriftDetected covers each configuration item differing on one hub,
// as seen from every hub, the leader and the followers alike.
func TestConfigDriftDetected(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	configs := sameConfig(hubs)
	for _, h := range hubs {
		r := driftOf(t, h.testNode)
		for _, item := range configItems {
			wantItem(t, itemOf(t, r, item), DriftInSync, allThree, []string{})
		}
	}
	for _, item := range configItems {
		t.Run(item, func(t *testing.T) {
			configs["n3"].set(item, "edited on n3")
			defer configs["n3"].set(item, "shared")
			for _, h := range hubs {
				r := driftOf(t, h.testNode)
				for _, other := range configItems {
					if other == item {
						wantItem(t, itemOf(t, r, other), DriftDiffers, [][]string{{"n1", "n2"}, {"n3"}}, []string{})
					} else {
						wantItem(t, itemOf(t, r, other), DriftInSync, allThree, []string{})
					}
				}
			}
		})
	}
}

// TestConfigDriftFollowsChanges: a digest that changes while the hubs run is
// noticed on the next comparison, and the warning clears once they agree.
func TestConfigDriftFollowsChanges(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	configs := sameConfig(hubs)
	configs["n2"].set(ConfigHostFlags, "one more automation")
	wantItem(t, itemOf(t, driftOf(t, hubs[0].testNode), ConfigHostFlags), DriftDiffers,
		[][]string{{"n1", "n3"}, {"n2"}}, []string{})
	configs["n2"].set(ConfigHostFlags, "shared")
	wantItem(t, itemOf(t, driftOf(t, hubs[0].testNode), ConfigHostFlags), DriftInSync, allThree, []string{})
}

func TestConfigDriftSingleHub(t *testing.T) {
	n := startNode(t, newTestCA(t), "solo", "", "", true)
	leaderOf(t, n)
	c := &hubConfig{digests: map[string]string{}}
	for _, item := range configItems {
		c.set(item, "only")
	}
	n.SetConfigSource(c.source)
	r := driftOf(t, n)
	for _, item := range configItems {
		wantItem(t, itemOf(t, r, item), DriftInSync, [][]string{{"solo"}}, []string{})
	}
}

// TestConfigDriftHubDown: a hub that is down is unknown, not differing, whether
// or not the others agree.
func TestConfigDriftHubDown(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	configs := sameConfig(hubs)
	leader := leaderHub(t, hubs)
	down := followers(hubs, leader)[0]
	up := followers(hubs, leader)[1]
	configs[down.ID()].set(ConfigHostFlags, "different, but about to go down")
	down.kill()

	r := driftOf(t, leader.testNode)
	if h := hubOf(t, r, down.ID()); h.Reported || h.Reason != DriftUnreachable {
		t.Errorf("hub down = %+v", h)
	}
	agree := []string{leader.ID(), up.ID()}
	slices.Sort(agree)
	for _, item := range configItems {
		wantItem(t, itemOf(t, r, item), DriftUnknown, [][]string{agree}, []string{down.ID()})
	}

	// The hubs that are up still differ from each other.
	configs[up.ID()].set(ConfigHostFlags, "edited")
	got := itemOf(t, driftOf(t, leader.testNode), ConfigHostFlags)
	if got.Status != DriftDiffers || len(got.Groups) != 2 || !slices.Equal(got.Unknown, []string{down.ID()}) {
		t.Errorf("two live hubs differing with one down = %+v", got)
	}
}

// TestConfigDriftNotReportedYet: a hub that answers without digests, as one
// still starting does, is unknown.
func TestConfigDriftNotReportedYet(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	sameConfig(hubs[:2])
	r := driftOf(t, hubs[0].testNode)
	if h := hubOf(t, r, "n3"); h.Reported || h.Reason != DriftNotReported {
		t.Errorf("n3 = %+v", h)
	}
	for _, item := range configItems {
		wantItem(t, itemOf(t, r, item), DriftUnknown, [][]string{{"n1", "n2"}}, []string{"n3"})
	}
}

// TestConfigDriftOlderItems: a hub whose Hearth compares the files it used to
// read (policy.yaml, notify.yaml, automations, runbooks) and not the host
// flags is unknown for the host flags, and its old items are ignored: they
// are documents of the store now, the same on every hub.
func TestConfigDriftOlderItems(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	configs := sameConfig(hubs)
	configs["n2"].mu.Lock()
	configs["n2"].digests = map[string]string{"policy.yaml": digestMark + "x", "automations": digestMark + "y"}
	configs["n2"].mu.Unlock()
	r := driftOf(t, hubs[0].testNode)
	wantItem(t, itemOf(t, r, ConfigHostFlags), DriftUnknown, [][]string{{"n1", "n3"}}, []string{"n2"})
	if len(r.Items) != 1 {
		t.Errorf("items = %+v, want the host flags only", r.Items)
	}
}

// olderHub answers like a hub whose Hearth predates ConfigDigests: its
// ClusterService does not know the procedure.
func olderHub(t *testing.T, h *testHub) *httptest.Server {
	t.Helper()
	cert, err := h.ca.IssueServerCert([]string{"127.0.0.1"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.NewServeMux())
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// TestConfigDriftMixedVersions: a hub on an older Hearth is unknown, and the
// cluster keeps working around it.
func TestConfigDriftMixedVersions(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	sameConfig(hubs[:2])
	old := olderHub(t, hubs[0])
	if err := hubs[0].st.Hubs().SetAgentURL(t.Context(), "n3", old.URL); err != nil {
		t.Fatal(err)
	}
	eventually(t, "n1 and n2 to see n3 as an older hub", func() bool {
		for _, h := range hubs[:2] {
			if hubOfReason(t, h, "n3") != DriftOlderVersion {
				return false
			}
		}
		return true
	})
	r := driftOf(t, hubs[1].testNode)
	for _, item := range configItems {
		wantItem(t, itemOf(t, r, item), DriftUnknown, [][]string{{"n1", "n2"}}, []string{"n3"})
	}
	upsert(t, hubs[1].testNode, "still-writable")
	eventually(t, "the write on every hub", func() bool { return hasDevice(hubs[2].testNode, "still-writable") })
}

func hubOfReason(t *testing.T, h *testHub, id string) string {
	t.Helper()
	return hubOf(t, driftOf(t, h.testNode), id).Reason
}

// TestConfigDigestsRejectsNonMembers: digests go to cluster members only.
func TestConfigDigestsRejectsNonMembers(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	sameConfig(hubs)
	leader := leaderHub(t, hubs)
	follower := followers(hubs, leader)[0]
	member := followers(hubs, leader)[1]
	revoked := hubCert(t, leader.ca, member.ID())
	if err := leader.st.Hubs().RecordCert(t.Context(), pki.SerialString(revoked.Leaf), member.ID()); err != nil {
		t.Fatal(err)
	}
	if _, err := leader.st.Hubs().RevokeCerts(t.Context(), member.ID(), time.Now()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the revocation on "+follower.ID(), func() bool {
		return follower.checkPeerCert(revoked.Leaf) != nil
	})

	call := func(certs ...tls.Certificate) (*connect.Response[clusterv1.ConfigDigestsResponse], error) {
		c := clusterv1connect.NewClusterServiceClient(tlsClient(leader.ca, certs...), follower.url)
		return c.ConfigDigests(t.Context(), connect.NewRequest(&clusterv1.ConfigDigestsRequest{}))
	}
	tests := []struct {
		name  string
		certs []tls.Certificate
		want  connect.Code
	}{
		{"no certificate", nil, connect.CodeUnauthenticated},
		{"device certificate", []tls.Certificate{enrollTestDevice(t, leader, "pi")}, connect.CodePermissionDenied},
		{"hub certificate of a non-member", []tls.Certificate{hubCert(t, leader.ca, "stranger")}, connect.CodePermissionDenied},
		{"revoked hub certificate", []tls.Certificate{revoked}, connect.CodePermissionDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := call(tt.certs...)
			if got := connect.CodeOf(err); err == nil || got != tt.want {
				t.Errorf("code = %v (err %v), want %v", got, err, tt.want)
			}
			if resp != nil {
				t.Errorf("answered %v", resp.Msg.GetDigests())
			}
		})
	}
	resp, err := call(hubCert(t, leader.ca, leader.ID()))
	if err != nil {
		t.Fatalf("member: %v", err)
	}
	if len(resp.Msg.GetDigests()) != len(configItems) {
		t.Errorf("member got %d digests, want %d", len(resp.Msg.GetDigests()), len(configItems))
	}
}

// TestConfigDriftHoldsNoDigests guards what leaves the hub: the report, and
// the status the CLI prints, name items and hubs and never a digest.
func TestConfigDriftHoldsNoDigests(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: time.Minute, flushEvery: time.Minute})
	configs := sameConfig(hubs)
	configs["n3"].set(ConfigHostFlags, "s3cret")

	ctx, cancel := context.WithTimeout(t.Context(), waitFor)
	defer cancel()
	var st Status
	eventually(t, "a status comparing every hub", func() bool {
		var err error
		st, err = hubs[0].StatusWithSchemas(ctx)
		return err == nil && st.ConfigDrift != nil &&
			itemOf(t, *st.ConfigDrift, ConfigHostFlags).Status == DriftDiffers
	})
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	for _, leak := range []string{digestMark, "s3cret"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("status holds %q: %s", leak, b)
		}
	}
}
