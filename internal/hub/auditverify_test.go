// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"net/http"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// The audit API says, per entry and for the whole log, whether the seals
// check (#387).
func TestAPIAuditVerify(t *testing.T) {
	f := newAPIFixture(t, true)
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ring, err := pki.NewAuditKeyring(ca)
	if err != nil {
		t.Fatal(err)
	}
	f.st.SetAuditSealer(ring)
	c := sessionCookie(t, f.login(t, testPassword))
	if _, err := f.st.Audit().Append(t.Context(), store.AuditEntry{
		ActorKind: "admin", ActorID: "root", Action: "device.revoke", Target: "d1", Decision: "allow",
	}); err != nil {
		t.Fatal(err)
	}
	if resp := f.do(t, http.MethodGet, "/api/v1/audit/verify", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("unauthenticated = %d", resp.StatusCode)
	}
	p := decode[AuditPageJSON](t, f.do(t, http.MethodGet, "/api/v1/audit?action=device.revoke", "", c))
	if e := p.Entries[0]; e.Verification != store.AuditVerified || e.SealSeq == 0 || e.SealOrigin == "" {
		t.Errorf("entry = %+v, want verified and sealed", e)
	}
	v := decode[AuditVerifyJSON](t, f.do(t, http.MethodGet, "/api/v1/audit/verify", "", c))
	// The fixture's entries written before the first seal (its admin
	// password) are legacy; the rest is one chain.
	ch := v.Chains
	if !v.OK || !v.CanVerify || v.Legacy == 0 || v.Unsealed != 0 || len(ch) != 1 || ch[0].Verified != int(ch[0].Last) {
		t.Errorf("verify = %+v", v)
	}
}
