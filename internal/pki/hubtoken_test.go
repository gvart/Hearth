// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"strings"
	"testing"
)

// TestHubTokenRoundTrip: a token naming its owning hub parses back with the
// hub URL; the hearth1 form keeps parsing with none; a bad URL part is
// refused without echoing the token.
func TestHubTokenRoundTrip(t *testing.T) {
	ca, _ := newCA(t)
	tok, err := NewToken(ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	s := tok.EncodeHub("https://hub-b.lan:8443")
	if !strings.HasPrefix(s, "hearth2.") {
		t.Fatalf("EncodeHub = %q, want hearth2. prefix", s)
	}
	got, err := ParseToken(s)
	if err != nil {
		t.Fatalf("ParseToken: %v", err)
	}
	if got.Secret != tok.Secret || got.CAFingerprint != tok.CAFingerprint || got.HubURL != "https://hub-b.lan:8443" {
		t.Errorf("round trip = %+v", got)
	}
	if old, err := ParseToken(tok.Encode()); err != nil || old.HubURL != "" || old.Secret != tok.Secret {
		t.Errorf("hearth1 token = %+v, %v", old, err)
	}
	for _, bad := range []string{
		s[:strings.LastIndexByte(s, '.')] + ".!!!",
		s[:strings.LastIndexByte(s, '.')] + ".",
		"hearth2." + tok.Secret,
		strings.Replace(tok.Encode(), "hearth1.", "hearth2.", 1),
	} {
		if _, err := ParseToken(bad); err == nil {
			t.Errorf("ParseToken(%q) succeeded", bad)
		} else if strings.Contains(err.Error(), tok.Secret) {
			t.Errorf("error echoes the secret: %v", err)
		}
	}
}
