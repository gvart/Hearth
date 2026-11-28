// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"bytes"
	"errors"
	"testing"
)

// A rotation run through its finish leaves the entries sealed before it
// verifiable: the keyring keeps the key of the CA it no longer holds, and
// seals with the serving CA's at every stage.
func TestAuditKeyringThroughARotation(t *testing.T) {
	ca, _ := newCA(t)
	ring, err := NewAuditKeyring(ca)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("entry")
	oldKID, oldMAC, err := ring.MAC(msg)
	if err != nil || oldKID != AuditKeyID(ca.Cert()) {
		t.Fatalf("MAC = %s, %v; want the CA's key id", oldKID, err)
	}
	if known, ok := ring.Check(oldKID, msg, oldMAC); !known || !ok {
		t.Fatal("a fresh MAC does not check")
	}
	if _, ok := ring.Check(oldKID, []byte("other"), oldMAC); ok {
		t.Fatal("a MAC checks another message")
	}

	next, err := ca.GenerateNext(now)
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.TrustNext(next); err != nil {
		t.Fatal(err)
	}
	// Before the cutover the old CA serves, and seals.
	if kid, _, _ := ring.MAC(msg); kid != oldKID || len(ring.Held()) != 2 {
		t.Fatalf("before the cutover: sealing with %s, %d keys held", kid, len(ring.Held()))
	}
	if err := ca.Cutover(); err != nil {
		t.Fatal(err)
	}
	newKID, newMAC, err := ring.MAC(msg)
	if err != nil || newKID != AuditKeyID(next) || newKID == oldKID {
		t.Fatalf("after the cutover: sealing with %s, %v; want the next CA's key", newKID, err)
	}
	if err := ca.Finish(); err != nil {
		t.Fatal(err)
	}
	if held := ring.Held(); len(held) != 1 || held[0].ID != newKID {
		t.Fatalf("after the finish: held %v, want the new key alone", held)
	}
	for _, c := range []struct {
		kid string
		mac []byte
	}{{oldKID, oldMAC}, {newKID, newMAC}} {
		if known, ok := ring.Check(c.kid, msg, c.mac); !known || !ok {
			t.Errorf("after the finish, a MAC of %s does not check", c.kid)
		}
	}

	// A hub started after the finish knows the old key only from the
	// sealed copy the masters keep (AddEarlier).
	fresh, err := NewAuditKeyring(ca)
	if err != nil {
		t.Fatal(err)
	}
	if known, _ := fresh.Check(oldKID, msg, oldMAC); known {
		t.Fatal("a fresh keyring knows a key it was not given")
	}
	fresh.AddEarlier(AuditKey{ID: oldKID, Key: earlierKey(t, ring, oldKID)})
	if _, ok := fresh.Check(oldKID, msg, oldMAC); !ok {
		t.Fatal("the earlier key added does not check")
	}
}

func earlierKey(t *testing.T, ring *AuditKeyring, kid string) []byte {
	t.Helper()
	ring.mu.RLock()
	defer ring.mu.RUnlock()
	k, ok := ring.earlier[kid]
	if !ok {
		t.Fatalf("no earlier key %s", kid)
	}
	return bytes.Clone(k)
}

// A hub without the CA key seals nothing and checks nothing.
func TestAuditKeyringWithoutTheKey(t *testing.T) {
	ca, _ := newCA(t)
	ring, err := NewAuditKeyring(ca)
	if err != nil {
		t.Fatal(err)
	}
	kid, mac, err := ring.MAC([]byte("entry"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ca.DropKey(); err != nil {
		t.Fatal(err)
	}
	if ring.CanVerify() {
		t.Fatal("a keyless hub can verify")
	}
	if _, _, err := ring.MAC([]byte("entry")); !errors.Is(err, ErrNoCAKey) {
		t.Fatalf("MAC without the key = %v, want ErrNoCAKey", err)
	}
	// Unlike after a rotation, a demoted master keeps no derived key.
	if known, _ := ring.Check(kid, []byte("entry"), mac); known {
		t.Error("the dropped key is still known")
	}
}

// Each CA has an audit key of its own, and the key is not the CA key.
func TestDeriveAuditKey(t *testing.T) {
	a, _ := newCA(t)
	b, _ := newCA(t)
	ka, err := a.AuditKeys()
	if err != nil || len(ka) != 1 {
		t.Fatal(ka, err)
	}
	kb, err := b.AuditKeys()
	if err != nil || len(kb) != 1 {
		t.Fatal(kb, err)
	}
	if bytes.Equal(ka[0].Key, kb[0].Key) || ka[0].ID == kb[0].ID {
		t.Fatal("two CAs share an audit key")
	}
	der, err := a.KeyDERs()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(der[0], ka[0].Key) {
		t.Fatal("the audit key is part of the CA key")
	}
	if _, err := DeriveAuditKey(nil); !errors.Is(err, ErrNoCAKey) {
		t.Fatalf("DeriveAuditKey(nil) = %v", err)
	}
}
