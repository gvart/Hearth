// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"bytes"
	"strings"
	"testing"
)

func TestSealer(t *testing.T) {
	s, err := NewSealer([]byte("ca key a"))
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewSealer([]byte("ca key b"))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("apiVersion: v1\nkind: Config\n")
	sealed, err := s.Seal("c1", plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, plain) {
		t.Fatal("sealed kubeconfig contains the plaintext")
	}
	again, _ := s.Seal("c1", plain)
	if bytes.Equal(sealed, again) {
		t.Error("two seals of the same plaintext are equal: nonce reused")
	}
	got, err := s.Open("c1", sealed)
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("Open = %q, %v", got, err)
	}

	tampered := bytes.Clone(sealed)
	tampered[len(tampered)-1] ^= 1
	for name, open := range map[string]func() ([]byte, error){
		"another cluster ID": func() ([]byte, error) { return s.Open("c2", sealed) },
		"another CA key":     func() ([]byte, error) { return other.Open("c1", sealed) },
		"tampered":           func() ([]byte, error) { return s.Open("c1", tampered) },
		"truncated":          func() ([]byte, error) { return s.Open("c1", sealed[:5]) },
	} {
		if _, err := open(); err == nil {
			t.Errorf("Open with %s succeeded", name)
		}
	}
	if _, err := NewSealer(nil); err == nil {
		t.Error("NewSealer with an empty secret succeeded")
	}
}

// While the hub CA rotates, a sealer seals with the new key and opens with
// either; Reseal moves what the old key sealed to the new one.
func TestSealerKeyring(t *testing.T) {
	oldKey, newKey := []byte("old ca key"), []byte("new ca key")
	s, err := NewPurposeSealer(oldKey, "test seal v1")
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("secret")
	byOld, err := s.Seal("r1", plain)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecrets(newKey, oldKey); err != nil {
		t.Fatal(err)
	}
	byNew, err := s.Seal("r1", plain)
	if err != nil {
		t.Fatal(err)
	}
	for name, sealed := range map[string][]byte{"old": byOld, "new": byNew} {
		if got, err := s.Open("r1", sealed); err != nil || !bytes.Equal(got, plain) {
			t.Errorf("Open(%s) during the rotation = %q, %v", name, got, err)
		}
	}
	onlyNew, err := NewPurposeSealer(newKey, "test seal v1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := onlyNew.Open("r1", byOld); err == nil {
		t.Fatal("the new key alone opens what the old one sealed")
	}

	resealed, changed, err := s.Reseal("r1", byOld)
	if err != nil || !changed {
		t.Fatalf("Reseal(old) = %v, %v; want resealed", changed, err)
	}
	if got, err := onlyNew.Open("r1", resealed); err != nil || !bytes.Equal(got, plain) {
		t.Errorf("Open(resealed) with the new key alone = %q, %v", got, err)
	}
	if same, changed, err := s.Reseal("r1", byNew); err != nil || changed || !bytes.Equal(same, byNew) {
		t.Errorf("Reseal(new) = changed %v, %v; want unchanged", changed, err)
	}
	if _, _, err := s.Reseal("r2", byOld); err == nil {
		t.Error("Reseal under another ID succeeded")
	}
	if _, err := s.Open("r1", byOld[:5]); err == nil || !strings.Contains(err.Error(), "too short") {
		t.Errorf("Open(truncated) with two keys = %v, want too short", err)
	}

	// Once the old key is gone only the new one opens.
	if err := s.SetSecrets(newKey); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open("r1", byOld); err == nil {
		t.Error("Open(old) after the old key was dropped succeeded")
	}
	if err := s.SetSecrets(); err == nil {
		t.Error("SetSecrets() with no secret succeeded")
	}
	if err := s.SetSecrets(newKey, nil); err == nil {
		t.Error("SetSecrets with an empty secret succeeded")
	}
}
