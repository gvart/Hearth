// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"bytes"
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
