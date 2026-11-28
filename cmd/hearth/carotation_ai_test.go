// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"testing"

	"github.com/gvart/hearth/internal/hubconfig"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/store"
)

// A hub CA rotation re-seals ai.yaml with the new CA's key, as it does
// notify.yaml: after the rotation the document still opens.
func TestResealAIDoc(t *testing.T) {
	oldKey, newKey := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32)
	notify, err := kubernetes.NewPurposeSealer(oldKey, notifySealInfo)
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("provider: anthropic\napi_key: k\n")
	stored, err := hubconfig.Seal([]hubconfig.Doc{{Kind: store.ConfigAI, Name: hubconfig.AIFile, Content: content}}, notify)
	if err != nil {
		t.Fatal(err)
	}
	// The rotation: the new key seals, the old one still opens.
	if err := notify.SetSecrets(newKey, oldKey); err != nil {
		t.Fatal(err)
	}
	s := &hubSealers{notify: notify}
	id := store.ConfigDocID(store.ConfigAI, hubconfig.AIFile)
	out, err := s.reseal(t.Context(), []store.SealedSecret{{Table: store.SealedConfigDocs, ID: id, Sealed: stored[0].Content}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("resealed %d secrets", len(out))
	}
	// Once the old key is gone, the re-sealed document opens.
	if err := notify.SetSecrets(newKey); err != nil {
		t.Fatal(err)
	}
	got, err := notify.Open(hubconfig.SealIDOfRow(id), out[0].Resealed)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatalf("open after rotation = %q, %v", got, err)
	}
}
