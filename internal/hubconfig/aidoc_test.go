// SPDX-License-Identifier: AGPL-3.0-only

package hubconfig

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/store"
)

// tagSealer is a Sealer that tags what it seals with its id.
type tagSealer struct{}

func (tagSealer) Seal(id string, b []byte) ([]byte, error) {
	return append([]byte("sealed:"+id+":"), b...), nil
}

func (tagSealer) Open(id string, b []byte) ([]byte, error) {
	p := []byte("sealed:" + id + ":")
	if !bytes.HasPrefix(b, p) {
		return nil, os.ErrInvalid
	}
	return b[len(p):], nil
}

func TestCheckNameAI(t *testing.T) {
	if err := CheckName(store.ConfigAI, AIFile); err != nil {
		t.Error(err)
	}
	if err := CheckName(store.ConfigAI, "other.yaml"); err == nil {
		t.Error("an ai document of another name")
	}
}

// ai.yaml is sealed like notify.yaml, under its own row's id, and the rest
// is not; an export reads back as it was written.
func TestAIDocSealedAndRoundTrip(t *testing.T) {
	aiYAML := []byte("provider: anthropic\napi_key: sk-ant-SENTINEL\n")
	docs := []Doc{
		{Kind: store.ConfigPolicy, Name: PolicyFile, Content: []byte("classes: {}\n")},
		{Kind: store.ConfigAI, Name: AIFile, Content: aiYAML},
	}
	stored, err := Seal(docs, tagSealer{})
	if err != nil {
		t.Fatal(err)
	}
	if string(stored[0].Content) != "classes: {}\n" {
		t.Errorf("policy sealed: %q", stored[0].Content)
	}
	if !strings.HasPrefix(string(stored[1].Content), "sealed:config-doc/ai/ai.yaml:") {
		t.Errorf("ai.yaml not sealed for its row: %q", stored[1].Content)
	}

	set, err := Parse(docs)
	if err != nil {
		t.Fatal(err)
	}
	if !set.AI.Enabled() || set.AI.Provider != "anthropic" {
		t.Errorf("AI = %+v", set.AI)
	}
	bad := []Doc{{Kind: store.ConfigAI, Name: AIFile, Content: []byte("provider: gemini\napi_key: SENTINEL\n")}}
	if _, err := Parse(bad); err == nil || strings.Contains(err.Error(), "SENTINEL") {
		t.Errorf("bad ai.yaml: %v", err)
	}

	dir := t.TempDir()
	if err := WriteDir(dir, docs); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, AIFile))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("ai.yaml exported as %v, %v", info, err)
	}
	back, err := ReadPath(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 2 || back[0].ID() != "ai/ai.yaml" || !bytes.Equal(back[0].Content, aiYAML) || back[1].ID() != "policy/policy.yaml" {
		t.Fatalf("read back = %+v", back)
	}
	if one, err := ReadPath(filepath.Join(dir, AIFile), ""); err != nil || one[0].Kind != store.ConfigAI {
		t.Fatalf("ai.yaml file = %+v, %v", one, err)
	}
}
