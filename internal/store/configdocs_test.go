// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestConfigDocsPutListDelete(t *testing.T) {
	ctx := t.Context()
	s := openMember(t, "a", time.Unix(1_700_000_000, 0))
	r := s.ConfigDocs()
	now := time.UnixMilli(1_700_000_000_000).UTC()
	if err := r.Put(ctx, "admin/op", []ConfigDoc{
		{Kind: ConfigPolicy, Name: "policy.yaml", Content: []byte("classes: {}\n")},
		{Kind: ConfigAutomation, Name: "a.yaml", Content: []byte("id: a\n")},
	}, now); err != nil {
		t.Fatal(err)
	}
	docs, err := r.List(ctx, "")
	if err != nil || len(docs) != 2 {
		t.Fatalf("List = %v, %v", docs, err)
	}
	if d := docs[0]; d.Kind != ConfigAutomation || string(d.Content) != "id: a\n" || d.UpdatedBy != "admin/op" ||
		!d.UpdatedAt.Equal(now) || d.Digest != ConfigDigest(d.Content) {
		t.Fatalf("doc = %+v", d)
	}
	if err := r.Delete(ctx, ConfigAutomation, "a.yaml"); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Get(ctx, ConfigAutomation, "a.yaml"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after delete = %v, want ErrNotFound", err)
	}
	var content []byte
	if err := s.db.QueryRowContext(ctx, `SELECT content FROM config_docs WHERE id = 'automation/a.yaml' AND _deleted = 1`).
		Scan(&content); err != nil || len(content) != 0 {
		t.Fatalf("tombstone content = %q, %v; want none", content, err)
	}
	for _, kind := range []string{ConfigPolicy, ConfigNotify} {
		if err := r.Delete(ctx, kind, "x"); !errors.Is(err, ErrConfigDoc) {
			t.Errorf("Delete %s = %v, want ErrConfigDoc", kind, err)
		}
	}
	if err := r.Put(ctx, "admin/op", []ConfigDoc{{Kind: "secrets", Name: "x"}}, now); !errors.Is(err, ErrConfigDoc) {
		t.Errorf("Put unknown kind = %v, want ErrConfigDoc", err)
	}
}

func TestConfigDocsImportFirstOnce(t *testing.T) {
	ctx := t.Context()
	s := openMember(t, "a", time.Unix(1_700_000_000, 0))
	r := s.ConfigDocs()
	doc := []ConfigDoc{{Kind: ConfigPolicy, Name: "policy.yaml", Content: []byte{}}}
	if err := r.ImportFirst(ctx, "hub/a", doc, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := r.ImportFirst(ctx, "hub/b", doc, time.Now()); !errors.Is(err, ErrExists) {
		t.Fatalf("second ImportFirst = %v, want ErrExists", err)
	}
}

// An edit on one member, merged into another, is the document there; an
// older version merged later does not undo it, and a delete merges as a
// tombstone.
func TestConfigDocsMerge(t *testing.T) {
	ctx := t.Context()
	start := time.Unix(1_700_000_000, 0)
	a, b := openMember(t, "a", start), openMember(t, "b", start)
	put := func(s *Store, content string) []Mutation {
		return write(t, s, PutConfigDocs{By: "admin/op", Now: 1, Docs: []ConfigDocWrite{{
			Kind: ConfigPolicy, Name: "policy.yaml", Content: []byte(content), Digest: ConfigDigest([]byte(content)),
		}}})
	}
	other := write(t, a, PutConfigDocs{By: "admin/op", Now: 1, Docs: []ConfigDocWrite{{
		Kind: ConfigAutomation, Name: "z.yaml", Content: []byte("id: z\n"), Digest: ConfigDigest([]byte("id: z\n")),
	}}})
	old := put(b, "old\n")
	newer := put(a, "new\n")
	fp0, err := b.ConfigDocs().Fingerprint(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Merge(ctx, append(newer, other...)); err != nil {
		t.Fatal(err)
	}
	if err := b.Merge(ctx, old); err != nil {
		t.Fatal(err)
	}
	got, err := b.ConfigDocs().Get(ctx, ConfigPolicy, "policy.yaml")
	if err != nil || !bytes.Equal(got.Content, []byte("new\n")) {
		t.Fatalf("merged policy = %q, %v; want the newer one", got.Content, err)
	}
	fp1, err := b.ConfigDocs().Fingerprint(ctx)
	if err != nil || fp1 == fp0 {
		t.Fatalf("fingerprint did not change on merge: %v", err)
	}
	// A merge of a row older than the newest row still changes the
	// fingerprint.
	del := write(t, a, DeleteConfigDoc{Kind: ConfigAutomation, Name: "z.yaml"})
	write(t, b, PutConfigDocs{By: "admin/op", Now: 2, Docs: []ConfigDocWrite{{
		Kind: ConfigRunbook, Name: "late.yaml", Content: []byte("x"), Digest: ConfigDigest([]byte("x")),
	}}})
	fp2, _ := b.ConfigDocs().Fingerprint(ctx)
	if err := b.Merge(ctx, del); err != nil {
		t.Fatal(err)
	}
	if fp3, _ := b.ConfigDocs().Fingerprint(ctx); fp3 == fp2 {
		t.Fatal("fingerprint did not change on a merged delete")
	}
	if _, err := b.ConfigDocs().Get(ctx, ConfigAutomation, "z.yaml"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("merged delete: Get = %v, want ErrNotFound", err)
	}
}

// A member not migrated to schema 28 opens, writes and collects tombstones
// without the table, and refuses document writes.
func TestConfigDocsBelowSchema(t *testing.T) {
	ctx := t.Context()
	s := openAtSchema(t, configDocsSchema-1)
	r := s.ConfigDocs()
	if ok, err := r.Available(ctx); err != nil || ok {
		t.Fatalf("Available = %v, %v; want false", ok, err)
	}
	if fp, err := r.Fingerprint(ctx); err != nil || fp != "" {
		t.Fatalf("Fingerprint = %q, %v", fp, err)
	}
	if err := r.Put(ctx, "admin/op", []ConfigDoc{{Kind: ConfigPolicy, Name: "policy.yaml"}}, time.Now()); !errors.Is(err, ErrSchemaTooOld) {
		t.Fatalf("Put = %v, want ErrSchemaTooOld", err)
	}
	if _, err := s.GCTombstones(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CARotations().Sealed(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApplyLocal(ctx, PutConfigDocs{}); !errors.Is(err, ErrSchemaTooOld) {
		t.Fatalf("ApplyLocal = %v, want ErrSchemaTooOld", err)
	}
}

// Only notify documents are sealed secrets for a CA rotation.
func TestConfigDocsSealed(t *testing.T) {
	ctx := t.Context()
	s := openMember(t, "a", time.Unix(1_700_000_000, 0))
	if err := s.ConfigDocs().Put(ctx, "admin/op", []ConfigDoc{
		{Kind: ConfigPolicy, Name: "policy.yaml", Content: []byte("plain")},
		{Kind: ConfigNotify, Name: "notify.yaml", Content: []byte("sealed")},
	}, time.Now()); err != nil {
		t.Fatal(err)
	}
	secrets, err := s.CARotations().Sealed(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(secrets) != 1 || secrets[0].Table != SealedConfigDocs || secrets[0].ID != "notify/notify.yaml" ||
		string(secrets[0].Sealed) != "sealed" {
		t.Fatalf("Sealed = %+v", secrets)
	}
}

func TestConfigDocsCommandRoundTrip(t *testing.T) {
	for _, cmd := range []Command{
		PutConfigDocs{By: "x", Now: 1, IfNone: true, Docs: []ConfigDocWrite{{Kind: ConfigRunbook, Name: "r.yaml", Content: []byte("c"), Digest: "d"}}},
		DeleteConfigDoc{Kind: ConfigRunbook, Name: "r.yaml"},
	} {
		b, err := EncodeCommand(cmd)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeCommand(b)
		if err != nil {
			t.Fatal(err)
		}
		if got.Op() != cmd.Op() {
			t.Fatalf("round trip %s = %s", cmd.Op(), got.Op())
		}
	}
}

// TestConfigDocsVersion: the version of a kind grows with each write and
// delete of one of its documents, and no other kind's moves it.
func TestConfigDocsVersion(t *testing.T) {
	ctx := t.Context()
	s := openMember(t, "a", time.Unix(1_700_000_000, 0))
	r := s.ConfigDocs()
	version := func() uint64 {
		t.Helper()
		v, err := r.Version(ctx, ConfigAutomation)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	if v := version(); v != 0 {
		t.Fatalf("Version with no documents = %d, want 0", v)
	}
	if err := r.Put(ctx, "admin/op", []ConfigDoc{{Kind: ConfigAutomation, Name: "a.yaml", Content: []byte("id: a\n")}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	put := version()
	if put == 0 {
		t.Fatal("Version after a put = 0")
	}
	if err := r.Put(ctx, "admin/op", []ConfigDoc{{Kind: ConfigRunbook, Name: "r.yaml", Content: []byte("id: r\n")}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if v := version(); v != put {
		t.Fatalf("Version after a runbook put = %d, want %d", v, put)
	}
	if err := r.Delete(ctx, ConfigAutomation, "a.yaml"); err != nil {
		t.Fatal(err)
	}
	if v := version(); v <= put {
		t.Fatalf("Version after a delete = %d, want more than %d", v, put)
	}
}
