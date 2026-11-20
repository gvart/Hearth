// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"time"
)

// configDocsSchema is the schema version whose migration (00028) added the
// config_docs table. Below it the hub reads its configuration from files.
const configDocsSchema = 28

// ConfigDocsSchema is configDocsSchema, for the hub to check.
const ConfigDocsSchema = configDocsSchema

// Kinds of configuration documents.
const (
	ConfigPolicy     = "policy"
	ConfigNotify     = "notify"
	ConfigAutomation = "automation"
	ConfigRunbook    = "runbook"
)

// ConfigKinds are the kinds of configuration documents.
var ConfigKinds = []string{ConfigPolicy, ConfigNotify, ConfigAutomation, ConfigRunbook}

// ConfigDoc is one configuration document: policy.yaml, notify.yaml, an
// automation file or a runbook file. Content is the file byte for byte, but
// for ConfigNotify, whose content is sealed (see the hub's sealers): the
// store never holds notification credentials in clear.
type ConfigDoc struct {
	Kind string
	Name string
	// Content is the document; sealed for ConfigNotify.
	Content []byte
	// Digest is the SHA-256, in hex, of Content as stored.
	Digest    string
	UpdatedAt time.Time
	// UpdatedBy is the actor that wrote it, as kind/id.
	UpdatedBy string
}

// ConfigDocID is the row id of a document: kind/name.
func ConfigDocID(kind, name string) string { return kind + "/" + name }

// ConfigDigest is the digest of content as a ConfigDoc stores it.
func ConfigDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// ConfigDocs is the repository of configuration documents.
type ConfigDocs struct{ s *Store }

// ConfigDocs returns the configuration documents repository.
func (s *Store) ConfigDocs() ConfigDocs { return ConfigDocs{s: s} }

// Available reports whether the database holds configuration documents:
// whether it is at schema 28 or newer.
func (r ConfigDocs) Available(ctx context.Context) (bool, error) {
	return atSchema(ctx, r.s.db, configDocsSchema)
}

func (r ConfigDocs) requireSchema(ctx context.Context) error {
	ok, err := r.Available(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: configuration documents need schema %d; run `hearth cluster migrate` first",
			ErrSchemaTooOld, configDocsSchema)
	}
	return nil
}

const configDocColumns = `kind, name, content, digest, updated_at, updated_by`

// List returns the live documents of kind, or of every kind for "", ordered
// by kind and name.
func (r ConfigDocs) List(ctx context.Context, kind string) ([]ConfigDoc, error) {
	if err := r.requireSchema(ctx); err != nil {
		return nil, fmt.Errorf("list config documents: %w", err)
	}
	rows, err := r.s.db.QueryContext(ctx, `SELECT `+configDocColumns+` FROM config_docs
		WHERE _deleted = 0 AND (? = '' OR kind = ?) ORDER BY kind, name`, kind, kind)
	if err != nil {
		return nil, fmt.Errorf("list config documents: %w", err)
	}
	defer rows.Close()
	var out []ConfigDoc
	for rows.Next() {
		var (
			d  ConfigDoc
			at int64
		)
		if err := rows.Scan(&d.Kind, &d.Name, &d.Content, &d.Digest, &at, &d.UpdatedBy); err != nil {
			return nil, fmt.Errorf("list config documents: %w", err)
		}
		d.UpdatedAt = fromMillis(at)
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list config documents: %w", err)
	}
	return out, nil
}

// Get returns the live document kind/name, or ErrNotFound.
func (r ConfigDocs) Get(ctx context.Context, kind, name string) (ConfigDoc, error) {
	docs, err := r.List(ctx, kind)
	if err != nil {
		return ConfigDoc{}, err
	}
	for _, d := range docs {
		if d.Name == name {
			return d, nil
		}
	}
	return ConfigDoc{}, fmt.Errorf("config document %s: %w", ConfigDocID(kind, name), ErrNotFound)
}

// Fingerprint changes whenever a document is written, merged or deleted,
// whichever hub wrote it: it covers the version of every row, tombstones
// included. It is "" below schema 28.
func (r ConfigDocs) Fingerprint(ctx context.Context) (string, error) {
	if ok, err := r.Available(ctx); err != nil || !ok {
		return "", err
	}
	rows, err := r.s.db.QueryContext(ctx, `SELECT id, _hlc, _origin, _deleted, digest FROM config_docs ORDER BY id`)
	if err != nil {
		return "", fmt.Errorf("fingerprint config documents: %w", err)
	}
	defer rows.Close()
	h := sha256.New()
	for rows.Next() {
		var (
			id, origin, digest string
			at, deleted        int64
		)
		if err := rows.Scan(&id, &at, &origin, &deleted, &digest); err != nil {
			return "", fmt.Errorf("fingerprint config documents: %w", err)
		}
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00%s\x00%d\x00%s\n", id, at, origin, deleted, digest)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("fingerprint config documents: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Put writes docs in one step, all or none, as by (kind/id) at now. A
// document's Digest is computed here; the hub validates and seals before.
func (r ConfigDocs) Put(ctx context.Context, by string, docs []ConfigDoc, now time.Time) error {
	return r.put(ctx, by, docs, now, false)
}

// ImportFirst is Put, refused with ErrExists if the store holds any
// document already: the one-time import of a hub's files. Of two hubs
// importing at once, the first write wins and the other is refused.
func (r ConfigDocs) ImportFirst(ctx context.Context, by string, docs []ConfigDoc, now time.Time) error {
	return r.put(ctx, by, docs, now, true)
}

func (r ConfigDocs) put(ctx context.Context, by string, docs []ConfigDoc, now time.Time, first bool) error {
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("write config documents: %w", err)
	}
	cmd := PutConfigDocs{IfNone: first, By: by, Now: toMillis(now)}
	for _, d := range docs {
		cmd.Docs = append(cmd.Docs, ConfigDocWrite{
			Kind: d.Kind, Name: d.Name, Content: d.Content, Digest: ConfigDigest(d.Content),
		})
	}
	if _, err := r.s.apply(ctx, cmd); err != nil {
		return fmt.Errorf("write config documents: %w", err)
	}
	return nil
}

// Delete deletes the document kind/name, leaving a tombstone, or fails with
// ErrNotFound. Policy and notify documents are not deleted: import an empty
// file instead.
func (r ConfigDocs) Delete(ctx context.Context, kind, name string) error {
	if err := r.requireSchema(ctx); err != nil {
		return fmt.Errorf("delete config document: %w", err)
	}
	if _, err := r.s.apply(ctx, DeleteConfigDoc{Kind: kind, Name: name}); err != nil {
		return fmt.Errorf("delete config document %s: %w", ConfigDocID(kind, name), err)
	}
	return nil
}

// ErrConfigDoc refuses a document the store does not hold: an unknown
// kind, or a delete of a policy or notify document.
var ErrConfigDoc = errors.New("invalid config document")

// ConfigDocWrite is one document of PutConfigDocs.
type ConfigDocWrite struct {
	Kind    string `json:"kind"`
	Name    string `json:"name"`
	Content []byte `json:"content"`
	Digest  string `json:"digest"`
}

// PutConfigDocs writes configuration documents, all in one transaction.
// With IfNone it is refused with ErrExists when any document is stored.
type PutConfigDocs struct {
	Stamp
	Docs   []ConfigDocWrite `json:"docs"`
	IfNone bool             `json:"if_none,omitempty"`
	By     string           `json:"by"`
	Now    int64            `json:"now"`
}

// Op implements Command.
func (PutConfigDocs) Op() string { return "put_config_docs" }

func (PutConfigDocs) minSchema() int64 { return configDocsSchema }

func (c PutConfigDocs) apply(ctx context.Context, w *writer) (Result, error) {
	if c.IfNone {
		live, err := w.query(ctx, "config_docs", `1 = 1`, "")
		if err != nil {
			return Result{}, err
		}
		if len(live) > 0 {
			return Result{}, fmt.Errorf("config documents: %w", ErrExists)
		}
	}
	for _, d := range c.Docs {
		if !slices.Contains(ConfigKinds, d.Kind) || d.Name == "" {
			return Result{}, fmt.Errorf("%w: %q/%q", ErrConfigDoc, d.Kind, d.Name)
		}
		id := ConfigDocID(d.Kind, d.Name)
		r, err := w.get(ctx, "config_docs", id)
		if err != nil {
			return Result{}, err
		}
		if r == nil {
			r = row{"id": id, "kind": d.Kind, "name": d.Name}
		}
		r["content"], r["digest"], r["updated_at"], r["updated_by"] = d.Content, d.Digest, c.Now, c.By
		if err := w.put(ctx, "config_docs", r); err != nil {
			return Result{}, err
		}
	}
	return Result{Count: len(c.Docs)}, nil
}

// DeleteConfigDoc deletes an automation or runbook document.
type DeleteConfigDoc struct {
	Stamp
	Kind string `json:"kind"`
	Name string `json:"name"`
}

// Op implements Command.
func (DeleteConfigDoc) Op() string { return "delete_config_doc" }

func (DeleteConfigDoc) minSchema() int64 { return configDocsSchema }

func (c DeleteConfigDoc) apply(ctx context.Context, w *writer) (Result, error) {
	if c.Kind != ConfigAutomation && c.Kind != ConfigRunbook {
		return Result{}, fmt.Errorf("%w: only automation and runbook documents are deleted, not %q", ErrConfigDoc, c.Kind)
	}
	return deleteRow(ctx, w, "config_docs", ConfigDocID(c.Kind, c.Name))
}
