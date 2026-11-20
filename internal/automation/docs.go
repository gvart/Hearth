// SPDX-License-Identifier: AGPL-3.0-only

package automation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
)

// Doc is one automation or runbook file as a document of the hub's store:
// its file name and content.
type Doc struct {
	Name    string
	Content []byte
}

// DocSource lists the documents of one kind, as they are now.
type DocSource interface {
	Docs(ctx context.Context) ([]Doc, error)
}

// DocStore is a DocSource that also saves documents: the hub's store.
type DocStore interface {
	DocSource
	Put(ctx context.Context, name string, content []byte) error
}

// docNamePattern is what a document name looks like: the name of a file the
// hub would load, that export can write into a directory.
var docNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}\.(yaml|yml)$`)

// ValidDocName reports whether name can name an automation or runbook
// document: a .yaml or .yml file name without a path or a leading dot.
func ValidDocName(name string) bool { return docNamePattern.MatchString(name) }

// LoadDocs is LoadDir for documents: any invalid document, or two with the
// same automation id, fails the whole load.
func LoadDocs(docs []Doc, kinds Kinds) ([]*Automation, error) {
	var (
		out  []*Automation
		errs []error
		ids  = map[string]string{}
	)
	for _, d := range docs {
		a, err := Parse(d.Name, d.Content, kinds)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if prev, ok := ids[a.ID]; ok {
			errs = append(errs, fmt.Errorf("%s: automation id %q is already used by %s", d.Name, a.ID, prev))
			continue
		}
		ids[a.ID] = d.Name
		out = append(out, a)
	}
	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return out, nil
}

// LoadRunbookDocs is LoadRunbooks for documents.
func LoadRunbookDocs(docs []Doc, kinds Kinds) ([]*Runbook, []error) {
	var (
		out  []*Runbook
		errs []error
		ids  = map[string]string{}
	)
	for _, d := range docs {
		rb, err := ParseRunbook(d.Name, d.Content, kinds)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if prev, ok := ids[rb.ID]; ok {
			errs = append(errs, fmt.Errorf("%s: runbook id %q is already used by %s", d.Name, rb.ID, prev))
			continue
		}
		ids[rb.ID] = d.Name
		out = append(out, rb)
	}
	return out, errs
}

// ReadDirDocs reads the files the hub would load from dir (*.yaml and
// *.yml, not hidden, not in subdirectories) as documents, by file name. A
// missing dir has none.
func ReadDirDocs(dir string) ([]Doc, error) {
	paths, err := automationFiles(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Doc, 0, len(paths))
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", filepath.Base(p), err)
		}
		out = append(out, Doc{Name: filepath.Base(p), Content: b})
	}
	return out, nil
}

// docsFingerprint changes whenever a document is added, removed or changed.
func docsFingerprint(docs []Doc) string {
	h := sha256.New()
	for _, d := range docs {
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", d.Name, len(d.Content))
		_, _ = h.Write(d.Content)
	}
	return hex.EncodeToString(h.Sum(nil))
}
