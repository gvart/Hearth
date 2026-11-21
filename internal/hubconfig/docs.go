// SPDX-License-Identifier: AGPL-3.0-only

// Package hubconfig holds the hub's configuration as documents of the store
// (docs/design/ap-cluster.md §7): policy.yaml, notify.yaml, each automation
// file and each runbook file. Every hub applies the documents it holds, and
// reapplies them when they change, whichever hub wrote them. Files on disk
// are import and export only, apart from a hub's one-time import of its own
// files into an empty store.
package hubconfig

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// File and directory names, in a hub's data dir and in an export.
const (
	PolicyFile     = policy.ConfigFile
	NotifyFile     = "notify.yaml"
	AutomationsDir = "automations"
	RunbooksDir    = "runbooks"
)

// Store is where the documents are: store.ConfigDocs.
type Store interface {
	Available(ctx context.Context) (bool, error)
	List(ctx context.Context, kind string) ([]store.ConfigDoc, error)
	Fingerprint(ctx context.Context) (string, error)
	Put(ctx context.Context, by string, docs []store.ConfigDoc, now time.Time) error
	ImportFirst(ctx context.Context, by string, docs []store.ConfigDoc, now time.Time) error
	Delete(ctx context.Context, kind, name string) error
}

// Sealer seals the notify document, which holds credentials, with a key
// derived from the hub CA key (see cmd/hearth's hubSealers).
type Sealer interface {
	Seal(id string, plaintext []byte) ([]byte, error)
	Open(id string, sealed []byte) ([]byte, error)
}

// SealID is the id a notify document named name is sealed for: a sealed
// document moved to another row fails to open.
func SealID(name string) string { return SealIDOfRow(store.ConfigDocID(store.ConfigNotify, name)) }

// SealIDOfRow is SealID for the document whose row id (kind/name) is id.
func SealIDOfRow(id string) string { return "config-doc/" + id }

// Doc is one document in clear.
type Doc struct {
	Kind    string
	Name    string
	Content []byte
}

// ID is the document's kind/name.
func (d Doc) ID() string { return store.ConfigDocID(d.Kind, d.Name) }

// fixedName is the one name of a policy or notify document.
var fixedName = map[string]string{store.ConfigPolicy: PolicyFile, store.ConfigNotify: NotifyFile}

// CheckName refuses a document name that could not be a file of an export:
// policy and notify have one name each, automations and runbooks are .yaml
// or .yml file names without a path.
func CheckName(kind, name string) error {
	if fixed, ok := fixedName[kind]; ok {
		if name != fixed {
			return fmt.Errorf("a %s document is named %s, not %q", kind, fixed, name)
		}
		return nil
	}
	if kind != store.ConfigAutomation && kind != store.ConfigRunbook {
		return fmt.Errorf("unknown document kind %q (want policy, notify, automation or runbook)", kind)
	}
	if !automation.ValidDocName(name) {
		return fmt.Errorf("%s %q: a name is a .yaml or .yml file name, without a path or a leading dot", kind, name)
	}
	return nil
}

// Load reads every document of st, the notify document opened with sealer.
func Load(ctx context.Context, st Store, sealer Sealer) ([]Doc, error) {
	stored, err := st.List(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make([]Doc, 0, len(stored))
	for _, d := range stored {
		content := d.Content
		if d.Kind == store.ConfigNotify {
			if content, err = sealer.Open(SealID(d.Name), d.Content); err != nil {
				return nil, fmt.Errorf("open the stored %s: %w", d.Name, err)
			}
		}
		out = append(out, Doc{Kind: d.Kind, Name: d.Name, Content: content})
	}
	return out, nil
}

// Seal returns docs as the store keeps them: the notify document sealed.
func Seal(docs []Doc, sealer Sealer) ([]store.ConfigDoc, error) {
	out := make([]store.ConfigDoc, 0, len(docs))
	for _, d := range docs {
		content := d.Content
		if d.Kind == store.ConfigNotify {
			var err error
			if content, err = sealer.Seal(SealID(d.Name), d.Content); err != nil {
				return nil, fmt.Errorf("seal %s: %w", d.Name, err)
			}
		}
		if content == nil {
			content = []byte{}
		}
		out = append(out, store.ConfigDoc{Kind: d.Kind, Name: d.Name, Content: content})
	}
	return out, nil
}

// Overlay returns current with every document of incoming added or
// replacing the one of the same kind and name, sorted by kind and name.
func Overlay(current, incoming []Doc) []Doc {
	byID := map[string]Doc{}
	for _, d := range current {
		byID[d.ID()] = d
	}
	for _, d := range incoming {
		byID[d.ID()] = d
	}
	out := make([]Doc, 0, len(byID))
	for _, d := range byID {
		out = append(out, d)
	}
	slices.SortFunc(out, func(a, b Doc) int { return strings.Compare(a.ID(), b.ID()) })
	return out
}

// Set is a whole configuration, as a hub runs it.
type Set struct {
	Policy   policy.Config
	Notifier *notify.Notifier
	// Automations and Runbooks are their documents, by name.
	Automations []automation.Doc
	Runbooks    []automation.Doc
}

// Parse reads docs into a Set. The policy and notify documents must be
// valid, and the policy's approval channel one of notify's; automations
// and runbooks are only sorted out, their own loaders judge them. No error
// quotes a notify value: they are credentials.
func Parse(docs []Doc) (Set, error) {
	set := Set{Notifier: &notify.Notifier{}}
	var errs []error
	for _, d := range docs {
		switch d.Kind {
		case store.ConfigPolicy:
			cfg, err := policy.ParseConfig(d.Content)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", d.Name, err))
			}
			set.Policy = cfg
		case store.ConfigNotify:
			n, err := notify.Parse(d.Content)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", d.Name, err))
				continue
			}
			set.Notifier = n
		case store.ConfigAutomation:
			set.Automations = append(set.Automations, automation.Doc{Name: d.Name, Content: d.Content})
		case store.ConfigRunbook:
			set.Runbooks = append(set.Runbooks, automation.Doc{Name: d.Name, Content: d.Content})
		default:
			errs = append(errs, fmt.Errorf("unknown document kind %q", d.Kind))
		}
	}
	if ch := set.Policy.ApprovalNotify.Channel; len(errs) == 0 && ch != "" && !set.Notifier.Has(ch) {
		errs = append(errs, fmt.Errorf("%s: approval_notify.channel %q is not a channel of %s", PolicyFile, ch, NotifyFile))
	}
	return set, errors.Join(errs...)
}

// Validate checks docs, the whole configuration an import would leave, as
// the hub would load it: Parse, then every automation and runbook with the
// step types kinds returns for the configuration's notification channels.
func Validate(docs []Doc, kinds func(*notify.Notifier) automation.Kinds) error {
	for _, d := range docs {
		if err := CheckName(d.Kind, d.Name); err != nil {
			return err
		}
	}
	set, err := Parse(docs)
	if err != nil {
		return err
	}
	var errs []error
	k := kinds(set.Notifier)
	if _, err := automation.LoadDocs(set.Automations, k); err != nil {
		errs = append(errs, err)
	}
	if _, rbErrs := automation.LoadRunbookDocs(set.Runbooks, k); len(rbErrs) > 0 {
		errs = append(errs, rbErrs...)
	}
	return errors.Join(errs...)
}

// CheckLockout refuses a policy document of incoming that would deny the
// operator config.import: the only way to change the policy back.
func CheckLockout(incoming []Doc) error {
	for _, d := range incomingPolicy(incoming) {
		cfg, err := policy.ParseConfig(d.Content)
		if err != nil {
			return fmt.Errorf("%s: %w", d.Name, err)
		}
		req := policy.Request{ActorKind: policy.ActorAdmin, ActorID: "operator", Action: policy.ConfigImport}
		if decision, _ := policy.NewWithConfig(nil, nil, cfg).Check(req); decision == policy.Deny {
			return fmt.Errorf("%s: it denies config.import to the operator, so it could never be changed again: "+
				"hold dangerous actions for approval (confirm) instead", d.Name)
		}
	}
	return nil
}

// CheckWebLockout is CheckLockout for a policy written from the web UI's
// policy editor: it also refuses one that would deny config.import to the
// web UI's admin, who could then never change the policy back from there.
func CheckWebLockout(incoming []Doc) error {
	if err := CheckLockout(incoming); err != nil {
		return err
	}
	for _, d := range incomingPolicy(incoming) {
		cfg, err := policy.ParseConfig(d.Content)
		if err != nil {
			return fmt.Errorf("%s: %w", d.Name, err)
		}
		req := policy.Request{ActorKind: policy.ActorWeb, ActorID: "web", Action: policy.ConfigImport}
		if decision, _ := policy.NewWithConfig(nil, nil, cfg).Check(req); decision == policy.Deny {
			return fmt.Errorf("%s: it denies config.import to the web UI, so the policy editor could never change it back: "+
				"hold dangerous actions for approval (confirm) instead, or change it with `hearth config import` on a hub host",
				d.Name)
		}
	}
	return nil
}

func incomingPolicy(docs []Doc) []Doc {
	var out []Doc
	for _, d := range docs {
		if d.Kind == store.ConfigPolicy {
			out = append(out, d)
		}
	}
	return out
}

// ReadPath reads documents to import from path: a directory laid out like a
// hub's data dir or an export (policy.yaml, notify.yaml, automations/,
// runbooks/), or one file. A file's kind is kind, or else what its name
// says: policy.yaml, notify.yaml, or a file of an automations or runbooks
// directory.
func ReadPath(path, kind string) ([]Doc, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		if kind != "" {
			return nil, errors.New("--kind is for one file, not a directory")
		}
		return ReadDir(filepath.Join(path, PolicyFile), filepath.Join(path, NotifyFile),
			filepath.Join(path, AutomationsDir), filepath.Join(path, RunbooksDir))
	}
	base := filepath.Base(path)
	if kind == "" {
		switch {
		case base == PolicyFile:
			kind = store.ConfigPolicy
		case base == NotifyFile:
			kind = store.ConfigNotify
		case filepath.Base(filepath.Dir(path)) == AutomationsDir:
			kind = store.ConfigAutomation
		case filepath.Base(filepath.Dir(path)) == RunbooksDir:
			kind = store.ConfigRunbook
		default:
			return nil, fmt.Errorf("cannot tell what %s is: give --kind policy, notify, automation or runbook", base)
		}
	}
	name := base
	if fixed, ok := fixedName[kind]; ok {
		name = fixed
	}
	if err := CheckName(kind, name); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return []Doc{{Kind: kind, Name: name, Content: b}}, nil
}

// ReadDir reads a hub's configuration files: the policy file at policyPath,
// the notify file at notifyPath and the automations and runbooks directories. A
// missing file or directory has no documents.
func ReadDir(policyPath, notifyPath, automationsDir, runbooksDir string) ([]Doc, error) {
	var out []Doc
	for kind, path := range map[string]string{
		store.ConfigPolicy: policyPath, store.ConfigNotify: notifyPath,
	} {
		b, err := os.ReadFile(path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Doc{Kind: kind, Name: fixedName[kind], Content: b})
	}
	for kind, d := range map[string]string{store.ConfigAutomation: automationsDir, store.ConfigRunbook: runbooksDir} {
		docs, err := automation.ReadDirDocs(d)
		if err != nil {
			return nil, err
		}
		for _, doc := range docs {
			if err := CheckName(kind, doc.Name); err != nil {
				return nil, err
			}
			out = append(out, Doc{Kind: kind, Name: doc.Name, Content: doc.Content})
		}
	}
	return Overlay(nil, out), nil
}

// WriteDir writes docs into dir in the layout ReadPath reads, every file
// readable by its owner only (notify.yaml holds credentials), each written
// whole or not at all. It refuses a name that is not a plain file name.
func WriteDir(dir string, docs []Doc) error {
	for _, d := range docs {
		if err := CheckName(d.Kind, d.Name); err != nil {
			return err
		}
	}
	for _, d := range docs {
		target := dir
		switch d.Kind {
		case store.ConfigAutomation:
			target = filepath.Join(dir, AutomationsDir)
		case store.ConfigRunbook:
			target = filepath.Join(dir, RunbooksDir)
		}
		if err := os.MkdirAll(target, 0o700); err != nil {
			return err
		}
		if err := writeFile(target, d.Name, d.Content); err != nil {
			return fmt.Errorf("write %s: %w", d.ID(), err)
		}
	}
	return nil
}

// writeFile writes b to dir/name, mode 0600, in one step.
func writeFile(dir, name string, b []byte) error {
	tmp, err := os.CreateTemp(dir, ".export-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, name))
}
