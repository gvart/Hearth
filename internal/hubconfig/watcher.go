// SPDX-License-Identifier: AGPL-3.0-only

package hubconfig

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/notify"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// DefaultEvery is how often a hub checks its documents for changes: a
// write on this hub, by `hearth config import` in another process, or
// replicated from another hub.
const DefaultEvery = 2 * time.Second

// Files are a hub's configuration files: in effect until the store holds
// documents, and imported into an empty store once.
type Files struct {
	Policy, Notify, AutomationsDir, RunbooksDir string
}

// Read reads the files as documents. The policy document is always there,
// empty for a missing file: it marks the store as imported.
func (f Files) Read() ([]Doc, error) {
	docs, err := ReadDir(f.Policy, f.Notify, f.AutomationsDir, f.RunbooksDir)
	if err != nil {
		return nil, err
	}
	for _, d := range docs {
		if d.Kind == store.ConfigPolicy {
			return docs, nil
		}
	}
	return Overlay(docs, []Doc{{Kind: store.ConfigPolicy, Name: PolicyFile, Content: []byte{}}}), nil
}

// WatcherConfig holds a Watcher's dependencies.
type WatcherConfig struct {
	Store  Store
	Sealer Sealer
	// Policy and Notifier are the hub's, changed in place.
	Policy   *policy.Engine
	Notifier *notify.Notifier
	// HostDangerous are --allow-dangerous-automation: the host's grants,
	// added to every policy applied.
	HostDangerous []string
	Files         Files
	// Actor is this hub as the actor of its first import: its node id.
	Actor string
	// Every is how often Run checks; default DefaultEvery.
	Every time.Duration
	Log   *slog.Logger
	Now   func() time.Time
}

// Watcher applies the store's documents to the hub: the policy engine's
// configuration and the notification channels are replaced, and the
// automations runtime reads Automations. A configuration whose policy or
// notify document is invalid is not applied at all: the hub keeps running
// the one before.
type Watcher struct {
	cfg WatcherConfig

	mu   sync.Mutex
	last string
	// automations are the automation documents applied; nil until the
	// store's documents are, while the files are in effect.
	automations atomic.Pointer[[]automation.Doc]
	// filesNoted is set once the hub said its files are not read any more.
	filesNoted bool
}

// NewWatcher returns a Watcher. Sync or Run applies the documents.
func NewWatcher(cfg WatcherConfig) *Watcher {
	if cfg.Every <= 0 {
		cfg.Every = DefaultEvery
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Watcher{cfg: cfg}
}

// ImportFirst imports the hub's files into the store if it holds no
// document yet, through policy (config.import.first) and audited. Of two
// hubs importing at once, the first wins: the other's import is refused and
// it applies the winner's documents. When the store holds documents
// already and the hub has files, it says once that they are not read.
func (w *Watcher) ImportFirst(ctx context.Context) error {
	if ok, err := w.cfg.Store.Available(ctx); err != nil || !ok {
		return err
	}
	stored, err := w.cfg.Store.List(ctx, "")
	if err != nil {
		return err
	}
	if len(stored) > 0 {
		w.noteFiles(ctx)
		return nil
	}
	docs, err := w.cfg.Files.Read()
	if err != nil {
		return fmt.Errorf("import the configuration files: %w", err)
	}
	sealed, err := Seal(docs, w.cfg.Sealer)
	if err != nil {
		return fmt.Errorf("import the configuration files: %w", err)
	}
	names := make([]string, 0, len(docs))
	for _, d := range docs {
		names = append(names, d.ID())
	}
	req := policy.Request{
		ActorKind: policy.ActorHub, ActorID: w.cfg.Actor, Action: policy.ConfigImportFirst,
		Detail: map[string]any{"documents": names},
	}
	err = w.cfg.Policy.Do(ctx, req, func(ctx context.Context) error {
		return w.cfg.Store.ImportFirst(ctx, policy.ActorHub+"/"+w.cfg.Actor, sealed, w.cfg.Now())
	})
	switch {
	case errors.Is(err, store.ErrExists):
		w.cfg.Log.InfoContext(ctx, "another hub imported its configuration files first: using those")
		return nil
	case err != nil:
		return fmt.Errorf("import the configuration files: %w", err)
	}
	w.cfg.Log.InfoContext(ctx, "configuration files imported into the store; from now on they are import/export only "+
		"(hearth config import|export)", "documents", names)
	w.mu.Lock()
	w.filesNoted = true
	w.mu.Unlock()
	return nil
}

// noteFiles logs once that the hub's files are not read any more.
func (w *Watcher) noteFiles(ctx context.Context) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.filesNoted {
		return
	}
	w.filesNoted = true
	if docs, err := ReadDir(w.cfg.Files.Policy, w.cfg.Files.Notify, w.cfg.Files.AutomationsDir, w.cfg.Files.RunbooksDir); err == nil && len(docs) > 0 {
		w.cfg.Log.InfoContext(ctx, "the store holds the configuration: policy.yaml, notify.yaml and the automations "+
			"and runbooks directories on this host are import/export only now (hearth config import|export)")
	}
}

// Sync applies the store's documents if they changed since the last Sync,
// and reports whether the store's documents are in effect. Below schema 28,
// or while the store holds no document, the files stay in effect. A
// configuration that does not parse is not applied, and Sync returns why.
func (w *Watcher) Sync(ctx context.Context) (bool, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ok, err := w.cfg.Store.Available(ctx); err != nil || !ok {
		return false, err
	}
	fp, err := w.cfg.Store.Fingerprint(ctx)
	if err != nil {
		return w.applied(), err
	}
	if fp == w.last {
		return w.applied(), nil
	}
	docs, err := Load(ctx, w.cfg.Store, w.cfg.Sealer)
	if err != nil {
		return w.applied(), err
	}
	if len(docs) == 0 {
		w.last = fp
		return false, nil
	}
	set, err := Parse(docs)
	if err != nil {
		// Not again until the documents change.
		w.last = fp
		return w.applied(), fmt.Errorf("the stored configuration is invalid, keeping the one in effect: %w", err)
	}
	w.last = fp
	set.Policy.DangerousAutomations = append(set.Policy.DangerousAutomations, w.cfg.HostDangerous...)
	w.cfg.Notifier.Replace(set.Notifier)
	w.cfg.Policy.SetConfig(set.Policy)
	automations := set.Automations
	if automations == nil {
		automations = []automation.Doc{}
	}
	w.automations.Store(&automations)
	channels := []string{}
	for _, c := range set.Notifier.Channels() {
		channels = append(channels, c.Name)
	}
	w.cfg.Log.InfoContext(ctx, "configuration applied", "automations", len(set.Automations),
		"runbooks", len(set.Runbooks), "channels", channels)
	return true, nil
}

func (w *Watcher) applied() bool { return w.automations.Load() != nil }

// Run syncs every Every until ctx is done, logging what cannot be applied.
func (w *Watcher) Run(ctx context.Context) error {
	tick := time.NewTicker(w.cfg.Every)
	defer tick.Stop()
	for {
		if _, err := w.Sync(ctx); err != nil && ctx.Err() == nil {
			w.cfg.Log.ErrorContext(ctx, "configuration not applied", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
}

// Automations are the automations the runtime runs: the documents last
// applied, or the files while those are in effect.
func (w *Watcher) Automations() automation.DocSource { return appliedAutomations{w} }

type appliedAutomations struct{ w *Watcher }

func (a appliedAutomations) Docs(context.Context) ([]automation.Doc, error) {
	if docs := a.w.automations.Load(); docs != nil {
		return *docs, nil
	}
	return automation.ReadDirDocs(a.w.cfg.Files.AutomationsDir)
}

// StoreDocs are the documents of kind (automation or runbook) as the store
// holds them now, for the editors and the runbook engine; the files of dir
// while the store holds no document at all. Put writes one document,
// recorded as written by by.
func StoreDocs(st Store, kind, dir, by string, now func() time.Time) automation.DocStore {
	return storeDocs{st: st, kind: kind, dir: dir, by: by, now: now}
}

type storeDocs struct {
	st        Store
	kind, dir string
	by        string
	now       func() time.Time
}

func (s storeDocs) Docs(ctx context.Context) ([]automation.Doc, error) {
	all, err := s.st.List(ctx, "")
	if err != nil {
		return nil, err
	}
	if len(all) == 0 {
		return automation.ReadDirDocs(s.dir)
	}
	out := []automation.Doc{}
	for _, d := range all {
		if d.Kind == s.kind {
			out = append(out, automation.Doc{Name: d.Name, Content: d.Content})
		}
	}
	return out, nil
}

func (s storeDocs) Put(ctx context.Context, name string, content []byte) error {
	if err := CheckName(s.kind, name); err != nil {
		return err
	}
	return s.st.Put(ctx, s.by, []store.ConfigDoc{{Kind: s.kind, Name: name, Content: content}}, s.now())
}
