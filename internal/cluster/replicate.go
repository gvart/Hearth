// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gvart/hearth/internal/hlc"
	"github.com/gvart/hearth/internal/store"
)

// Replication of a sharded (AP) cluster (docs/design/ap-cluster.md §5).
//
// The Replicator is the store's Applier and its Shards. A write runs on one
// replica of the rows it touches (the coordinator): the command is applied
// to that member's database, and the row mutations it made are sent to the
// other replicas, which merge them last-writer-wins. Placement is sloppy:
// a write meant for a replica that is down goes to the next live member of
// the preference list instead, and the coordinator keeps a hint (hints.go)
// that delivers it to the replica once it is back. Critical writes wait for
// W = min(2, N) replicas, and fail fast with store.ErrUnavailable when fewer
// are live; every other write waits for the coordinator alone and is copied
// in the background.
//
// Members talk over the gossip port's mutual TLS (gossipReplica
// connections, one request after another, each a length-prefixed JSON
// frame), so replication is authenticated like gossip: a peer must present
// the hub node certificate of a current storage member. No CA key material
// is ever sent.

// APPeers is the cluster as the replicator reaches it.
type APPeers interface {
	// Members lists the members, this one included.
	Members() []MemberInfo
	// DialReplica opens a replication connection to a live member.
	DialReplica(ctx context.Context, id string) (net.Conn, error)
}

// ReplicatorConfig configures a Replicator.
type ReplicatorConfig struct {
	// NodeID is this member's id: the origin of the writes it stamps.
	NodeID string
	Peers  APPeers
	// Replicas is N, the copies of each row; zero means min(2, storage
	// members). It is never more than the storage members.
	Replicas int
	// Hints keeps the writes for replicas that are down; nil keeps none.
	Hints *Hints
	// LastContact is the file that records when this member last reached
	// the cluster (see CheckRejoin); empty records nothing.
	LastContact string
	// Broadcast, if set, sends a message to every member on the gossip
	// (Membership.Broadcast): revocations are announced with it.
	Broadcast func([]byte)
	Log       *slog.Logger

	// Tuning; zero values use the defaults.
	RequestTimeout time.Duration
	// QuickTimeout bounds the requests a client waits on: a read, and a
	// replica's acknowledgement of a critical write. A member that does not
	// answer in time is taken as down for SuspectFor.
	QuickTimeout     time.Duration
	SuspectFor       time.Duration
	AntiEntropyEvery time.Duration
	HintsEvery       time.Duration
	GCEvery          time.Duration
	Now              func() time.Time
	// OnSynced, if set, is called once a member promoted to storage has
	// copied the rows of every bucket it owns (see SetLocal).
	OnSynced func()
}

const (
	defaultRequestTimeout   = 10 * time.Second
	defaultQuickTimeout     = 1500 * time.Millisecond
	defaultSuspectFor       = 5 * time.Second
	defaultAntiEntropyEvery = 30 * time.Second
	defaultHintsEvery       = 5 * time.Second
	defaultGCEvery          = time.Hour
	// replicaIdle closes a served replication connection after this long
	// without a request.
	replicaIdle = 2 * time.Minute
	// maxFrame bounds one request or response.
	maxFrame = 64 << 20
	// poolSize is how many idle connections are kept per member.
	poolSize = 4
	// asyncQueue is how many background jobs may wait.
	asyncQueue = 4096
)

// Replicator coordinates the writes and reads of a sharded cluster.
type Replicator struct {
	cfg ReplicatorConfig
	log *slog.Logger
	st  atomic.Pointer[store.Store]

	poolMu sync.Mutex
	pool   map[string][]net.Conn

	ringMu  sync.Mutex
	ringKey string
	ring    *Ring

	jobs chan func(context.Context)
	// ctx is Run's, for the requests served; background before Run.
	ctx atomic.Pointer[context.Context]

	contactMu   sync.Mutex
	contactSeen time.Time

	// suspect holds the members a request just failed to reach, until when
	// they count as down whatever the gossip says: a member that died a
	// moment ago, or behind a cut link, costs one timeout, not one per
	// request until the gossip notices.
	suspectMu sync.Mutex
	suspect   map[string]time.Time

	// handed is the digest of each bucket this member does not own when
	// its rows were last handed off to the owners (see handOff).
	handedMu sync.Mutex
	handed   map[int]uint64

	// synced names, for each peer whose last anti-entropy round succeeded,
	// the ring it ran on (safestop.go).
	syncedMu sync.Mutex
	synced   map[string]string

	// uses are the master-owned rows this member used (owned.go).
	uses *ownedUses

	// local is this member's own part in the storage ring (SetLocal).
	local atomic.Pointer[replicaLocal]
	// catchUpMu runs one CatchUp at a time.
	catchUpMu sync.Mutex
	// seeking is set while this member, told of a cluster to join, has not
	// found another member yet (SetSeeking): its ring is itself alone, so a
	// critical write would be acknowledged with its one copy.
	seeking atomic.Bool
	// alone is set while this member, told of a cluster, started without
	// finding it (StartAlone) and has not found it since: its ring is only
	// itself, so it is no majority of anything (#307).
	alone atomic.Bool
	// aeRounds counts the anti-entropy rounds run (tests wait on it).
	aeRounds atomic.Int64
}

// replicaLocal is whether this member is a storage member, and whether it
// is still catching up after its promotion.
type replicaLocal struct {
	storage, syncing bool
}

// NewReplicator returns a Replicator; bind it to the store with Bind (or
// open the store with store.WithShards and store.WithApplier) and run it
// with Run.
func NewReplicator(cfg ReplicatorConfig) (*Replicator, error) {
	if err := ValidNodeID(cfg.NodeID); err != nil {
		return nil, err
	}
	if cfg.Peers == nil {
		return nil, errors.New("replicator: no peers")
	}
	if cfg.Replicas < 0 {
		return nil, errors.New("replicator: replicas must be at least 1")
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	setIfZero(&cfg.RequestTimeout, defaultRequestTimeout)
	setIfZero(&cfg.QuickTimeout, defaultQuickTimeout)
	setIfZero(&cfg.SuspectFor, defaultSuspectFor)
	setIfZero(&cfg.AntiEntropyEvery, defaultAntiEntropyEvery)
	setIfZero(&cfg.HintsEvery, defaultHintsEvery)
	setIfZero(&cfg.GCEvery, defaultGCEvery)
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	uses, err := newOwnedUses(context.Background(), cfg.Hints)
	if err != nil {
		return nil, err
	}
	r := &Replicator{
		cfg: cfg, log: cfg.Log.With("component", "replication"),
		pool: map[string][]net.Conn{}, jobs: make(chan func(context.Context), asyncQueue),
		suspect: map[string]time.Time{}, handed: map[int]uint64{}, uses: uses,
	}
	bg := context.Background()
	r.ctx.Store(&bg)
	r.local.Store(&replicaLocal{storage: true})
	return r, nil
}

// SetLocal sets this member's part in the storage ring: storage puts it on
// the ring; syncing, after a promotion, keeps reads off it until it has
// copied the rows of its buckets from the others (OnSynced). A member that
// is not storage still holds the global rows.
func (r *Replicator) SetLocal(storage, syncing bool) {
	r.local.Store(&replicaLocal{storage: storage, syncing: storage && syncing})
}

// SetSeeking sets whether this member is still looking for the cluster it
// was told to join. Until it finds another member (the view notices), or
// SetSeeking(false) says it starts alone, critical writes fail fast with
// store.ErrUnavailable and write nothing.
func (r *Replicator) SetSeeking(seeking bool) { r.seeking.Store(seeking) }

// StartAlone lets this member, which did not find the cluster it was told
// to join, take critical writes alone. It still refuses the writes that need
// a majority of their replicas (runbook runs) until it finds another member:
// on a ring of itself it cannot know it is not the minority of a split.
func (r *Replicator) StartAlone() {
	r.alone.Store(true)
	r.seeking.Store(false)
}

// Syncing reports whether this member is still catching up after its
// promotion to storage.
func (r *Replicator) Syncing() bool { return r.local.Load().syncing }

func setIfZero[T comparable](dst *T, v T) {
	var zero T
	if *dst == zero {
		*dst = v
	}
}

// Bind records the store the replicator writes to and returns it as the
// store's Applier: pass it to store.WithApplier.
func (r *Replicator) Bind(s *store.Store) store.Applier {
	r.st.Store(s)
	return r
}

func (r *Replicator) store() *store.Store { return r.st.Load() }

// view is the ring and liveness of the moment.
type view struct {
	self string
	ring *Ring
	live map[string]bool
	n    int
	// everyone are the members holding the global rows: the storage
	// members and the masters, live or not.
	everyone []string
	// syncing are the storage members still catching up after their
	// promotion: on the ring for writes, last for reads.
	syncing map[string]bool
}

// view returns the current view: the ring over the storage members not
// gone for good (dead ones stay on it, so a crash moves no data), and the
// members reachable now.
func (r *Replicator) view() view {
	members := r.cfg.Peers.Members()
	local := r.local.Load()
	var ids []string
	everyone := []string{r.cfg.NodeID}
	live := map[string]bool{r.cfg.NodeID: true}
	syncing := map[string]bool{}
	if local.storage {
		ids = append(ids, r.cfg.NodeID)
		if local.syncing {
			syncing[r.cfg.NodeID] = true
		}
	}
	for _, m := range members {
		if m.ID == r.cfg.NodeID || !m.Roles.Gossips() || m.State == MemberLeft {
			continue
		}
		everyone = append(everyone, m.ID)
		if m.State == MemberAlive || m.State == MemberSuspect {
			// The gossip found the cluster: the ring is not this member
			// alone any more.
			r.seeking.Store(false)
			r.alone.Store(false)
			if !r.suspected(m.ID) {
				live[m.ID] = true
			}
		}
		if m.Roles.Has(RoleStorage) {
			ids = append(ids, m.ID)
			if m.Syncing {
				syncing[m.ID] = true
			}
		}
	}
	slices.Sort(everyone)
	everyone = slices.Compact(everyone)
	slices.Sort(ids)
	ids = slices.Compact(ids)
	key := strings.Join(ids, ",")
	r.ringMu.Lock()
	if key != r.ringKey || r.ring == nil {
		r.ring, r.ringKey = NewRing(ids), key
		r.forgetSynced()
	}
	ring := r.ring
	r.ringMu.Unlock()
	n := r.cfg.Replicas
	if n == 0 {
		n = 2
	}
	n = max(1, min(n, ring.Size()))
	return view{self: r.cfg.NodeID, ring: ring, live: live, n: n, everyone: everyone, syncing: syncing}
}

// N is the replication factor in effect.
func (r *Replicator) N() int { return r.view().n }

// targets returns where a write of bucket goes: the live members among the
// first N of its preference list, filled up to N with the next live ones
// (stand-ins for replicas that are down), and the replicas that are down.
func (v view) targets(bucket int) (live, down []string) {
	pref := v.ring.Preference(bucket)
	for i, m := range pref {
		switch {
		case i < v.n && v.live[m]:
			live = append(live, m)
		case i < v.n:
			down = append(down, m)
		case len(live) < v.n && v.live[m]:
			live = append(live, m)
		}
	}
	return live, down
}

// owners returns the replicas of bucket, live and down: the first N of its
// preference list, never a stand-in.
func (v view) owners(bucket int) (live, down []string) {
	return v.split(v.ring.Owners(bucket, v.n))
}

// all returns every storage member, live and down: where a command that
// runs on every shard runs.
func (v view) all() (live, down []string) {
	return v.split(v.ring.Members())
}

// globals returns every member holding the global rows, live and down:
// the storage members and the masters, which read them locally.
func (v view) globals() (live, down []string) {
	return v.split(v.everyone)
}

func (v view) split(ms []string) (live, down []string) {
	for _, m := range ms {
		if v.live[m] {
			live = append(live, m)
		} else {
			down = append(down, m)
		}
	}
	return live, down
}

// placementTargets returns the targets of a row placed at p.
func (v view) placementTargets(p store.Placement) (live, down []string) {
	if p.Global {
		return v.globals()
	}
	return v.targets(store.BucketOf(store.Token(p.Key)))
}

// writeQuorum is W for a write to replicas targets: min(2, N) for a
// critical one, else 1.
func writeQuorum(critical bool, n int) int {
	if critical {
		return min(2, n)
	}
	return 1
}

// majority is W for a write that needs a strict majority of its n replicas
// (store.Route.Majority): two such writes always share a replica.
func majority(n int) int { return n/2 + 1 }

// checkMajority refuses a Majority command of key unless a strict majority
// of key's replicas, stand-ins not counted, is reachable. A member that has
// not found its cluster (seeking, or started alone) reaches no majority.
func (r *Replicator) checkMajority(cmd store.Command, key string, v view) error {
	if r.seeking.Load() || r.alone.Load() {
		return fmt.Errorf("apply %s: this member has not found the rest of its cluster: %w", cmd.Op(), store.ErrNoMajority)
	}
	live, _ := v.owners(store.BucketOf(store.Token(key)))
	if w := majority(v.n); len(live) < w {
		return fmt.Errorf("apply %s: %d of %d replicas of its key reachable, %d needed: %w",
			cmd.Op(), len(live), v.n, w, store.ErrNoMajority)
	}
	return nil
}

// errUnreachable marks a member that could not be reached: its writes go
// to hints.
var errUnreachable = errors.New("member unreachable")

// Apply implements store.Applier. A command creating a master-owned row is
// owned by this member, and one using such a row is refused unless this
// member owns it (store.OwnedBy, owned.go).
func (r *Replicator) Apply(ctx context.Context, cmd store.Command) (store.Result, error) {
	cmd = store.OwnedBy(cmd, r.cfg.NodeID)
	if key, ok := store.OwnedUse(cmd); ok {
		return r.applyOwned(ctx, key, cmd)
	}
	return r.applyRouted(ctx, cmd)
}

// applyRouted applies cmd where its route says.
func (r *Replicator) applyRouted(ctx context.Context, cmd store.Command) (store.Result, error) {
	route, err := store.RouteOf(cmd)
	if err != nil {
		return store.Result{}, err
	}
	v := r.view()
	switch route.Kind {
	case store.RouteEvery:
		live, _ := v.all()
		results := make([]store.Result, len(live))
		errs := make([]error, len(live))
		var wg sync.WaitGroup
		for i, m := range live {
			wg.Go(func() { results[i], errs[i] = r.applyOn(ctx, m, cmd) })
		}
		wg.Wait()
		if err := firstDomainError(errs); err != nil {
			return store.Result{}, err
		}
		// A critical one is not done until some member applied it.
		if route.Critical && !slices.Contains(errs, nil) {
			return store.Result{}, fmt.Errorf("apply %s: no storage member reachable: %w", cmd.Op(), store.ErrUnavailable)
		}
		return store.MergeResults(cmd, results), nil
	case store.RouteSplit:
		parts, err := store.SplitCommand(cmd, func(key string) string {
			return v.coordinator(store.BucketOf(store.Token(key)))
		})
		if err != nil {
			return store.Result{}, err
		}
		var results []store.Result
		for m, part := range parts {
			if m == "" {
				return store.Result{}, fmt.Errorf("apply %s: no live replica: %w", cmd.Op(), store.ErrUnavailable)
			}
			res, err := r.applyOn(ctx, m, part)
			if err != nil {
				return store.Result{}, err
			}
			results = append(results, res)
		}
		return store.MergeResults(cmd, results), nil
	case store.RouteGlobal:
		return r.applyHere(ctx, cmd, route, v)
	}
	// RouteKey: on this member if it takes the write, else forwarded to
	// the first live one that does. A First command runs on the first live
	// replica, and on the next ones only if that one cannot be reached.
	if route.Majority {
		if err := r.checkMajority(cmd, route.Key, v); err != nil {
			return store.Result{}, err
		}
	}
	live, _ := v.targets(store.BucketOf(store.Token(route.Key)))
	if (route.First && len(live) > 0 && live[0] == v.self) || (!route.First && slices.Contains(live, v.self)) {
		return r.applyHere(ctx, cmd, route, v)
	}
	if len(live) < writeQuorum(route.Critical, v.n) {
		return store.Result{}, fmt.Errorf("apply %s: %d of %d replicas reachable: %w", cmd.Op(), len(live), v.n, store.ErrUnavailable)
	}
	var lastErr error
	for _, m := range live {
		res, err := r.applyOn(ctx, m, cmd)
		if err == nil || !errors.Is(err, errUnreachable) {
			return res, err
		}
		lastErr = err
	}
	return store.Result{}, fmt.Errorf("apply %s: %w: %w", cmd.Op(), lastErr, store.ErrUnavailable)
}

// coordinator is the member a write of bucket runs on: this one if it is a
// target, else the first live target; "" if there is none.
func (v view) coordinator(bucket int) string {
	live, _ := v.targets(bucket)
	if slices.Contains(live, v.self) {
		return v.self
	}
	if len(live) == 0 {
		return ""
	}
	return live[0]
}

// firstDomainError returns the first error of errs that is not a member
// being unreachable: a write every member runs succeeds on those it
// reaches.
func firstDomainError(errs []error) error {
	for _, err := range errs {
		if err != nil && !errors.Is(err, errUnreachable) {
			return err
		}
	}
	return nil
}

// applyOn applies cmd on member m, which then replicates it.
func (r *Replicator) applyOn(ctx context.Context, m string, cmd store.Command) (store.Result, error) {
	if m == r.cfg.NodeID {
		route, err := store.RouteOf(cmd)
		if err != nil {
			return store.Result{}, err
		}
		return r.applyHere(ctx, cmd, route, r.view())
	}
	b, err := store.EncodeCommand(cmd)
	if err != nil {
		return store.Result{}, err
	}
	// The member applies it and may wait for its replicas: two quick rounds.
	actx, cancel := context.WithTimeout(ctx, 3*r.cfg.QuickTimeout)
	defer cancel()
	resp, err := r.call(actx, m, apRequest{Op: opApply, Cmd: b})
	if err != nil {
		return store.Result{}, err
	}
	if resp.Result == nil {
		return store.Result{}, nil
	}
	return *resp.Result, nil
}

// applyHere applies cmd to this member's database and replicates the rows
// it wrote. A critical write first checks that W replicas are live, so it
// fails before writing anything when they are not. A Majority one also needs
// a majority of its replicas to answer the refresh of the rows it reads.
func (r *Replicator) applyHere(ctx context.Context, cmd store.Command, route store.Route, v view) (store.Result, error) {
	st := r.store()
	if st == nil {
		return store.Result{}, errors.New("replicator: no store bound")
	}
	if route.Critical {
		if r.seeking.Load() {
			return store.Result{}, fmt.Errorf("apply %s: this member has not found the cluster it joins yet: %w",
				cmd.Op(), store.ErrUnavailable)
		}
		var live []string
		n := v.n
		if route.Kind == store.RouteKey {
			live, _ = v.targets(store.BucketOf(store.Token(route.Key)))
		} else {
			live, _ = v.globals()
			n = len(v.everyone)
		}
		if w := writeQuorum(true, n); len(live) < w {
			return store.Result{}, fmt.Errorf("apply %s: %d of %d replicas reachable, %d needed: %w",
				cmd.Op(), len(live), n, w, store.ErrUnavailable)
		}
	}
	if route.Majority {
		if err := r.checkMajority(cmd, route.Key, v); err != nil {
			return store.Result{}, err
		}
	}
	answered := r.refresh(ctx, st, cmd, route, v)
	if route.Majority && len(store.ReadsOf(cmd)) > 0 {
		if err := readMajority(cmd, route.Key, v, answered); err != nil {
			return store.Result{}, err
		}
	}
	res, muts, err := st.ApplyLocalMutations(ctx, cmd)
	if err != nil {
		return store.Result{}, err
	}
	if store.Revokes(cmd) {
		r.announceRevocation(muts)
	}
	if err := r.replicate(ctx, muts, route, v); err != nil {
		return store.Result{}, fmt.Errorf("apply %s: %w", cmd.Op(), err)
	}
	return res, nil
}

// refresh merges here the newest copy, on the other live members that may
// hold them, of the rows cmd reads (store.ReadsOf), so a command this member
// applies decides on them and not on a copy it missed a write of. It is
// best effort: a member that does not answer within QuickTimeout is
// skipped, and its rows reach this one by hints and anti-entropy. It returns
// the members whose rows it merged.
func (r *Replicator) refresh(ctx context.Context, st *store.Store, cmd store.Command, route store.Route, v view) map[string]bool {
	reads := store.ReadsOf(cmd)
	if len(reads) == 0 {
		return nil
	}
	var peers []string
	if route.Kind == store.RouteKey {
		peers = v.readOrder(store.BucketOf(store.Token(route.Key)))
	} else {
		peers, _ = v.globals()
	}
	peers = slices.DeleteFunc(slices.Clone(peers), func(m string) bool { return m == v.self })
	answered := map[string]bool{}
	if len(peers) == 0 {
		return answered
	}
	got := make([][]store.Mutation, len(peers))
	ok := make([]bool, len(peers))
	var wg sync.WaitGroup
	for i, m := range peers {
		wg.Go(func() {
			qctx, cancel := context.WithTimeout(ctx, r.cfg.QuickTimeout)
			defer cancel()
			ms, err := r.fetchReads(qctx, m, reads)
			if err != nil {
				r.log.DebugContext(ctx, "fetch the rows a write reads", "op", cmd.Op(), "member", m, "err", err)
				return
			}
			got[i], ok[i] = ms, true
		})
	}
	wg.Wait()
	for i, ms := range got {
		if !ok[i] {
			continue
		}
		if len(ms) > 0 {
			store.SortMutations(ms)
			if err := st.Merge(ctx, ms); err != nil {
				r.log.WarnContext(ctx, "merge the rows a write reads", "op", cmd.Op(), "member", peers[i], "err", err)
				continue
			}
		}
		answered[peers[i]] = true
	}
	return answered
}

// readMajority refuses a Majority command of key unless a majority of key's
// replicas, this member included if it is one, gave it the rows it reads:
// then it decides on the newest copy any earlier Majority write left, as
// that write's majority and this one share a replica. A replica still
// catching up after its promotion does not count.
func readMajority(cmd store.Command, key string, v view, answered map[string]bool) error {
	live, _ := v.owners(store.BucketOf(store.Token(key)))
	n := 0
	for _, m := range live {
		if !v.syncing[m] && (m == v.self || answered[m]) {
			n++
		}
	}
	if w := majority(v.n); n < w {
		return fmt.Errorf("apply %s: %d of %d replicas of its key answered, %d needed: %w", cmd.Op(), n, v.n, w, store.ErrNoMajority)
	}
	return nil
}

// fetchReads reads on member m the rows reads name.
func (r *Replicator) fetchReads(ctx context.Context, m string, reads []store.Read) ([]store.Mutation, error) {
	var refs []store.RowRef
	for _, rd := range reads {
		if ref, ok := rd.Ref(); ok {
			refs = append(refs, ref)
			continue
		}
		rows, err := r.readOn(ctx, m, rd.KeysQuery(), rd.Args)
		if err != nil {
			return nil, err
		}
		for _, key := range rows.Vals {
			refs = append(refs, store.RowRef{Table: rd.Table, Key: key})
		}
	}
	if len(refs) == 0 {
		return nil, nil
	}
	return r.fetch(ctx, m, refs)
}

// replicate sends muts, written here, to the other members that take them.
// Replicas that are down get hints. A critical write waits for W - 1 other
// replicas of every row; any other is sent in the background. A replica
// that fails to take a critical write though the gossip still has it live
// (it died a moment ago) is treated as down: it gets a hint, and the rows
// go to the next live stand-in instead. A Majority write waits for a strict
// majority of each row's replicas; a stand-in gets it but does not count.
func (r *Replicator) replicate(ctx context.Context, muts []store.Mutation, route store.Route, v view) error {
	if len(muts) == 0 {
		return nil
	}
	critical := route.Critical || route.Majority
	batches, hinted, groups, err := r.plan(ctx, muts, critical, route.Majority, v)
	if err != nil {
		return err
	}
	for t, ms := range hinted {
		r.hint(t, ms)
	}
	if !critical {
		for t, ms := range batches {
			r.enqueue(func(ctx context.Context) {
				if _, err := r.call(ctx, t, apRequest{Op: opMerge, Muts: ms}); err != nil {
					r.log.DebugContext(ctx, "replicate: hinted", "member", t, "err", err)
					r.hint(t, ms)
				}
			}, func() { r.hint(t, ms) })
		}
		return nil
	}
	acked := map[string]bool{v.self: true}
	failed := map[string]bool{}
	for round := 0; ; round++ {
		r.sendCritical(ctx, batches, acked, failed)
		err := shortOf(groups, acked)
		if err == nil || round == 1 || len(failed) == 0 {
			return err
		}
		// Once more, with the members that failed as down.
		live := maps.Clone(v.live)
		for m := range failed {
			delete(live, m)
		}
		v.live = live
		if batches, _, groups, err = r.plan(ctx, muts, critical, route.Majority, v); err != nil {
			return err
		}
		for t := range batches {
			if acked[t] || failed[t] {
				delete(batches, t)
			}
		}
	}
}

// shortOf returns ErrUnavailable if a row has fewer than W acks.
func shortOf(groups []writeGroup, acked map[string]bool) error {
	for _, g := range groups {
		n := 0
		for _, t := range g.live {
			if acked[t] {
				n++
			}
		}
		switch {
		case n < g.w && g.majority:
			return fmt.Errorf("%d of %d replicas took a majority write: %w", n, g.w, store.ErrNoMajority)
		case n < g.w:
			return fmt.Errorf("%d of %d replicas took a critical write: %w", n, g.w, store.ErrUnavailable)
		}
	}
	return nil
}

// writeGroup is the live targets of one row and how many must take it.
type writeGroup struct {
	live []string
	w    int
	// majority is set for a write that needs a majority of the replicas.
	majority bool
}

// plan returns, for muts written here, the rows to send to each other live
// target, the rows to hint to each replica that is down, and each row's
// targets and W; for a majority write, each row's live replicas, stand-ins
// left out, and a strict majority of N. Every target of a child row (a certificate) gets its
// parent (the device) first: a stand-in may never have held it, and an
// owner may not hold it yet, its copy still in a hint or in the
// background replication of the parent's write (#370).
func (r *Replicator) plan(ctx context.Context, muts []store.Mutation, critical, maj bool, v view) (batches, hinted map[string][]store.Mutation, groups []writeGroup, err error) {
	batches, hinted = map[string][]store.Mutation{}, map[string][]store.Mutation{}
	parents := map[string][]store.RowRef{}
	for _, m := range muts {
		p, err := m.Placement()
		if err != nil {
			return nil, nil, nil, err
		}
		live, down := v.placementTargets(p)
		n := v.n
		if p.Global {
			n = len(v.everyone)
		}
		if maj && !p.Global {
			owners, _ := v.owners(store.BucketOf(store.Token(p.Key)))
			groups = append(groups, writeGroup{live: owners, w: majority(n), majority: true})
		} else {
			groups = append(groups, writeGroup{live: live, w: writeQuorum(critical, n)})
		}
		ref, hasParent := m.ParentRef()
		for _, t := range live {
			if t == v.self {
				continue
			}
			batches[t] = append(batches[t], m)
			if hasParent {
				parents[t] = append(parents[t], ref)
			}
		}
		for _, t := range down {
			hinted[t] = append(hinted[t], m)
		}
	}
	for t, refs := range parents {
		ps, err := r.store().ReadRows(ctx, refs)
		if err != nil {
			return nil, nil, nil, err
		}
		batches[t] = append(ps, batches[t]...)
	}
	return batches, hinted, groups, nil
}

// sendCritical sends each batch and waits: a member that takes it goes in
// acked; one that does not gets a hint and goes in failed.
func (r *Replicator) sendCritical(ctx context.Context, batches map[string][]store.Mutation, acked, failed map[string]bool) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	for t, ms := range batches {
		wg.Go(func() {
			qctx, cancel := context.WithTimeout(ctx, r.cfg.QuickTimeout)
			defer cancel()
			_, err := r.call(qctx, t, apRequest{Op: opMerge, Muts: ms})
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				r.log.WarnContext(ctx, "replicate a critical write: hinted", "member", t, "err", err)
				r.hint(t, ms)
				failed[t] = true
				return
			}
			acked[t] = true
		})
	}
	wg.Wait()
}

// hint keeps ms for member t.
func (r *Replicator) hint(t string, ms []store.Mutation) {
	if r.cfg.Hints == nil {
		return
	}
	if err := r.cfg.Hints.Add(t, ms); err != nil {
		r.log.Warn("keep a hint", "member", t, "err", err)
	}
}

// enqueue runs job in the background; full, it runs full instead.
func (r *Replicator) enqueue(job func(context.Context), full func()) {
	select {
	case r.jobs <- job:
	default:
		if full != nil {
			full()
		}
	}
}

// Holds implements store.Shards: this member reads its own copy of the
// rows it holds, unless it is still catching up after its promotion.
func (r *Replicator) Holds(key string) bool {
	v := r.view()
	return !v.syncing[v.self] && slices.Contains(v.ring.Owners(store.BucketOf(store.Token(key)), v.n), v.self)
}

// readOrder is where a read of bucket is tried: its live replicas in
// preference order, this member first, then the other live members (which
// may hold rows as stand-ins), and last the replicas still catching up
// after their promotion.
func (v view) readOrder(bucket int) []string {
	pref := v.ring.Preference(bucket)
	var out, late []string
	for i, m := range pref {
		switch {
		case !v.live[m] || i >= v.n:
		case v.syncing[m]:
			late = append(late, m)
		default:
			out = append(out, m)
		}
	}
	if i := slices.Index(out, v.self); i > 0 {
		out = append([]string{v.self}, slices.Delete(out, i, i+1)...)
	}
	for i, m := range pref {
		if v.live[m] && i >= v.n {
			out = append(out, m)
		}
	}
	return append(out, late...)
}

// ReadKey implements store.Shards.
func (r *Replicator) ReadKey(ctx context.Context, key, query string, args store.Values) (store.Rows, error) {
	v := r.view()
	lastErr := store.ErrUnavailable
	for _, m := range v.readOrder(store.BucketOf(store.Token(key))) {
		rows, err := r.readOn(ctx, m, query, args)
		if err == nil {
			return rows, nil
		}
		if !errors.Is(err, errUnreachable) {
			return store.Rows{}, err
		}
		lastErr = err
	}
	return store.Rows{}, fmt.Errorf("read: no replica reachable: %w: %w", lastErr, store.ErrUnavailable)
}

// ReadReplicas implements store.Shards.
func (r *Replicator) ReadReplicas(ctx context.Context, key, query string, args store.Values) ([]store.Rows, error) {
	v := r.view()
	order := v.readOrder(store.BucketOf(store.Token(key)))
	out := make([]store.Rows, len(order))
	errs := make([]error, len(order))
	var wg sync.WaitGroup
	for i, m := range order {
		wg.Go(func() { out[i], errs[i] = r.readOn(ctx, m, query, args) })
	}
	wg.Wait()
	var rows []store.Rows
	lastErr := store.ErrUnavailable
	for i, err := range errs {
		if err != nil {
			if !errors.Is(err, errUnreachable) {
				return nil, err
			}
			lastErr = err
			continue
		}
		rows = append(rows, out[i])
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("read: no replica reachable: %w: %w", lastErr, store.ErrUnavailable)
	}
	return rows, nil
}

func (r *Replicator) readOn(ctx context.Context, m, query string, args store.Values) (store.Rows, error) {
	if m == r.cfg.NodeID {
		return r.store().ReadLocal(ctx, query, args)
	}
	resp, err := r.call(ctx, m, apRequest{Op: opRead, Query: query, Args: args})
	if err != nil {
		return store.Rows{}, err
	}
	if resp.Rows == nil {
		return store.Rows{Member: m}, nil
	}
	resp.Rows.Member = m
	return *resp.Rows, nil
}

// ReadAll implements store.Shards: it reads on every live storage member,
// and fails unless those that answered hold a replica of every bucket.
func (r *Replicator) ReadAll(ctx context.Context, query string, args store.Values) ([]store.Rows, error) {
	v := r.view()
	live, _ := v.all()
	out := make([]store.Rows, len(live))
	errs := make([]error, len(live))
	var wg sync.WaitGroup
	for i, m := range live {
		wg.Go(func() { out[i], errs[i] = r.readOn(ctx, m, query, args) })
	}
	wg.Wait()
	answered := map[string]bool{}
	var rows []store.Rows
	for i, err := range errs {
		if err != nil {
			if !errors.Is(err, errUnreachable) {
				return nil, err
			}
			continue
		}
		if !v.syncing[live[i]] {
			answered[live[i]] = true
		}
		rows = append(rows, out[i])
	}
	for _, seg := range v.ring.Segments() {
		if !slices.ContainsFunc(v.ring.Owners(seg.Start, v.n), func(m string) bool { return answered[m] }) {
			return nil, fmt.Errorf("read: no replica of buckets %d-%d reachable: %w", seg.Start, seg.End-1, store.ErrUnavailable)
		}
	}
	return rows, nil
}

// Repair implements store.Shards: in the background, the rows refs name are
// read on every live member, and the newest version of each is merged into
// all its replicas.
func (r *Replicator) Repair(refs []store.RowRef) {
	r.enqueue(func(ctx context.Context) {
		if err := r.repair(ctx, refs); err != nil {
			r.log.DebugContext(ctx, "read repair", "err", err)
		}
	}, nil)
}

func (r *Replicator) repair(ctx context.Context, refs []store.RowRef) error {
	v := r.view()
	live, _ := v.globals()
	var muts []store.Mutation
	for _, m := range live {
		ms, err := r.fetch(ctx, m, refs)
		if err != nil {
			continue
		}
		muts = append(muts, ms...)
	}
	batches := map[string][]store.Mutation{}
	for _, m := range muts {
		p, err := m.Placement()
		if err != nil {
			return err
		}
		targets, _ := v.placementTargets(p)
		for _, t := range targets {
			batches[t] = append(batches[t], m)
		}
	}
	for t, ms := range batches {
		if err := r.mergeOn(ctx, t, ms); err != nil {
			r.log.DebugContext(ctx, "read repair", "member", t, "err", err)
		}
	}
	return nil
}

// fetch reads the rows refs name on member m.
func (r *Replicator) fetch(ctx context.Context, m string, refs []store.RowRef) ([]store.Mutation, error) {
	if m == r.cfg.NodeID {
		return r.store().ReadRows(ctx, refs)
	}
	resp, err := r.call(ctx, m, apRequest{Op: opFetch, Refs: refs})
	if err != nil {
		return nil, err
	}
	return resp.Muts, nil
}

// mergeOn merges ms into member m's database.
func (r *Replicator) mergeOn(ctx context.Context, m string, ms []store.Mutation) error {
	if len(ms) == 0 {
		return nil
	}
	if m == r.cfg.NodeID {
		ms = slices.Clone(ms)
		store.SortMutations(ms)
		return r.store().Merge(ctx, ms)
	}
	_, err := r.call(ctx, m, apRequest{Op: opMerge, Muts: ms})
	return err
}

// Run delivers hints, runs anti-entropy and the tombstone GC, and works the
// background jobs until ctx ends.
func (r *Replicator) Run(ctx context.Context) error {
	r.ctx.Store(&ctx)
	var wg sync.WaitGroup
	for range 2 {
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case job := <-r.jobs:
					jctx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
					job(jctx)
					cancel()
				}
			}
		})
	}
	wg.Go(func() { r.every(ctx, r.cfg.HintsEvery, r.deliverHints) })
	wg.Go(func() { r.every(ctx, r.cfg.AntiEntropyEvery, r.antiEntropy) })
	wg.Go(func() { r.every(ctx, r.cfg.GCEvery, r.gc) })
	wg.Wait()
	r.closePool()
	return nil
}

// every runs fn now and then every d until ctx ends.
func (r *Replicator) every(ctx context.Context, d time.Duration, fn func(context.Context)) {
	t := time.NewTicker(d)
	defer t.Stop()
	for {
		fn(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// gc drops the tombstones older than store.TombstoneTTL.
func (r *Replicator) gc(ctx context.Context) {
	st := r.store()
	if st == nil {
		return
	}
	n, err := st.GCTombstones(ctx, r.cfg.Now())
	if err != nil {
		r.log.WarnContext(ctx, "tombstone gc", "err", err)
		return
	}
	if n > 0 {
		r.log.InfoContext(ctx, "dropped old tombstones", "count", n)
	}
}

// deliverHints sends the hints of every live member.
func (r *Replicator) deliverHints(ctx context.Context) {
	h := r.cfg.Hints
	if h == nil {
		return
	}
	members, err := h.Members(ctx)
	if err != nil {
		r.log.WarnContext(ctx, "read hints", "err", err)
		return
	}
	v := r.view()
	for _, m := range members {
		if !v.live[m] || m == v.self {
			continue
		}
		for ctx.Err() == nil {
			ids, ms, err := h.Take(ctx, m, hintBatch)
			if err != nil || len(ids) == 0 {
				break
			}
			if _, err := r.call(ctx, m, apRequest{Op: opMerge, Muts: ms}); err != nil {
				r.log.DebugContext(ctx, "deliver hints", "member", m, "err", err)
				break
			}
			if err := h.Delete(ctx, ids); err != nil {
				r.log.WarnContext(ctx, "delete delivered hints", "err", err)
				break
			}
			r.log.DebugContext(ctx, "delivered hints", "member", m, "count", len(ms))
		}
	}
}

// Requests between members.
const (
	opApply  = "apply"
	opMerge  = "merge"
	opRead   = "read"
	opTree   = "tree"
	opLeaves = "leaves"
	opRows   = "rows"
	opFetch  = "fetch"
)

type apRequest struct {
	Op      string           `json:"op"`
	Cmd     json.RawMessage  `json:"cmd,omitempty"`
	Muts    []store.Mutation `json:"muts,omitempty"`
	Query   string           `json:"query,omitempty"`
	Args    store.Values     `json:"args,omitempty"`
	Space   store.Space      `json:"space,omitempty"`
	Ranges  []bucketRange    `json:"ranges,omitempty"`
	Buckets []int            `json:"buckets,omitempty"`
	Refs    []store.RowRef   `json:"refs,omitempty"`
}

type apResponse struct {
	Error   *wireError        `json:"error,omitempty"`
	Result  *store.Result     `json:"result,omitempty"`
	Rows    *store.Rows       `json:"rows,omitempty"`
	Hashes  []uint64          `json:"hashes,omitempty"`
	Digests []store.RowDigest `json:"digests,omitempty"`
	Muts    []store.Mutation  `json:"muts,omitempty"`
}

// The store errors a member's answer carries beyond those of wireKinds.
var apKinds = map[string]error{
	"exists":       store.ErrExists,
	"skew":         hlc.ErrSkew,
	"no_route":     store.ErrNoRoute,
	"not_member":   errNotMember,
	"cert_revoked": store.ErrCertRevoked,
}

// errNotMember refuses a replication request from a hub that is not a
// storage member or a master.
var errNotMember = errors.New("not a member of this cluster")

func apWireError(err error) *wireError {
	for kind, target := range apKinds {
		if errors.Is(err, target) {
			return &wireError{Kind: kind, Message: err.Error()}
		}
	}
	return toWireError(err)
}

func apError(e *wireError) error {
	if target, ok := apKinds[e.Kind]; ok {
		return &kindError{msg: e.Message, target: target}
	}
	return e.toError()
}

// call sends req to member m and returns its answer. A member that cannot
// be reached fails with errUnreachable; its answer's error is returned as
// the store error it carries.
func (r *Replicator) call(ctx context.Context, m string, req apRequest) (apResponse, error) {
	if m == r.cfg.NodeID {
		resp := r.handle(ctx, m, req)
		if resp.Error != nil {
			return resp, apError(resp.Error)
		}
		return resp, nil
	}
	parent := ctx
	timeout := r.cfg.RequestTimeout
	if req.Op == opRead {
		timeout = r.cfg.QuickTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	unreachable := func(err error) (apResponse, error) {
		if !errors.Is(parent.Err(), context.Canceled) {
			// Not the caller giving up: the member is taken as down for a
			// while, and its other connections, likely dead too, dropped.
			r.markSuspect(m)
		}
		return apResponse{}, fmt.Errorf("%s: %w: %w", m, errUnreachable, err)
	}
	// A member that cannot be connected to in a quick timeout is down,
	// whatever the request may take once it is: a write forwarded to a
	// member cut off a moment ago costs that, not the request's timeout,
	// before the next target is tried.
	var (
		c    net.Conn
		resp apResponse
	)
	// A pooled connection may have been closed since it was pooled (a hub
	// CA rotation closes the connections of the old CA's certificates): its
	// request is sent again once, on a new connection. A merge or a read is
	// harmless again (a merge applies by its stamps); a command forwarded
	// for m to coordinate (opApply) is sent again only if it could not be
	// written, as m may have applied it.
	for tryPool := true; ; tryPool = false {
		dctx, dcancel := context.WithTimeout(ctx, r.cfg.QuickTimeout)
		var pooled bool
		var err error
		c, pooled, err = r.conn(dctx, m, tryPool)
		dcancel()
		if err != nil {
			return unreachable(err)
		}
		d, _ := ctx.Deadline()
		_ = c.SetDeadline(d)
		sent := false
		if err = writeFrame(c, req); err == nil {
			sent = true
			err = readFrame(c, &resp)
		}
		if err == nil {
			break
		}
		_ = c.Close()
		if !pooled || ctx.Err() != nil || (sent && req.Op == opApply) {
			return unreachable(err)
		}
		resp = apResponse{}
	}
	_ = c.SetDeadline(time.Time{})
	if resp.Error != nil && resp.Error.Kind == "not_member" {
		// The member hung up after refusing this one (ServeConn): a
		// pooled connection would fail the next request as unreachable.
		_ = c.Close()
	} else {
		r.putConn(m, c)
	}
	r.clearSuspect(m)
	r.touchContact()
	if resp.Error != nil {
		return resp, apError(resp.Error)
	}
	return resp, nil
}

// markSuspect takes m as down for SuspectFor and drops its pooled
// connections.
func (r *Replicator) markSuspect(m string) {
	r.suspectMu.Lock()
	r.suspect[m] = r.cfg.Now().Add(r.cfg.SuspectFor)
	r.suspectMu.Unlock()
	r.poolMu.Lock()
	cs := r.pool[m]
	delete(r.pool, m)
	r.poolMu.Unlock()
	for _, c := range cs {
		_ = c.Close()
	}
}

// clearSuspect forgets that a request failed to reach m: m was heard from.
func (r *Replicator) clearSuspect(m string) {
	r.suspectMu.Lock()
	delete(r.suspect, m)
	r.suspectMu.Unlock()
}

// suspected reports whether a request failed to reach m a moment ago.
func (r *Replicator) suspected(m string) bool {
	r.suspectMu.Lock()
	defer r.suspectMu.Unlock()
	until, ok := r.suspect[m]
	if ok && !r.cfg.Now().Before(until) {
		delete(r.suspect, m)
		return false
	}
	return ok
}

// conn returns a connection to m: a pooled one if pool and there is one
// (pooled is then true), else a new one.
func (r *Replicator) conn(ctx context.Context, m string, pool bool) (c net.Conn, pooled bool, err error) {
	if pool {
		r.poolMu.Lock()
		if cs := r.pool[m]; len(cs) > 0 {
			c := cs[len(cs)-1]
			r.pool[m] = cs[:len(cs)-1]
			r.poolMu.Unlock()
			return c, true, nil
		}
		r.poolMu.Unlock()
	}
	c, err = r.cfg.Peers.DialReplica(ctx, m)
	return c, false, err
}

func (r *Replicator) putConn(m string, c net.Conn) {
	r.poolMu.Lock()
	defer r.poolMu.Unlock()
	if len(r.pool[m]) >= poolSize {
		_ = c.Close()
		return
	}
	r.pool[m] = append(r.pool[m], c)
}

func (r *Replicator) closePool() {
	r.poolMu.Lock()
	defer r.poolMu.Unlock()
	for m, cs := range r.pool {
		for _, c := range cs {
			_ = c.Close()
		}
		delete(r.pool, m)
	}
}

// ServeConn serves the replication requests of peer, the hub node ID its
// certificate names, on c until c fails or stays idle; then it closes c.
// Pass it as MembershipConfig.Replica.
func (r *Replicator) ServeConn(c net.Conn, peer string) {
	defer func() { _ = c.Close() }()
	ctx := *r.ctx.Load()
	for ctx.Err() == nil {
		_ = c.SetReadDeadline(time.Now().Add(replicaIdle))
		var req apRequest
		if err := readFrame(c, &req); err != nil {
			return
		}
		_ = c.SetReadDeadline(time.Time{})
		rctx, cancel := context.WithTimeout(ctx, r.cfg.RequestTimeout)
		var resp apResponse
		if r.isMember(peer) {
			r.clearSuspect(peer) // it reached this member: it is up
			resp = r.handle(rctx, peer, req)
		} else {
			r.log.Warn("refused a replication request from a non-member", "peer", peer, "op", req.Op)
			resp = apResponse{Error: apWireError(fmt.Errorf("%s: %w", peer, errNotMember))}
		}
		cancel()
		_ = c.SetWriteDeadline(time.Now().Add(r.cfg.RequestTimeout))
		if err := writeFrame(c, resp); err != nil {
			return
		}
		if resp.Error != nil && resp.Error.Kind == "not_member" {
			return
		}
	}
}

// isMember reports whether peer is a storage member or a master this
// member knows: a master that holds no shard still coordinates writes and
// reads, and holds the global rows.
func (r *Replicator) isMember(peer string) bool {
	if peer == "" || peer == r.cfg.NodeID {
		return false
	}
	for _, m := range r.cfg.Peers.Members() {
		if m.ID == peer && m.Roles.Gossips() && m.State != MemberLeft {
			return true
		}
	}
	return false
}

// handle answers one request.
func (r *Replicator) handle(ctx context.Context, peer string, req apRequest) apResponse {
	st := r.store()
	if st == nil {
		return apResponse{Error: apWireError(errors.New("replicator: no store bound"))}
	}
	fail := func(err error) apResponse { return apResponse{Error: apWireError(err)} }
	switch req.Op {
	case opApply:
		cmd, err := store.DecodeCommand(req.Cmd)
		if err != nil {
			return fail(err)
		}
		route, err := store.RouteOf(cmd)
		if err != nil {
			return fail(err)
		}
		res, err := r.applyHere(ctx, cmd, route, r.view())
		if err != nil {
			return fail(err)
		}
		return apResponse{Result: &res}
	case opMerge:
		ms := slices.Clone(req.Muts)
		store.SortMutations(ms)
		if err := st.Merge(ctx, ms); err != nil {
			if errors.Is(err, hlc.ErrSkew) {
				r.log.WarnContext(ctx, "refused rows stamped too far ahead of this clock", "peer", peer, "err", err)
			}
			return fail(err)
		}
		return apResponse{}
	case opRead:
		rows, err := st.ReadLocal(ctx, req.Query, req.Args)
		if err != nil {
			return fail(err)
		}
		return apResponse{Rows: &rows}
	case opFetch:
		ms, err := st.ReadRows(ctx, req.Refs)
		if err != nil {
			return fail(err)
		}
		return apResponse{Muts: ms}
	case opTree, opLeaves, opRows:
		return r.handleAntiEntropy(ctx, st, req)
	}
	return fail(fmt.Errorf("unknown request %q", req.Op))
}

func writeFrame(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > maxFrame {
		return fmt.Errorf("frame of %d bytes exceeds %d", len(b), maxFrame)
	}
	buf := make([]byte, 4+len(b))
	binary.BigEndian.PutUint32(buf, uint32(len(b))) //nolint:gosec // bounded by maxFrame
	copy(buf[4:], b)
	_, err = w.Write(buf)
	return err
}

func readFrame(rd io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(rd, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > maxFrame {
		return fmt.Errorf("frame of %d bytes exceeds %d", n, maxFrame)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rd, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// touchContact records that this member reached the cluster now (see
// CheckRejoin), at most once a minute.
func (r *Replicator) touchContact() {
	if r.cfg.LastContact == "" {
		return
	}
	now := r.cfg.Now()
	r.contactMu.Lock()
	defer r.contactMu.Unlock()
	if now.Sub(r.contactSeen) < time.Minute {
		return
	}
	r.contactSeen = now
	if err := writeLastContact(r.cfg.LastContact, now); err != nil {
		r.log.Warn("record last contact", "err", err)
	}
}

// ErrRejoinEmpty refuses to start a storage member that was cut off from
// the cluster for longer than the tombstone window: rows deleted meanwhile
// lost their tombstones elsewhere, so its copy could bring them back.
var ErrRejoinEmpty = errors.New("this member was away from the cluster for longer than the tombstone window " +
	"and must rejoin empty")

// CheckRejoin refuses a member whose database holds rows and whose last
// contact with the cluster (recorded in the file at path) is older than
// store.TombstoneTTL at now. A member alone in its cluster counts as in
// contact (the Replicator records it every anti-entropy round).
func CheckRejoin(path string, hasRows bool, now time.Time) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read last contact: %w", err)
	}
	last, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	if err != nil {
		return fmt.Errorf("read last contact %s: %w", path, err)
	}
	if hasRows && now.Sub(last) > store.TombstoneTTL {
		return fmt.Errorf("%w: last in contact %s ago (window %s); move the database (hearth.db) aside, "+
			"start the hub to resync from the cluster, then delete the old copy",
			ErrRejoinEmpty, now.Sub(last).Round(time.Hour), store.TombstoneTTL)
	}
	return nil
}

func writeLastContact(path string, t time.Time) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(t.UTC().Format(time.RFC3339)+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
