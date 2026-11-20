// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gvart/hearth/internal/policy"
)

// Plugin states.
const (
	StateStarting   = "starting"
	StateRunning    = "running"
	StateRestarting = "restarting"
	StateStopped    = "stopped"
)

// Options bound a plugin's process. The zero value of a field means its
// default.
type Options struct {
	// BackoffMin and BackoffMax bound the wait before a restart, which
	// doubles after each failure. Defaults 1s and 5m.
	BackoffMin, BackoffMax time.Duration
	// HealthyAfter is how long a process must have run for the next
	// failure to start the backoff over. Default 1m.
	HealthyAfter time.Duration
	// StartTimeout is how long a started plugin has to answer hello.
	// Default 10s.
	StartTimeout time.Duration
	// PingEvery is how often the hub pings a running plugin, and
	// ReplyTimeout how long it waits for the pong before it restarts the
	// plugin as hung. Defaults 30s and 10s.
	PingEvery, ReplyTimeout time.Duration
	// DiscoverEvery is how often the hub asks a plugin with the discover
	// capability for its devices. Default 1m.
	DiscoverEvery time.Duration
	// CommandTimeout is how long a command, or a discover, may take.
	// Default 30s.
	CommandTimeout time.Duration
	// MaxLine is the longest line a plugin may print. Default 1 MiB.
	MaxLine int
	// MaxRate is the most lines a plugin may print in a second. Default 200.
	MaxRate int
}

func (o Options) withDefaults() Options {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.BackoffMin, time.Second)
	def(&o.BackoffMax, 5*time.Minute)
	def(&o.HealthyAfter, time.Minute)
	def(&o.StartTimeout, 10*time.Second)
	def(&o.PingEvery, 30*time.Second)
	def(&o.ReplyTimeout, 10*time.Second)
	def(&o.DiscoverEvery, time.Minute)
	def(&o.CommandTimeout, 30*time.Second)
	if o.MaxLine <= 0 {
		o.MaxLine = 1 << 20
	}
	if o.MaxRate <= 0 {
		o.MaxRate = 200
	}
	return o
}

// errViolation marks a plugin breaking the protocol: the hub restarts it.
var errViolation = errors.New("protocol violation")

func violation(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errViolation, fmt.Sprintf(format, args...))
}

// plugin supervises one plugin: it runs its process, restarts it with
// backoff, and keeps what it reported.
type plugin struct {
	m   Manifest
	o   Options
	pol Policy
	log *slog.Logger
	now func() time.Time

	mu        sync.Mutex
	state     string
	lastErr   string
	restarts  int
	startedAt time.Time
	devices   []Device
	stderr    []string
	proc      *proc
}

// proc is one running process of a plugin, once it said hello.
type proc struct {
	// send queues lines for the plugin's stdin; a full queue means the
	// plugin stopped reading, and stops it.
	send   chan []byte
	dead   <-chan struct{}
	cancel context.CancelCauseFunc
	seq    atomic.Uint64

	mu      sync.Mutex
	pending map[string]pendingReply
}

type pendingReply struct {
	want string
	ch   chan message
}

// run runs the plugin until ctx is done, restarting it with backoff
// whenever it stops.
func (p *plugin) run(ctx context.Context) {
	delay := p.o.BackoffMin
	for {
		started := p.now()
		err := p.runOnce(ctx)
		if ctx.Err() != nil {
			p.setState(StateStopped, "")
			return
		}
		if p.now().Sub(started) >= p.o.HealthyAfter {
			delay = p.o.BackoffMin
		}
		p.mu.Lock()
		p.restarts++
		p.state, p.lastErr = StateRestarting, err.Error()
		p.devices = nil
		p.mu.Unlock()
		p.log.WarnContext(ctx, "plugin stopped; restarting", "plugin", p.m.Name, "err", err, "in", delay)
		t := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			t.Stop()
			p.setState(StateStopped, "")
			return
		case <-t.C:
		}
		delay = min(delay*2, p.o.BackoffMax)
	}
}

func (p *plugin) setState(state, lastErr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.state, p.lastErr = state, lastErr
}

// runOnce starts the plugin's process through policy and runs it until it
// stops or ctx is done. It returns why it stopped.
func (p *plugin) runOnce(ctx context.Context) error {
	p.setState(StateStarting, "")
	path, err := p.resolve()
	if err != nil {
		return err
	}
	pctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	// The hub holds the pipes itself, so that closing its ends unblocks
	// every read and write whatever the plugin (or a child it left behind)
	// does with its own.
	var pipes [6]*os.File
	closeAll := func() {
		for _, f := range pipes {
			if f != nil {
				_ = f.Close()
			}
		}
	}
	for i := 0; i < len(pipes); i += 2 {
		if pipes[i], pipes[i+1], err = os.Pipe(); err != nil {
			closeAll()
			return fmt.Errorf("plugin %s: pipe: %w", p.m.Name, err)
		}
	}
	inR, inW, outR, outW, errR, errW := pipes[0], pipes[1], pipes[2], pipes[3], pipes[4], pipes[5]
	cmd := exec.Command(path, p.m.Args...) //nolint:gosec // the operator's manifest names the program; no shell
	cmd.Dir, cmd.Env = p.m.Dir, p.env()
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, errW

	err = p.pol.Do(ctx, policy.Request{
		ActorKind: policy.ActorHub,
		ActorID:   actorID,
		Action:    policy.PluginStart,
		Target:    p.m.Name,
		Detail:    map[string]any{"version": p.m.Version, "command": path},
	}, func(context.Context) error { return cmd.Start() })
	// The child holds its ends now, if it started.
	_, _, _ = inR.Close(), outW.Close(), errW.Close()
	if err != nil {
		if cmd.Process != nil {
			// It started, but its outcome could not be audited.
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_, _, _ = inW.Close(), outR.Close(), errR.Close()
		return fmt.Errorf("start plugin %s: %w", p.m.Name, err)
	}
	p.mu.Lock()
	p.startedAt = p.now()
	p.mu.Unlock()

	pr := &proc{send: make(chan []byte, 64), dead: pctx.Done(), cancel: cancel, pending: map[string]pendingReply{}}
	hello := make(chan struct{})
	var wg sync.WaitGroup
	wg.Go(func() {
		err := cmd.Wait()
		if err == nil {
			err = errors.New("exited")
		}
		cancel(fmt.Errorf("plugin process: %w", err))
	})
	wg.Go(func() { cancel(p.readLoop(pctx, pr, outR, hello)) })
	wg.Go(func() { p.stderrLoop(errR) })
	wg.Go(func() { cancel(writeLoop(pctx, pr, inW)) })

	pr.send <- line(message{Type: typeHello, Protocol: ProtocolVersion})
	t := time.NewTimer(p.o.StartTimeout)
	select {
	case <-hello:
		t.Stop()
		p.mu.Lock()
		p.state, p.proc = StateRunning, pr
		p.mu.Unlock()
		p.log.InfoContext(ctx, "plugin running", "plugin", p.m.Name, "version", p.m.Version)
		wg.Go(func() { cancel(p.keepalive(pctx, pr)) })
	case <-pctx.Done():
		t.Stop()
	case <-t.C:
		cancel(fmt.Errorf("no hello within %s", p.o.StartTimeout))
	}
	<-pctx.Done()

	p.mu.Lock()
	p.proc = nil
	p.mu.Unlock()
	// The hub stops a plugin by killing it; closing its ends of the pipes
	// ends the loops.
	_ = cmd.Process.Kill()
	_, _, _ = inW.Close(), outR.Close(), errR.Close()
	wg.Wait()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return context.Cause(pctx)
}

// actorID is the audit actor of a plugin start.
const actorID = "hub/plugins"

// resolve returns the program to run.
func (p *plugin) resolve() (string, error) {
	c := p.m.Command
	var path string
	switch {
	case filepath.IsAbs(c):
		path = c
	case strings.ContainsRune(c, '/') || strings.ContainsRune(c, filepath.Separator):
		path = filepath.Join(p.m.Dir, c)
	default:
		var err error
		if path, err = exec.LookPath(c); err != nil {
			return "", fmt.Errorf("plugin %s: %w", p.m.Name, err)
		}
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(path)
		if err != nil {
			return "", fmt.Errorf("plugin %s: %w", p.m.Name, err)
		}
		if fi.Mode().Perm()&0o022 != 0 {
			return "", fmt.Errorf("plugin %s: %s is writable by group or others (mode %v)", p.m.Name, path, fi.Mode().Perm())
		}
	}
	return path, nil
}

// env is the plugin's environment: none of the hub's own, except what it
// needs to find programs.
func (p *plugin) env() []string {
	env := []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HEARTH_PLUGIN=" + p.m.Name}
	if runtime.GOOS == "windows" {
		env = []string{"PATH=" + os.Getenv("PATH"), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT"), "HEARTH_PLUGIN=" + p.m.Name}
	}
	keys := make([]string, 0, len(p.m.Env))
	for k := range p.m.Env {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		env = append(env, k+"="+p.m.Env[k])
	}
	return env
}

func line(m message) []byte {
	b, _ := json.Marshal(m) // a message always marshals
	return append(b, '\n')
}

// writeLoop writes queued lines to the plugin's stdin until pctx is done.
func writeLoop(pctx context.Context, pr *proc, w io.Writer) error {
	for {
		select {
		case <-pctx.Done():
			return nil
		case b := <-pr.send:
			if _, err := w.Write(b); err != nil {
				return fmt.Errorf("write to plugin: %w", err)
			}
		}
	}
}

// readLoop reads the plugin's stdout until it fails or the plugin breaks
// the protocol. It closes hello once the plugin said hello.
func (p *plugin) readLoop(pctx context.Context, pr *proc, r io.Reader, hello chan struct{}) error {
	br := bufio.NewReaderSize(r, 64<<10)
	greeted := false
	windowStart, count := p.now(), 0
	for {
		b, err := readLine(br, p.o.MaxLine)
		if err != nil {
			if pctx.Err() != nil {
				return nil
			}
			if errors.Is(err, io.EOF) {
				return errors.New("plugin closed its stdout")
			}
			return err
		}
		if now := p.now(); now.Sub(windowStart) >= time.Second {
			windowStart, count = now, 0
		}
		if count++; count > p.o.MaxRate {
			return violation("more than %d lines a second", p.o.MaxRate)
		}
		if len(b) == 0 {
			continue
		}
		var m message
		if err := json.Unmarshal(b, &m); err != nil {
			return violation("a line is not a JSON message (%d bytes)", len(b))
		}
		if !greeted {
			if m.Type != typeHello {
				return violation("first message is %.32q, not hello", m.Type)
			}
			if m.Protocol != ProtocolVersion {
				return violation("plugin speaks protocol %d, the hub %d", m.Protocol, ProtocolVersion)
			}
			if m.Name != p.m.Name {
				return violation("plugin says it is %.64q, its manifest %q", m.Name, p.m.Name)
			}
			greeted = true
			close(hello)
			continue
		}
		if err := p.handle(pr, m); err != nil {
			return err
		}
	}
}

// readLine reads one line of at most max bytes, without its newline.
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(buf)+len(chunk) > max+1 {
			return nil, violation("a line is longer than %d bytes", max)
		}
		switch {
		case err == nil:
			buf = append(buf, chunk...)
			return buf[:len(buf)-1], nil
		case errors.Is(err, bufio.ErrBufferFull):
			buf = append(buf, chunk...)
		default:
			return nil, err
		}
	}
}

// handle applies one message of a greeted plugin.
func (p *plugin) handle(pr *proc, m message) error {
	switch m.Type {
	case typePong:
		return pr.deliver(m)
	case typeDevices:
		if !p.m.Has(CapDiscover) {
			return violation("devices without the discover capability")
		}
		if err := validDevices(m.Devices); err != nil {
			return violation("devices: %v", err)
		}
		p.mu.Lock()
		p.devices = m.Devices
		p.mu.Unlock()
		if m.ID != "" {
			return pr.deliver(m)
		}
		return nil
	case typeState:
		if !p.m.Has(CapState) {
			return violation("state without the state capability")
		}
		if len(m.State) > maxState {
			return violation("state larger than %d bytes", maxState)
		}
		p.setEntityState(m.Device, m.Entity, m.State)
		return nil
	case typeResult:
		if !p.m.Has(CapCommand) {
			return violation("result without the command capability")
		}
		return pr.deliver(m)
	}
	return violation("unknown message type %.32q", m.Type)
}

// setEntityState sets an entity's state. A state of a device or entity the
// plugin has not reported is dropped.
func (p *plugin) setEntityState(dev, ent string, state json.RawMessage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.devices {
		if p.devices[i].ID != dev {
			continue
		}
		// Copied on write: snapshots share the old slices.
		ents := slices.Clone(p.devices[i].Entities)
		for j := range ents {
			if ents[j].ID == ent {
				ents[j].State = state
				devs := slices.Clone(p.devices)
				devs[i].Entities = ents
				p.devices = devs
				return
			}
		}
		return
	}
}

// stderrLoop keeps the tail of the plugin's stderr, each line cut short.
func (p *plugin) stderrLoop(r io.Reader) {
	br := bufio.NewReaderSize(r, 4<<10)
	var cur []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(cur) < maxStderrLine {
			cur = append(cur, chunk[:min(len(chunk), maxStderrLine-len(cur))]...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if s := strings.TrimRight(string(cur), "\r\n"); s != "" {
			p.mu.Lock()
			p.stderr = append(p.stderr, s)
			if len(p.stderr) > stderrLines {
				p.stderr = slices.Clone(p.stderr[len(p.stderr)-stderrLines:])
			}
			p.mu.Unlock()
		}
		cur = cur[:0]
		if err != nil {
			return
		}
	}
}

// keepalive pings the plugin and asks for its devices until pctx is done
// or the plugin fails to answer.
func (p *plugin) keepalive(pctx context.Context, pr *proc) error {
	ping := time.NewTicker(p.o.PingEvery)
	defer ping.Stop()
	disc := time.NewTicker(p.o.DiscoverEvery)
	defer disc.Stop()
	discover := func() error {
		if !p.m.Has(CapDiscover) {
			return nil
		}
		if _, err := pr.request(pctx, message{Type: typeDiscover}, typeDevices, p.o.CommandTimeout); err != nil {
			return fmt.Errorf("discover: %w", err)
		}
		return nil
	}
	if err := discover(); err != nil {
		return err
	}
	for {
		select {
		case <-pctx.Done():
			return nil
		case <-ping.C:
			if _, err := pr.request(pctx, message{Type: typePing}, typePong, p.o.ReplyTimeout); err != nil {
				return fmt.Errorf("ping: %w", err)
			}
		case <-disc.C:
			if err := discover(); err != nil {
				return err
			}
		}
	}
}

// errNoReply is a request the plugin did not answer in time.
var errNoReply = errors.New("no reply in time")

// request sends m with a new id and waits for the reply of type want.
func (pr *proc) request(ctx context.Context, m message, want string, timeout time.Duration) (message, error) {
	m.ID = strconv.FormatUint(pr.seq.Add(1), 10)
	ch := make(chan message, 1)
	pr.mu.Lock()
	pr.pending[m.ID] = pendingReply{want: want, ch: ch}
	pr.mu.Unlock()
	defer func() {
		pr.mu.Lock()
		delete(pr.pending, m.ID)
		pr.mu.Unlock()
	}()
	select {
	case pr.send <- line(m):
	case <-pr.dead:
		return message{}, ErrUnavailable
	default:
		pr.cancel(errors.New("plugin stopped reading its stdin"))
		return message{}, ErrUnavailable
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case r := <-ch:
		return r, nil
	case <-pr.dead:
		return message{}, ErrUnavailable
	case <-t.C:
		return message{}, errNoReply
	case <-ctx.Done():
		return message{}, ctx.Err()
	}
}

// deliver hands a reply to the request waiting for it. A reply nobody waits
// for, such as one that came too late, is dropped.
func (pr *proc) deliver(m message) error {
	pr.mu.Lock()
	w, ok := pr.pending[m.ID]
	pr.mu.Unlock()
	if !ok {
		return nil
	}
	if w.want != m.Type {
		return violation("reply %.32q to a request that wants %s", m.Type, w.want)
	}
	select {
	case w.ch <- m:
	default:
		return violation("two replies to request %s", m.ID)
	}
	return nil
}
