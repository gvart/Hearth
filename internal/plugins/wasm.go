// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"

	"github.com/gvart/hearth/internal/policy"
)

// WASM plugins (#74): a WebAssembly module (WASI preview 1) that speaks the
// exec plugins' protocol on its stdin and stdout, run in-process by wazero.
// It has no filesystem, no network, no environment but HEARTH_PLUGIN, and its
// memory is capped; it reaches out only through the host functions of the
// "hearth" module its manifest grants, each call decided and audited by
// policy. Nothing of wazero is set up until a WASM plugin first starts.

// Host function limits.
const (
	// maxHostRequest bounds a host call's request.
	maxHostRequest = 128 << 10
	// maxHostRate is the most host calls a WASM plugin may make in a
	// second; one that makes more is stopped.
	maxHostRate = 10
	// maxHTTPBody bounds an http call's request body, and maxHTTPResponse
	// its response's.
	maxHTTPBody     = 64 << 10
	maxHTTPResponse = 1 << 20
	// httpTimeout bounds an http call.
	httpTimeout = 10 * time.Second
)

// Host functions a manifest may grant.
const hostHTTP = "http"

// wasmRuntime is a WASM plugin's runtime, made when it first starts. It
// keeps the module compiled across restarts while its SHA-256 stays the
// same.
type wasmRuntime struct {
	rt       wazero.Runtime
	compiled wazero.CompiledModule
	sha256   string
	client   *http.Client
	// cur is the running instance, which host calls are of. One runs at a
	// time: runOnce waits for an instance to end before it starts another.
	cur *wasmInstance
}

// wasmInstance is one run of a WASM plugin's module.
type wasmInstance struct {
	// fail stops the instance for a reason.
	fail context.CancelCauseFunc
	// reply is the last host call's reply, until the plugin takes it.
	reply []byte
	// windowStart and calls count host calls, for maxHostRate.
	windowStart time.Time
	calls       int
}

// wasmCache shares compiled modules between a Manager's WASM plugins: a
// plugin's runtime is made, and closed, with the plugin, while its compiled
// module is worth keeping. It is made on first use, so that nothing of
// wazero is set up without a WASM plugin.
type wasmCache struct {
	once  sync.Once
	cache wazero.CompilationCache
}

func (c *wasmCache) get() wazero.CompilationCache {
	c.once.Do(func() { c.cache = wazero.NewCompilationCache() })
	return c.cache
}

// closeWasm releases the plugin's WASM runtime, if it has one.
func (p *plugin) closeWasm() {
	if p.wasm == nil {
		return
	}
	_ = p.wasm.rt.Close(context.Background())
	if p.wasm.client != nil {
		p.wasm.client.CloseIdleConnections()
	}
	p.wasm = nil
}

// wasmRuntimeFor returns the plugin's runtime, made on first use.
func (p *plugin) wasmRuntimeFor(ctx context.Context) (*wasmRuntime, error) {
	if p.wasm != nil {
		return p.wasm, nil
	}
	cfg := wazero.NewRuntimeConfig().
		WithCompilationCache(p.o.wasmCache.get()).
		// Cancelling an instance's context stops it, even in a tight loop.
		WithCloseOnContextDone(true).
		WithMemoryLimitPages(uint32(p.m.wasmMemory()) * 16) //nolint:gosec // at most 1024 MiB: 16384 pages of 64 KiB
	rt := wazero.NewRuntimeWithConfig(ctx, cfg)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("plugin %s: wasi: %w", p.m.Name, err)
	}
	w := &wasmRuntime{rt: rt}
	// Every host function is there, granted or not, so that a module that
	// imports one still runs: a call the manifest does not grant is denied
	// and audited when it is made.
	_, err := rt.NewHostModuleBuilder("hearth").
		NewFunctionBuilder().WithFunc(func(ctx context.Context, mod api.Module, namePtr, nameLen, reqPtr, reqLen uint32) int32 {
		return p.hostCall(ctx, w.cur, mod, namePtr, nameLen, reqPtr, reqLen)
	}).Export("call").
		NewFunctionBuilder().WithFunc(func(_ context.Context, mod api.Module, ptr, capacity uint32) int32 {
		return hostReply(w.cur, mod, ptr, capacity)
	}).Export("reply").
		Instantiate(ctx)
	if err != nil {
		_ = rt.Close(ctx)
		return nil, fmt.Errorf("plugin %s: host functions: %w", p.m.Name, err)
	}
	p.wasm = w
	return w, nil
}

// readModule reads the plugin's .wasm file, checked as an exec plugin's
// program is, and returns it with its resolved path and SHA-256.
func (p *plugin) readModule() ([]byte, string, string, error) {
	path, err := p.resolve()
	if err != nil {
		return nil, "", "", err
	}
	f, resolved, err := openTrusted(path)
	if err != nil {
		return nil, "", "", fmt.Errorf("plugin %s: %w", p.m.Name, err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, MaxProgramSize+1))
	if err != nil {
		return nil, "", "", fmt.Errorf("plugin %s: read %s: %w", p.m.Name, resolved, err)
	}
	if len(b) > MaxProgramSize {
		return nil, "", "", fmt.Errorf("plugin %s: %s is larger than %d bytes", p.m.Name, resolved, MaxProgramSize)
	}
	sum := sha256.Sum256(b)
	return b, resolved, hex.EncodeToString(sum[:]), nil
}

// wasmDigest pins a WASM plugin's release: the SHA-256, in hex, of its
// module's SHA-256 and of the SHA-256 of its manifest in canonical JSON, as
// Release.Digest does for a device plugin.
func wasmDigest(m Manifest, moduleSHA string) string {
	b, _ := json.Marshal(struct { // plain strings, slices and ints: it cannot fail
		Name         string        `json:"name"`
		Version      string        `json:"version"`
		Args         []string      `json:"args"`
		Capabilities []string      `json:"capabilities"`
		Commands     []CommandSpec `json:"commands"`
		Memory       int           `json:"memory"`
		Host         HostGrants    `json:"host"`
	}{m.Name, m.Version, nonNil(m.Args), nonNil(m.Capabilities), nonNil(m.Commands), m.wasmMemory(), m.Host})
	mh := sha256.Sum256(b)
	d := sha256.Sum256([]byte(moduleSHA + "\n" + hex.EncodeToString(mh[:])))
	return hex.EncodeToString(d[:])
}

func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// startWasm starts a WASM plugin's module through policy, on a context of
// pctx: the hub's ends of its pipes are returned, as of a process.
func (p *plugin) startWasm(ctx, pctx context.Context) (*running, error) {
	b, path, sum, err := p.readModule()
	if err != nil {
		return nil, err
	}
	if p.m.SHA256 != "" && sum != p.m.SHA256 {
		return nil, fmt.Errorf("plugin %s: %s is %s: %w", p.m.Name, path, sum, ErrPinMismatch)
	}
	w, err := p.wasmRuntimeFor(ctx)
	if err != nil {
		return nil, err
	}
	if w.sha256 != sum {
		if w.compiled != nil {
			_ = w.compiled.Close(ctx)
			w.compiled, w.sha256 = nil, ""
		}
		// Compiled from the bytes hashed, never read again by path.
		c, err := w.rt.CompileModule(ctx, b)
		if err != nil {
			return nil, fmt.Errorf("plugin %s: compile %s: %w", p.m.Name, path, err)
		}
		w.compiled, w.sha256 = c, sum
	}
	pipes, err := stdioPipes(p.m.Name)
	if err != nil {
		return nil, err
	}
	inR, inW, outR, outW, errR, errW := pipes[0], pipes[1], pipes[2], pipes[3], pipes[4], pipes[5]
	mctx, fail := context.WithCancelCause(pctx)
	sleep := func(ns int64) {
		// The plugin's sleep ends when it is stopped.
		t := time.NewTimer(time.Duration(ns))
		defer t.Stop()
		select {
		case <-t.C:
		case <-mctx.Done():
		}
	}
	// No filesystem, no network, no environment but HEARTH_PLUGIN: only
	// stdio, its args, a clock and random numbers. stdin is a real pipe, so
	// that a module may poll it (as Go's runtime does, see pkg/sdk) and run
	// timers while it waits. stdout and stderr are plain writers, which
	// wazero does not close: the hub closes them once the plugin ended, so
	// that the plugin's end, not its closed stdout, is why it stopped.
	cfg := wazero.NewModuleConfig().
		WithName("").
		WithArgs(append([]string{p.m.Name}, p.m.Args...)...).
		WithEnv("HEARTH_PLUGIN", p.m.Name).
		WithStdin(inR).WithStdout(struct{ io.Writer }{outW}).WithStderr(struct{ io.Writer }{errW}).
		WithSysWalltime().WithSysNanotime().WithNanosleep(sleep).
		WithRandSource(crand.Reader)
	inst := &wasmInstance{fail: fail}
	w.cur = inst
	done := make(chan error, 1)
	started := false
	var grants []string
	if p.m.Host.HTTP != nil {
		grants = append(grants, hostHTTP)
	}
	err = p.pol.Do(ctx, policy.Request{
		ActorKind: policy.ActorHub,
		ActorID:   actorID,
		Action:    policy.PluginStart,
		Target:    p.m.Name,
		Detail: map[string]any{
			"version": p.m.Version, "runtime": RuntimeWasm, "module": path, "sha256": sum,
			"digest": wasmDigest(p.m, sum), "memory_mib": p.m.wasmMemory(), "host": nonNil(grants),
		},
	}, func(context.Context) error {
		started = true
		compiled := w.compiled
		go func() { // owned: wait, or the failed start below, receives its end
			mod, err := w.rt.InstantiateModule(mctx, compiled, cfg)
			if mod != nil {
				_ = mod.Close(context.WithoutCancel(mctx))
			}
			done <- err
		}()
		return nil
	})
	// Its ends of the pipes; wazero may have closed stdin already.
	release := func() { _, _, _ = inR.Close(), outW.Close(), errW.Close() }
	wait := func() error {
		err := <-done
		if cause := context.Cause(mctx); cause != nil && !errors.Is(cause, context.Canceled) {
			return cause
		}
		var exit *sys.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 0 {
			return nil
		}
		return err
	}
	// Stopping cancels the instance, which ends it even in a tight loop;
	// closing the hub's end of stdin wakes it from a read or a poll.
	stop := func() { fail(context.Canceled) }
	if err != nil {
		if started {
			// It started, but its outcome could not be audited.
			stop()
			_, _, _ = inW.Close(), outR.Close(), errR.Close()
			_ = wait()
		} else {
			fail(context.Canceled)
			_, _, _ = inW.Close(), outR.Close(), errR.Close()
		}
		release()
		return nil, fmt.Errorf("start plugin %s: %w", p.m.Name, err)
	}
	return &running{stdin: inW, stdout: outR, stderr: errR, wait: wait, stop: stop, release: release}, nil
}

// hostCall runs the host function named at namePtr with the JSON request
// at reqPtr, through policy, and keeps its JSON reply for hostReply. It
// returns the reply's length, or -1 if the call itself is malformed.
func (p *plugin) hostCall(ctx context.Context, inst *wasmInstance, mod api.Module, namePtr, nameLen, reqPtr, reqLen uint32) int32 {
	if inst == nil {
		return -1
	}
	inst.reply = nil
	if now := p.now(); now.Sub(inst.windowStart) >= time.Second {
		inst.windowStart, inst.calls = now, 0
	}
	if inst.calls++; inst.calls > maxHostRate {
		inst.fail(violation("more than %d host calls a second", maxHostRate))
		// Stopped now, as proc_exit stops a module: no code of it runs after
		// this call. wazero turns the panic into the instance's end.
		_ = mod.CloseWithExitCode(ctx, 1)
		panic(sys.NewExitError(1)) //nolint:forbidigo // wazero's way to end a module from a host function
	}
	if nameLen > 64 || reqLen > maxHostRequest {
		return -1
	}
	name, ok := mod.Memory().Read(namePtr, nameLen)
	if !ok {
		return -1
	}
	req, ok := mod.Memory().Read(reqPtr, reqLen)
	if !ok {
		return -1
	}
	result, err := p.host(ctx, string(name), slices.Clone(req))
	r := struct {
		OK     bool   `json:"ok"`
		Result any    `json:"result,omitempty"`
		Error  string `json:"error,omitempty"`
	}{OK: err == nil, Result: result}
	if err != nil {
		r.Error = err.Error()
	}
	inst.reply, _ = json.Marshal(r) // plain values: it cannot fail
	return int32(len(inst.reply))   //nolint:gosec // at most a few MiB
}

// hostReply copies the last host call's reply to ptr, if it fits in
// capacity, and forgets it. It returns its length, or -1.
func hostReply(inst *wasmInstance, mod api.Module, ptr, capacity uint32) int32 {
	if inst == nil || uint64(len(inst.reply)) > uint64(capacity) {
		return -1
	}
	if !mod.Memory().Write(ptr, inst.reply) {
		return -1
	}
	n := len(inst.reply)
	inst.reply = nil
	return int32(n) //nolint:gosec // at most a few MiB
}

// errHostRequest is a malformed host call: it is not an action, and is
// neither decided nor audited.
var errHostRequest = errors.New("bad host call")

// host runs host function name, through policy: the action is
// plugin.host.call, target <plugin>/<name>. A host function the manifest
// does not grant, or a host its grant does not allow, is denied and
// audited.
func (p *plugin) host(ctx context.Context, name string, req []byte) (any, error) {
	if !idRE().MatchString(name) {
		name = "invalid"
	}
	preq := policy.Request{
		ActorKind: policy.ActorHub,
		ActorID:   actorID,
		Action:    policy.PluginHostCall,
		Target:    p.m.Name + "/" + name,
		Detail:    map[string]any{"plugin": p.m.Name, "version": p.m.Version, "function": name},
	}
	deny := func(format string, args ...any) {
		reason := fmt.Sprintf(format, args...)
		preq.Precheck = func(context.Context) error {
			return fmt.Errorf("plugin %s: %s: %w", p.m.Name, reason, policy.ErrDenied)
		}
	}
	var run func(context.Context) (any, error)
	switch name {
	case hostHTTP:
		var hr httpRequest
		var hreq *http.Request
		var hostport string
		err := json.Unmarshal(req, &hr)
		if err != nil {
			err = fmt.Errorf("%w: http: %w", errHostRequest, err)
		} else if hreq, hostport, err = hr.build(); err == nil {
			// The host and method only: a path or a query may hold a secret.
			preq.Detail["method"], preq.Detail["host"] = hreq.Method, hostport
		}
		switch {
		case p.m.Host.HTTP == nil:
			// Denied and audited, however malformed the request.
			deny("its manifest grants no http host function")
		case err != nil:
			return nil, err
		case !p.httpAllowed(hostport):
			deny("its manifest does not allow http to %s", hostport)
		default:
			run = func(ctx context.Context) (any, error) { return p.doHTTP(ctx, hreq) }
		}
	default:
		deny("no host function %q", name)
	}
	var result any
	err := p.pol.Do(ctx, preq, func(ctx context.Context) error {
		if run == nil {
			return fmt.Errorf("host function %s: %w", name, policy.ErrDenied)
		}
		var err error
		result, err = run(ctx)
		return err
	})
	return result, err
}

// httpRequest is an http host call's request. Body is base64 in JSON.
type httpRequest struct {
	Method string            `json:"method"`
	URL    string            `json:"url"`
	Header map[string]string `json:"header,omitempty"`
	Body   []byte            `json:"body,omitempty"`
}

// httpResponse is an http host call's result.
type httpResponse struct {
	Status int               `json:"status"`
	Header map[string]string `json:"header"`
	Body   []byte            `json:"body"`
}

// build checks the request and makes it, with the host:port it goes to.
func (r httpRequest) build() (*http.Request, string, error) {
	method := r.Method
	if method == "" {
		method = http.MethodGet
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
	default:
		return nil, "", fmt.Errorf("%w: http: method %.16q", errHostRequest, method)
	}
	if len(r.Body) > maxHTTPBody {
		return nil, "", fmt.Errorf("%w: http: body larger than %d bytes", errHostRequest, maxHTTPBody)
	}
	u, err := url.Parse(r.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return nil, "", fmt.Errorf("%w: http: want an http or https URL", errHostRequest)
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	hostport := net.JoinHostPort(strings.ToLower(u.Hostname()), port)
	req, err := http.NewRequest(method, u.String(), bytes.NewReader(r.Body)) //nolint:noctx // its context is set when it runs
	if err != nil {
		return nil, "", fmt.Errorf("%w: http: %w", errHostRequest, err)
	}
	for k, v := range r.Header {
		req.Header.Set(k, v)
	}
	return req, hostport, nil
}

// allowedHost normalises a host:port of an http grant.
func allowedHost(a string) (string, error) {
	host, port, err := net.SplitHostPort(a)
	if err != nil || host == "" {
		return "", fmt.Errorf("%q: want host:port", a)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%q: invalid port", a)
	}
	return net.JoinHostPort(strings.ToLower(host), port), nil
}

// httpAllowed reports whether the plugin's http grant allows hostport.
func (p *plugin) httpAllowed(hostport string) bool {
	if p.m.Host.HTTP == nil {
		return false
	}
	for _, a := range p.m.Host.HTTP.Allow {
		if n, err := allowedHost(a); err == nil && n == hostport {
			return true
		}
	}
	return false
}

// doHTTP makes an allowed http request: no proxy, no redirect, and a dial
// only to an allowed host, whatever the URL.
func (p *plugin) doHTTP(ctx context.Context, req *http.Request) (httpResponse, error) {
	w := p.wasm
	if w.client == nil {
		d := &net.Dialer{Timeout: 5 * time.Second}
		w.client = &http.Client{
			Timeout: httpTimeout,
			Transport: &http.Transport{
				Proxy: nil,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					if !p.httpAllowed(strings.ToLower(addr)) {
						return nil, fmt.Errorf("dial %s: not allowed: %w", addr, policy.ErrDenied)
					}
					return d.DialContext(ctx, network, addr)
				},
				TLSHandshakeTimeout: 5 * time.Second,
				MaxIdleConns:        4,
				IdleConnTimeout:     30 * time.Second,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	resp, err := w.client.Do(req.WithContext(ctx))
	if err != nil {
		return httpResponse{}, fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponse+1))
	if err != nil {
		return httpResponse{}, fmt.Errorf("http: read the response: %w", err)
	}
	if len(body) > maxHTTPResponse {
		return httpResponse{}, fmt.Errorf("http: response larger than %d bytes", maxHTTPResponse)
	}
	h := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		h[k] = resp.Header.Get(k)
	}
	return httpResponse{Status: resp.StatusCode, Header: h, Body: body}, nil
}
