// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// An agent upgrades itself when its hub asks (UpgradeRequest, #347): it
// downloads the release archive the hub names, checks it against the
// SHA-256 the hub took from the release's checksums.txt, puts the new
// hearth in place of its own executable by a rename in the same directory,
// keeping the old one as <exe>.prev, answers, and exits with ExitUpgraded
// for systemd (Restart=always) or launchd (KeepAlive) to start the new one.

// ErrUpgraded is returned by Run once the agent replaced its own binary:
// `hearth agent run` exits with ExitUpgraded, and the service manager starts
// the new binary.
var ErrUpgraded = errors.New("the agent's binary was upgraded; exiting so the service manager starts the new one")

// ExitUpgraded is the exit status of `hearth agent run` on ErrUpgraded
// (EX_TEMPFAIL from sysexits.h): not zero, and not ExitRevoked, so systemd
// restarts it whatever its Restart= says short of no.
const ExitUpgraded = 75

const (
	// upgradeTimeout bounds a whole upgrade: download, check and swap.
	upgradeTimeout = 5 * time.Minute
	// maxUpgradeArchive and maxUpgradeBinary cap the archive downloaded and
	// the hearth extracted from it. A release archive is some 30 MB.
	maxUpgradeArchive = 128 << 20
	maxUpgradeBinary  = 256 << 20
	// upgradeVersionTimeout bounds `<new binary> version`.
	upgradeVersionTimeout = 15 * time.Second
)

// upgradeVersion matches the release tags an UpgradeRequest may name.
var upgradeVersion = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)

// upgrader replaces the agent's executable.
type upgrader struct {
	// exe is the executable to replace, resolved when the agent starts:
	// once replaced, os.Executable may name the new file or the old.
	exe string
	// refusal, if set, is why this agent does not upgrade itself.
	refusal string
	// target is the release archive's os_arch.
	target string
	// client downloads the archive: a plain client, never the mTLS one,
	// which would show the device certificate to the download server.
	client                *http.Client
	maxArchive, maxBinary int64
	timeout               time.Duration
}

// newUpgrader is the upgrader of the executable exe ("" for the running
// one), refusing as selfUpgradeRefusal says from getenv.
func newUpgrader(exe string, getenv func(string) string) *upgrader {
	u := &upgrader{
		client:     &http.Client{Transport: http.DefaultTransport},
		maxArchive: maxUpgradeArchive, maxBinary: maxUpgradeBinary, timeout: upgradeTimeout,
		refusal: selfUpgradeRefusal(runtime.GOOS, getenv),
		target:  releaseTarget(runtime.GOOS, runtime.GOARCH, goarm()),
	}
	if exe == "" {
		p, err := os.Executable()
		if err == nil {
			p, err = filepath.EvalSymlinks(p)
		}
		if err != nil {
			u.refusal = "cannot find the agent's own executable: " + err.Error()
		}
		exe = p
	}
	u.exe = exe
	return u
}

// selfUpgradeRefusal says why an agent on goos, with the environment
// getenv reads, does not upgrade itself; "" if it does.
func selfUpgradeRefusal(goos string, getenv func(string) string) string {
	switch {
	case getenv("KUBERNETES_SERVICE_HOST") != "":
		return "this agent runs in a Kubernetes pod: upgrade its image instead"
	case getenv("HEARTH_NO_SELF_UPGRADE") != "":
		return "self-upgrade is turned off on this device (HEARTH_NO_SELF_UPGRADE)"
	case goos == "windows":
		return "an agent on Windows does not upgrade itself yet: re-run the installer on the device"
	case goos != "linux" && goos != "darwin":
		return "an agent on " + goos + " does not upgrade itself"
	}
	return ""
}

// releaseTarget is the os_arch of the release archive for goos and goarch,
// as .goreleaser.yaml names it: arm is armv<goarm>.
func releaseTarget(goos, goarch, goarm string) string {
	if goarch == "arm" {
		goarch = "armv" + goarm
	}
	return goos + "_" + goarch
}

// goarm is the GOARM the binary was built with, 7 (the releases') if it
// does not say.
func goarm() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "GOARM" && s.Value != "" {
				return strings.TrimSuffix(strings.TrimSuffix(s.Value, ",softfloat"), ",hardfloat")
			}
		}
	}
	return "7"
}

// hello sets the Hello fields that say whether, and from which archive, the
// agent upgrades itself; nothing for a runner without one (a test's).
func (u *upgrader) hello(h *agentv1.Hello) {
	if u == nil {
		return
	}
	if u.refusal != "" {
		h.NoSelfUpgrade = u.refusal
		return
	}
	h.ReleaseTarget = u.target
}

// upgrade carries out req: on success the new binary is in place and the
// caller must exit. Nothing of the old binary changes unless every check
// passed.
func (u *upgrader) upgrade(ctx context.Context, req *agentv1.UpgradeRequest) *agentv1.UpgradeResult {
	res := &agentv1.UpgradeResult{Id: req.GetId()}
	if u.refusal != "" {
		res.Denied, res.Error = true, u.refusal
		return res
	}
	if err := checkUpgradeRequest(req); err != nil {
		res.Denied, res.Error = true, err.Error()
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()
	version, err := u.install(ctx, req)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Ok, res.Version = true, version
	return res
}

// checkUpgradeRequest refuses a request that names no release, no hash or
// no http(s) URL.
func checkUpgradeRequest(req *agentv1.UpgradeRequest) error {
	if !upgradeVersion.MatchString(req.GetVersion()) {
		return errors.New("the upgrade names no release version")
	}
	if b, err := hex.DecodeString(req.GetSha256()); err != nil || len(b) != sha256.Size {
		return errors.New("the upgrade names no SHA-256")
	}
	p, err := url.Parse(req.GetUrl())
	if err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" {
		return errors.New("the upgrade names no http(s) URL")
	}
	return nil
}

// install downloads, checks and puts in place the binary of req, and
// returns the version it reports.
func (u *upgrader) install(ctx context.Context, req *agentv1.UpgradeRequest) (string, error) {
	archive, err := os.CreateTemp("", "hearth-upgrade-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("create a temporary file: %w", err)
	}
	defer func() { _ = archive.Close(); _ = os.Remove(archive.Name()) }()
	if err := u.download(ctx, req, archive); err != nil {
		return "", err
	}
	if _, err := archive.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("read the archive: %w", err)
	}

	dir := filepath.Dir(u.exe)
	next, err := os.CreateTemp(dir, ".hearth.new-*")
	if err != nil {
		return "", fmt.Errorf("write next to %s: %w%s", u.exe, err, readOnlyHint(err))
	}
	keep := false
	defer func() {
		_ = next.Close()
		if !keep {
			_ = os.Remove(next.Name())
		}
	}()
	if err := u.extract(archive, next); err != nil {
		return "", err
	}
	if err := next.Chmod(0o755); err != nil {
		return "", fmt.Errorf("make the new binary executable: %w", err)
	}
	if err := next.Close(); err != nil {
		return "", fmt.Errorf("write the new binary: %w", err)
	}
	version, err := binaryVersion(ctx, next.Name())
	if err != nil {
		return "", err
	}
	if version != req.GetVersion() {
		return "", fmt.Errorf("the archive's binary reports version %q, not %s", version, req.GetVersion())
	}

	prev := u.exe + ".prev"
	if err := os.Remove(prev); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("remove the old backup %s: %w", prev, err)
	}
	if err := os.Link(u.exe, prev); err != nil {
		return "", fmt.Errorf("keep the current binary as %s: %w", prev, err)
	}
	if err := os.Rename(next.Name(), u.exe); err != nil {
		return "", fmt.Errorf("put the new binary in place: %w", err)
	}
	keep = true
	return version, nil
}

// download writes the archive of req to f, checking its size and SHA-256.
func (u *upgrader) download(ctx context.Context, req *agentv1.UpgradeRequest, f *os.File) error {
	hr, err := http.NewRequestWithContext(ctx, http.MethodGet, req.GetUrl(), nil)
	if err != nil {
		return fmt.Errorf("download the release: %w", err)
	}
	resp, err := u.client.Do(hr)
	if err != nil {
		return fmt.Errorf("download the release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download the release: the server answered %s", resp.Status)
	}
	if resp.ContentLength > u.maxArchive {
		return fmt.Errorf("the release archive is larger than %d MiB: refused", u.maxArchive>>20)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, u.maxArchive+1))
	if err != nil {
		return fmt.Errorf("download the release: %w", err)
	}
	if n > u.maxArchive {
		return fmt.Errorf("the release archive is larger than %d MiB: refused", u.maxArchive>>20)
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, req.GetSha256()) {
		return fmt.Errorf("checksum mismatch: the archive's SHA-256 is %s, the release's checksums.txt says %s; nothing was changed",
			got, strings.ToLower(req.GetSha256()))
	}
	return nil
}

// extract copies the hearth file of the tar.gz archive to out.
func (u *upgrader) extract(archive io.Reader, out io.Writer) error {
	gz, err := gzip.NewReader(bufio.NewReader(archive))
	if err != nil {
		return fmt.Errorf("read the archive: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	for {
		hd, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("the archive holds no hearth binary")
		}
		if err != nil {
			return fmt.Errorf("read the archive: %w", err)
		}
		if strings.TrimPrefix(hd.Name, "./") != "hearth" || hd.Typeflag != tar.TypeReg {
			continue
		}
		if hd.Size > u.maxBinary {
			return fmt.Errorf("the archive's hearth is larger than %d MiB: refused", u.maxBinary>>20)
		}
		n, err := io.Copy(out, io.LimitReader(tr, u.maxBinary+1))
		if err != nil {
			return fmt.Errorf("extract hearth: %w", err)
		}
		if n > u.maxBinary {
			return fmt.Errorf("the archive's hearth is larger than %d MiB: refused", u.maxBinary>>20)
		}
		return nil
	}
}

// binaryVersion runs `path version` and returns the version it prints
// first ("hearth v0.1.0").
func binaryVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, upgradeVersionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "version").Output()
	if err != nil {
		return "", fmt.Errorf("the new binary does not run on this device (%s/%s): %w", runtime.GOOS, runtime.GOARCH, err)
	}
	line, _, _ := strings.Cut(string(out), "\n")
	v, ok := strings.CutPrefix(strings.TrimSpace(line), "hearth ")
	if !ok {
		return "", fmt.Errorf("the new binary printed no version: %q", line)
	}
	return v, nil
}

// readOnlyHint explains a read-only binary directory: the service unit of
// an older installer.
func readOnlyHint(err error) string {
	if errors.Is(err, syscall.EROFS) || errors.Is(err, os.ErrPermission) {
		return " (re-run the installer on the device once: its service unit lets the agent replace its binary)"
	}
	return ""
}

// handleUpgrade runs req on its own goroutine in execs, one upgrade at a
// time, and sends its result. Once the new binary is in place the agent
// exits (ErrUpgraded), whether or not the result could be sent: it already
// is the new version on disk.
func (r *runner) handleUpgrade(ctx context.Context, req *agentv1.UpgradeRequest, execs *sync.WaitGroup,
	send func(context.Context, *agentv1.AgentMessage) bool,
) {
	reply := func(res *agentv1.UpgradeResult) bool {
		return send(ctx, &agentv1.AgentMessage{Payload: &agentv1.AgentMessage_UpgradeResult{UpgradeResult: res}})
	}
	if !r.upgrading.CompareAndSwap(false, true) {
		execs.Go(func() {
			reply(&agentv1.UpgradeResult{Id: req.GetId(), Denied: true, Error: "an upgrade is already running"})
		})
		return
	}
	execs.Go(func() {
		defer r.upgrading.Store(false)
		r.log.InfoContext(ctx, "upgrade request", "id", req.GetId(), "version", req.GetVersion())
		res := r.upgrader.upgrade(ctx, req)
		r.log.InfoContext(ctx, "upgrade result", "id", req.GetId(), "version", req.GetVersion(),
			"ok", res.GetOk(), "denied", res.GetDenied(), "error", res.GetError())
		// Once send returns true, sendLoop took the result and sends it
		// before it looks at Run's context again.
		reply(res)
		if res.GetOk() {
			r.stop(ErrUpgraded)
		}
	})
}
