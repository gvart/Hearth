// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/release"
)

// An agent upgrades itself when its hub asks (UpgradeRequest, #347). The hub
// names only a version: the agent builds the archive's URL itself, from its
// compiled-in release base and its own platform, reads the SHA-256 from the
// same release's checksums.txt, checks the archive against it, puts the new
// hearth in place of its own executable by a rename in the same directory,
// keeping the old one as <exe>.prev, answers, and exits with ExitUpgraded
// for systemd (Restart=always) or launchd (KeepAlive) to start the new one.
// A hub can so make an agent install an official release, and nothing else.
//
// Until the new binary is welcomed by a hub, a marker in the data directory
// (upgradePendingFile) counts its starts: after maxUpgradeStarts without a
// Welcome, it puts <exe>.prev back and exits for the old binary to start.

// ReleaseBaseURL is where an agent downloads releases from, as
// <base>/<tag>/<asset>, as deploy/install.sh does.
const ReleaseBaseURL = "https://github.com/gvart/hearth/releases/download"

// releaseBaseEnv overrides ReleaseBaseURL, for the end-to-end tests only.
// Whoever sets an agent's environment owns its host already.
const releaseBaseEnv = "HEARTH_RELEASE_BASE_URL"

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
	// the hearth extracted from it, and maxUpgradeUnpacked all the bytes
	// read out of the archive. A release archive is some 30 MB.
	maxUpgradeArchive  = 128 << 20
	maxUpgradeBinary   = 256 << 20
	maxUpgradeUnpacked = 512 << 20
	// maxChecksums caps the read of a release's checksums.txt.
	maxChecksums = 1 << 20
	// upgradeVersionTimeout bounds `<new binary> version`.
	upgradeVersionTimeout = 15 * time.Second
	// maxRedirects bounds the redirects of a download (GitHub sends one).
	maxRedirects = 5
)

// upgrader replaces the agent's executable.
type upgrader struct {
	// exe is the executable to replace, resolved when the agent starts:
	// once replaced, os.Executable may name the new file or the old.
	exe string
	// dataDir holds the upgrade-pending marker.
	dataDir string
	// current is the version this agent runs.
	current string
	// refusal, if set, is why this agent does not upgrade itself.
	refusal string
	// target is the release archive's os_arch.
	target string
	// base is the release base URL, without a trailing slash.
	base string
	// client downloads the release: a plain client, never the mTLS one,
	// which would show the device certificate to the download server. It
	// follows https redirects only.
	client                             *http.Client
	maxArchive, maxBinary, maxUnpacked int64
	timeout                            time.Duration
	// pending is set while the upgrade-pending marker exists: the next
	// Welcome removes it.
	pending bool
}

// newUpgrader is the upgrader of the executable exe ("" for the running
// one) of an agent running version current, with its marker in dataDir,
// refusing as selfUpgradeRefusal says.
func newUpgrader(exe, dataDir, current string, localCeiling bool, getenv func(string) string) *upgrader {
	base := ReleaseBaseURL
	if b := getenv(releaseBaseEnv); b != "" {
		base = b
	}
	u := &upgrader{
		dataDir: dataDir, current: current,
		base:       strings.TrimRight(base, "/"),
		client:     &http.Client{Transport: http.DefaultTransport, CheckRedirect: httpsRedirects},
		maxArchive: maxUpgradeArchive, maxBinary: maxUpgradeBinary, maxUnpacked: maxUpgradeUnpacked,
		timeout: upgradeTimeout,
		refusal: selfUpgradeRefusal(runtime.GOOS, localCeiling, getenv),
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

// httpsRedirects follows a download's redirects only while they stay https:
// GitHub sends release assets on to its object storage.
func httpsRedirects(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refused a redirect to %s: only https", req.URL.Redacted())
	}
	if len(via) >= maxRedirects {
		return fmt.Errorf("more than %d redirects", maxRedirects)
	}
	return nil
}

// selfUpgradeRefusal says why an agent on goos, with --local-ceiling if
// localCeiling and the environment getenv reads, does not upgrade itself;
// "" if it does.
func selfUpgradeRefusal(goos string, localCeiling bool, getenv func(string) string) string {
	switch {
	case getenv("KUBERNETES_SERVICE_HOST") != "":
		return "this agent runs in a Kubernetes pod: upgrade its image instead"
	case getenv("HEARTH_NO_SELF_UPGRADE") != "":
		return "self-upgrade is turned off on this device (HEARTH_NO_SELF_UPGRADE)"
	case localCeiling:
		return "this agent runs with --local-ceiling, so the hub cannot change it: upgrade it on the device with the installer"
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
	version := req.GetVersion()
	switch {
	case u.refusal != "":
		res.Denied, res.Error = true, u.refusal
		return res
	case !release.Tag.MatchString(version):
		res.Denied, res.Error = true, "the upgrade names no release version"
		return res
	case release.Tag.MatchString(u.current) && release.Compare(version, u.current) < 0:
		res.Denied, res.Error = true, fmt.Sprintf("%s is older than the %s this agent runs: downgrades are refused", version, u.current)
		return res
	}
	ctx, cancel := context.WithTimeout(ctx, u.timeout)
	defer cancel()
	name := "hearth_" + strings.TrimPrefix(version, "v") + "_" + u.target + ".tar.gz"
	res.Url = u.base + "/" + version + "/" + name
	sum, err := u.checksum(ctx, version, name)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Sha256 = sum
	got, err := u.install(ctx, version, res.GetUrl(), sum)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Ok, res.Version = true, got
	return res
}

// get fetches url, answering an error unless the server says 200 OK.
func (u *upgrader) get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w (the device must reach GitHub to upgrade itself; "+
			"a local release mirror is not supported yet)", url, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("download %s: the server answered %s", url, resp.Status)
	}
	return resp, nil
}

// checksum is the SHA-256 of the asset name that the checksums.txt of
// release version lists.
func (u *upgrader) checksum(ctx context.Context, version, name string) (string, error) {
	url := u.base + "/" + version + "/checksums.txt"
	resp, err := u.get(ctx, url)
	if err != nil {
		return "", fmt.Errorf("%w (is %s a release?)", err, version)
	}
	defer func() { _ = resp.Body.Close() }()
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxChecksums))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			if b, err := hex.DecodeString(fields[0]); err != nil || len(b) != sha256.Size {
				return "", fmt.Errorf("%s has no valid SHA-256 for %s", url, name)
			}
			return strings.ToLower(fields[0]), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", fmt.Errorf("read %s: %w", url, err)
	}
	return "", fmt.Errorf("%s lists no %s: no release of %s for this device's platform", url, name, version)
}

// install downloads the archive at url, checks it against sum and puts its
// binary in place, and returns the version that binary reports.
func (u *upgrader) install(ctx context.Context, version, url, sum string) (string, error) {
	archive, err := os.CreateTemp("", "hearth-upgrade-*.tar.gz")
	if err != nil {
		return "", fmt.Errorf("create a temporary file: %w", err)
	}
	defer func() { _ = archive.Close(); _ = os.Remove(archive.Name()) }()
	if err := u.download(ctx, url, sum, archive); err != nil {
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
	if err := u.extract(ctx, archive, next); err != nil {
		return "", err
	}
	if err := next.Chmod(0o755); err != nil {
		return "", fmt.Errorf("make the new binary executable: %w", err)
	}
	if err := next.Sync(); err != nil {
		return "", fmt.Errorf("write the new binary: %w", err)
	}
	if err := next.Close(); err != nil {
		return "", fmt.Errorf("write the new binary: %w", err)
	}
	got, err := binaryVersion(ctx, next.Name())
	if err != nil {
		return "", err
	}
	if got != version {
		return "", fmt.Errorf("the archive's binary reports version %q, not %s", got, version)
	}

	prev := u.exe + ".prev"
	if err := os.Remove(prev); err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("remove the old backup %s: %w", prev, err)
	}
	if err := os.Link(u.exe, prev); err != nil {
		return "", fmt.Errorf("keep the current binary as %s: %w", prev, err)
	}
	// The marker goes first: a new binary that never reaches a hub is
	// rolled back, and one written over a binary still the old changes
	// nothing.
	if err := writePending(u.dataDir, pendingUpgrade{From: u.current, To: version}); err != nil {
		return "", fmt.Errorf("write the upgrade marker: %w", err)
	}
	if err := os.Rename(next.Name(), u.exe); err != nil {
		_ = os.Remove(filepath.Join(u.dataDir, upgradePendingFile))
		return "", fmt.Errorf("put the new binary in place: %w", err)
	}
	keep = true
	syncDir(dir)
	return got, nil
}

// syncDir flushes dir's entries, so a rename in it survives a power cut. It
// is best effort: the rename is done either way.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}

// download writes the archive at url to f, checking its size and SHA-256.
func (u *upgrader) download(ctx context.Context, url, sum string, f *os.File) error {
	resp, err := u.get(ctx, url)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.ContentLength > u.maxArchive {
		return fmt.Errorf("the release archive is larger than %d MiB: refused", u.maxArchive>>20)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, u.maxArchive+1))
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	if n > u.maxArchive {
		return fmt.Errorf("the release archive is larger than %d MiB: refused", u.maxArchive>>20)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sum {
		return fmt.Errorf("checksum mismatch: the archive's SHA-256 is %s, the release's checksums.txt says %s; nothing was changed", got, sum)
	}
	return nil
}

// errUnpackedTooLarge ends the read of an archive that unpacks to more than
// its cap.
var errUnpackedTooLarge = errors.New("unpacked too large")

// unpackReader reads at most left bytes from r, and nothing once ctx is done.
type unpackReader struct {
	ctx  context.Context //nolint:containedctx // it bounds the reads of one extract
	r    io.Reader
	left int64
}

func (ur *unpackReader) Read(p []byte) (int, error) {
	if err := ur.ctx.Err(); err != nil {
		return 0, err
	}
	if ur.left <= 0 {
		return 0, errUnpackedTooLarge
	}
	if int64(len(p)) > ur.left {
		p = p[:ur.left]
	}
	n, err := ur.r.Read(p)
	ur.left -= int64(n)
	return n, err
}

// extract copies the hearth file of the tar.gz archive to out, reading no
// more than maxUnpacked bytes out of it, until ctx is done.
func (u *upgrader) extract(ctx context.Context, archive io.Reader, out io.Writer) error {
	gz, err := gzip.NewReader(bufio.NewReader(archive))
	if err != nil {
		return fmt.Errorf("read the archive: %w", err)
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(&unpackReader{ctx: ctx, r: gz, left: u.maxUnpacked})
	unpackErr := func(what string, err error) error {
		if errors.Is(err, errUnpackedTooLarge) {
			return fmt.Errorf("the archive unpacks to more than %d MiB: refused", u.maxUnpacked>>20)
		}
		return fmt.Errorf("%s: %w", what, err)
	}
	for {
		hd, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("the archive holds no hearth binary")
		}
		if err != nil {
			return unpackErr("read the archive", err)
		}
		if strings.TrimPrefix(hd.Name, "./") != "hearth" || hd.Typeflag != tar.TypeReg {
			continue
		}
		if hd.Size > u.maxBinary {
			return fmt.Errorf("the archive's hearth is larger than %d MiB: refused", u.maxBinary>>20)
		}
		n, err := io.Copy(out, io.LimitReader(tr, u.maxBinary+1))
		if err != nil {
			return unpackErr("extract hearth", err)
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

// upgradePendingFile, in the data directory, marks an upgrade whose new
// binary no hub has welcomed yet.
const upgradePendingFile = "upgrade-pending"

// maxUpgradeStarts is how many times an upgraded agent may start without
// being welcomed by a hub before it puts the previous binary back.
const maxUpgradeStarts = 3

// pendingUpgrade is the content of upgradePendingFile.
type pendingUpgrade struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Starts int    `json:"starts"`
}

func writePending(dataDir string, p pendingUpgrade) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return replaceFile(dataDir, upgradePendingFile, b)
}

// rolledBack is the error of Run when the upgraded binary never reached a
// hub and the previous one is back in place: it is ErrUpgraded, for the
// service manager to start that one.
type rolledBack struct{ from, to string }

func (e *rolledBack) Error() string {
	return fmt.Sprintf("the upgraded agent (%s) reached no hub in %d starts; the previous binary (%s) is back, "+
		"exiting so the service manager starts it", e.to, maxUpgradeStarts, e.from)
}

func (e *rolledBack) Is(target error) bool { return target == ErrUpgraded }

// started counts a start of the agent while an upgrade is pending. After
// maxUpgradeStarts it moves <exe>.prev back over the executable and returns
// a rolledBack error: the caller exits for the service manager to start the
// previous binary.
func (u *upgrader) started(ctx context.Context, log *slog.Logger) error {
	if u == nil || u.dataDir == "" {
		return nil
	}
	path := filepath.Join(u.dataDir, upgradePendingFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	var p pendingUpgrade
	if err == nil {
		err = json.Unmarshal(b, &p)
	}
	if err != nil {
		log.WarnContext(ctx, "ignoring an unreadable upgrade marker", "path", path, "err", err)
		_ = os.Remove(path)
		return nil
	}
	p.Starts++
	if p.Starts <= maxUpgradeStarts {
		if err := writePending(u.dataDir, p); err != nil {
			log.WarnContext(ctx, "count the start of the upgraded agent", "err", err)
		}
		u.pending = true
		log.InfoContext(ctx, "upgraded agent starting; waiting for a hub to welcome it",
			"from", p.From, "version", p.To, "start", strconv.Itoa(p.Starts)+"/"+strconv.Itoa(maxUpgradeStarts))
		return nil
	}
	_ = os.Remove(path)
	if u.exe == "" {
		return nil
	}
	if err := os.Rename(u.exe+".prev", u.exe); err != nil {
		log.ErrorContext(ctx, "the upgraded agent reached no hub, and the previous binary cannot be put back", "err", err)
		return nil
	}
	syncDir(filepath.Dir(u.exe))
	log.ErrorContext(ctx, "the upgraded agent reached no hub; put the previous binary back", "from", p.From, "version", p.To)
	return &rolledBack{from: p.From, to: p.To}
}

// welcomed confirms a pending upgrade: a hub welcomed the new binary.
func (u *upgrader) welcomed(ctx context.Context, log *slog.Logger) {
	if u == nil || !u.pending {
		return
	}
	if err := os.Remove(filepath.Join(u.dataDir, upgradePendingFile)); err != nil && !errors.Is(err, os.ErrNotExist) {
		log.WarnContext(ctx, "remove the upgrade marker", "err", err)
		return
	}
	u.pending = false
	log.InfoContext(ctx, "upgrade confirmed: a hub welcomed the new binary")
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
		r.log.InfoContext(ctx, "upgrade result", "id", req.GetId(), "version", req.GetVersion(), "url", res.GetUrl(),
			"sha256", res.GetSha256(), "ok", res.GetOk(), "denied", res.GetDenied(), "error", res.GetError())
		// Once send returns true, sendLoop took the result and sends it
		// before it looks at Run's context again.
		reply(res)
		if res.GetOk() {
			r.stop(ErrUpgraded)
		}
	})
}
