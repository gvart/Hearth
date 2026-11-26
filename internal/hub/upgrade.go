// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// An admin upgrades a device's agent from its page or with `hearth device
// upgrade` (#347): the hub reads the SHA-256 of the agent's release archive
// from the release's checksums.txt and sends the agent an UpgradeRequest;
// the agent downloads the archive, checks it, swaps its binary and restarts.

// DefaultReleaseBaseURL is where releases are downloaded from, as
// <base>/<tag>/<asset>, as deploy/install.sh does.
const DefaultReleaseBaseURL = "https://github.com/gvart/hearth/releases/download"

const (
	// upgradeWait bounds how long the hub waits for an agent's upgrade: the
	// agent's own five minutes, and some.
	upgradeWait = 5*time.Minute + 30*time.Second
	// checksumsTimeout and maxChecksums bound the read of checksums.txt.
	checksumsTimeout = 30 * time.Second
	maxChecksums     = 1 << 20
)

// releaseTarget matches the os_arch of the release archives an agent may
// upgrade from (.goreleaser.yaml): no Windows zip.
var releaseTargetRE = regexp.MustCompile(`^(linux|darwin)_(amd64|arm64|armv[5-7])$`)

// releases reads the checksums of releases.
type releases struct {
	base   string
	client *http.Client
}

func newReleases(base string) *releases {
	if base == "" {
		base = DefaultReleaseBaseURL
	}
	return &releases{base: strings.TrimRight(base, "/"), client: &http.Client{Timeout: checksumsTimeout}}
}

// errReleaseUnreachable is a release whose checksums.txt the hub could not
// read.
var errReleaseUnreachable = errors.New("cannot read the release's checksums")

// asset is the URL of the release archive of version for target, and its
// SHA-256 from the release's checksums.txt.
func (rs *releases) asset(ctx context.Context, version, target string) (url, sum string, err error) {
	name := "hearth_" + strings.TrimPrefix(version, "v") + "_" + target + ".tar.gz"
	sums := rs.base + "/" + version + "/checksums.txt"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sums, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := rs.client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("%w: %s: %w (the hub must reach GitHub to upgrade agents)", errReleaseUnreachable, sums, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("%w: %s answered %s (is %s a release?)", errReleaseUnreachable, sums, resp.Status, version)
	}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, maxChecksums))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			if b, err := hex.DecodeString(fields[0]); err != nil || len(b) != 32 {
				return "", "", fmt.Errorf("%w: %s has no valid SHA-256 for %s", errReleaseUnreachable, sums, name)
			}
			return rs.base + "/" + version + "/" + name, strings.ToLower(fields[0]), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", "", fmt.Errorf("%w: %s: %w", errReleaseUnreachable, sums, err)
	}
	return "", "", fmt.Errorf("%w: %s lists no %s", errReleaseUnreachable, sums, name)
}

// compareRelease compares two release tags (releaseTag) as semantic
// versions: -1, 0 or 1. v0.0.1-rc.10 is newer than v0.0.1-rc.9, and
// v0.0.1 than both.
func compareRelease(a, b string) int {
	ac, ap, _ := strings.Cut(strings.TrimPrefix(a, "v"), "-")
	bc, bp, _ := strings.Cut(strings.TrimPrefix(b, "v"), "-")
	if c := compareIdents(strings.Split(ac, "."), strings.Split(bc, "."), true); c != 0 {
		return c
	}
	switch {
	case ap == bp:
		return 0
	case ap == "":
		return 1
	case bp == "":
		return -1
	}
	return compareIdents(strings.Split(ap, "."), strings.Split(bp, "."), false)
}

// compareIdents compares dot-separated identifiers as semver does: numbers
// numerically and below words, words in ASCII order, and a shorter list
// first when one is a prefix of the other.
func compareIdents(a, b []string, numeric bool) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		an, aerr := strconv.ParseUint(a[i], 10, 64)
		bn, berr := strconv.ParseUint(b[i], 10, 64)
		switch {
		case aerr == nil && berr == nil:
			if an != bn {
				if an < bn {
					return -1
				}
				return 1
			}
		case numeric || (aerr != nil && berr != nil):
			if c := strings.Compare(a[i], b[i]); c != 0 {
				return c
			}
		case aerr == nil:
			return -1
		default:
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

// AgentVersionJSON is a device's agent version next to the hub's.
type AgentVersionJSON struct {
	// Agent is the version the agent reports, Hub the hub's own.
	Agent string `json:"agent"`
	Hub   string `json:"hub"`
	// UpgradeAvailable is set when both are releases and the agent's is
	// older.
	UpgradeAvailable bool `json:"upgrade_available"`
	// RemoteUpgrade is set when the agent upgrades itself when asked. An
	// agent too old for that is upgraded once with the installer; one that
	// will not says why in NoRemoteUpgrade (a Kubernetes pod).
	RemoteUpgrade   bool   `json:"remote_upgrade"`
	NoRemoteUpgrade string `json:"no_remote_upgrade,omitempty"`
	// InstallCommand, on a device's own page, is the installer's one-liner
	// that upgrades an agent too old to upgrade itself.
	InstallCommand string `json:"install_command,omitempty"`
}

// deviceJSON is d as the API shows it, with its agent's version next to
// the hub's.
func (a *api) deviceJSON(d store.Device) DeviceJSON {
	out := deviceJSON(d)
	var f Facts
	if json.Unmarshal(d.Facts, &f) != nil || f.AgentVersion == "" {
		return out
	}
	v := &AgentVersionJSON{Agent: f.AgentVersion, Hub: a.version}
	hub, agent := releaseVersion(a.version), releaseVersion(f.AgentVersion)
	v.UpgradeAvailable = hub != "" && agent != "" && compareRelease(agent, hub) < 0
	if f.ProtocolMinor >= minUpgradeMinor {
		v.RemoteUpgrade = releaseTargetRE.MatchString(f.ReleaseTarget) && f.NoSelfUpgrade == ""
		v.NoRemoteUpgrade = f.NoSelfUpgrade
		if !v.RemoteUpgrade && v.NoRemoteUpgrade == "" {
			v.NoRemoteUpgrade = "there is no release of Hearth for this device's platform (" + f.ReleaseTarget + ")"
		}
	}
	out.AgentVersion = v
	return out
}

// UpgradeJSON asks for an agent upgrade, and answers it.
type UpgradeJSON struct {
	// Version is the release to upgrade to; empty means the hub's own.
	Version string `json:"version,omitempty"`
	// From is the version the agent ran before, in an answer.
	From string `json:"from,omitempty"`
}

// upgradeDevice serves POST /api/v1/devices/{id}/upgrade with an
// UpgradeJSON: the device's agent upgrades itself to the release named, or
// to the hub's own. It is the policy action device.upgrade, dangerous and
// only with the password entered again; refusals and failures are audited
// too. It answers once the agent put the new binary in place, before it
// restarts with it.
func (a *api) upgradeDevice(w http.ResponseWriter, r *http.Request) {
	if a.agents == nil {
		writeError(w, http.StatusNotFound, "not_found", "this hub does not reach agents")
		return
	}
	var body UpgradeJSON
	if r.ContentLength != 0 {
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
			return
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, "bad_request", `body must be {"version": "v0.1.0"}, or empty for the hub's version`)
			return
		}
	}
	version := body.Version
	if version == "" {
		version = releaseVersion(a.version)
		if version == "" {
			writeError(w, http.StatusConflict, "no_version", "this hub is a development build ("+a.version+"): name the release to upgrade to")
			return
		}
	}
	if releaseVersion(version) == "" {
		writeError(w, http.StatusBadRequest, "bad_request", "version must be a release tag such as v0.1.0")
		return
	}
	d, ok := a.device(w, r)
	if !ok {
		return
	}
	var f Facts
	_ = json.Unmarshal(d.Facts, &f)
	ctx, cancel := context.WithTimeout(r.Context(), upgradeWait)
	defer cancel()
	reauth := a.recentAuth(r)
	var res *agentv1.UpgradeResult
	err := a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.DeviceUpgrade, Target: d.ID,
		Detail: map[string]any{"version": version, "from": f.AgentVersion},
		Precheck: func(ctx context.Context) error {
			if err := reauth(ctx); err != nil {
				return err
			}
			return a.agents.CheckUpgrade(ctx, d.ID)
		},
	}, func(ctx context.Context) error {
		if !releaseTargetRE.MatchString(f.ReleaseTarget) {
			return fmt.Errorf("device %s: no release of Hearth for its platform (%q): %w", d.ID, f.ReleaseTarget, errNoSelfUpgrade)
		}
		url, sum, err := a.releases.asset(ctx, version, f.ReleaseTarget)
		if err != nil {
			return err
		}
		res, err = a.agents.Upgrade(ctx, d.ID, &agentv1.UpgradeRequest{Version: version, Url: url, Sha256: sum})
		switch {
		case err != nil:
			return err
		case res.GetDenied():
			return fmt.Errorf("device %s: the agent refused: %s: %w", d.ID, res.GetError(), policy.ErrBeyondCeiling)
		case !res.GetOk():
			return fmt.Errorf("%w: %s", errUpgradeFailed, res.GetError())
		}
		return nil
	})
	if err != nil {
		a.writeUpgradeError(w, r, err)
		return
	}
	a.log.InfoContext(ctx, "agent upgraded", "device_id", d.ID, "from", f.AgentVersion, "version", res.GetVersion())
	writeJSON(w, http.StatusOK, UpgradeJSON{Version: res.GetVersion(), From: f.AgentVersion})
}

// writeUpgradeError answers an upgrade that policy refused or that failed.
func (a *api) writeUpgradeError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, errReauthRequired):
		writeError(w, http.StatusForbidden, "reauth_required", "enter the admin password again to do this")
	case errors.Is(err, errAgentTooOld):
		writeError(w, http.StatusConflict, "agent_too_old", errAgentTooOld.Error())
	case errors.Is(err, policy.ErrBeyondCeiling):
		// The reason (a Kubernetes pod, an upgrade running) is no secret.
		writeError(w, http.StatusConflict, "cannot_upgrade", err.Error())
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, ErrAgentNotConnected):
		writeError(w, http.StatusConflict, "agent_not_connected", "the device's agent is not connected")
	case errors.Is(err, errReleaseUnreachable):
		writeError(w, http.StatusBadGateway, "release_unreachable", err.Error())
	case errors.Is(err, errUpgradeFailed):
		writeError(w, http.StatusBadGateway, "upgrade_failed", err.Error())
	case r.Context().Err() != nil:
		// The client went away.
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	default:
		a.log.ErrorContext(r.Context(), "upgrade an agent", "err", err)
		writeError(w, http.StatusBadGateway, "agent_error", err.Error())
	}
}
