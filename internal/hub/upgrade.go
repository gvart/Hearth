// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"regexp"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/release"
	"github.com/gvart/hearth/internal/store"
)

// An admin upgrades a device's agent from its page or with `hearth device
// upgrade` (#347): the hub sends the agent an UpgradeRequest naming only a
// release version; the agent finds the archive and its checksum in that
// official release itself, checks it, swaps its binary and restarts. The
// hub can so make an agent install an official release, and nothing else.

// upgradeWait bounds how long the hub waits for an agent's upgrade: the
// agent's own five minutes, and some.
const upgradeWait = 5*time.Minute + 30*time.Second

// releaseTarget matches the os_arch of the release archives an agent may
// upgrade from (.goreleaser.yaml): no Windows zip.
var releaseTargetRE = regexp.MustCompile(`^(linux|darwin)_(amd64|arm64|armv[5-7])$`)

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
	// that upgrades an agent too old to upgrade itself, or (PowerShell) an
	// agent on Windows, which does not upgrade itself.
	InstallCommand string `json:"install_command,omitempty"`
	// RolledBackFrom is the release an upgrade of the agent went to and was
	// rolled back from: the new binary reached no hub (#359).
	RolledBackFrom string `json:"rolled_back_from,omitempty"`
}

// deviceJSON is d as the API shows it, with its agent's version next to
// the hub's.
func (a *api) deviceJSON(d store.Device) DeviceJSON {
	out := deviceJSON(d)
	var f Facts
	if json.Unmarshal(d.Facts, &f) != nil || f.AgentVersion == "" {
		return out
	}
	v := &AgentVersionJSON{Agent: f.AgentVersion, Hub: a.version, RolledBackFrom: f.RolledBackFrom}
	hub, agent := releaseVersion(a.version), releaseVersion(f.AgentVersion)
	v.UpgradeAvailable = hub != "" && agent != "" && release.Compare(agent, hub) < 0
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
	ctx := r.Context()
	reauth := a.recentAuth(r)
	var res *agentv1.UpgradeResult
	detail := map[string]any{"version": version, "from": f.AgentVersion}
	err := a.policy.Do(ctx, policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.DeviceUpgrade, Target: d.ID,
		Detail: detail,
		Precheck: func(ctx context.Context) error {
			if err := reauth(ctx); err != nil {
				return err
			}
			return a.agents.CheckUpgrade(ctx, d.ID)
		},
	}, func(ctx context.Context) error {
		// The wait starts once policy allowed it, not while it was held.
		ctx, cancel := context.WithTimeout(ctx, upgradeWait)
		defer cancel()
		if !releaseTargetRE.MatchString(f.ReleaseTarget) {
			return fmt.Errorf("device %s: %w", d.ID, &refusedUpgrade{Why: "there is no release of Hearth for its platform (" + f.ReleaseTarget + ")"})
		}
		var err error
		res, err = a.agents.Upgrade(ctx, d.ID, &agentv1.UpgradeRequest{Version: version})
		// The outcome's audit entry shows the archive the agent chose and
		// its checksum: detail is the request's, written after fn returns.
		if res.GetUrl() != "" {
			detail["url"] = res.GetUrl()
		}
		if res.GetSha256() != "" {
			detail["sha256"] = res.GetSha256()
		}
		switch {
		case err != nil:
			return err
		case res.GetDenied():
			return fmt.Errorf("device %s: %w", d.ID, &refusedUpgrade{Why: "the agent refused: " + res.GetError()})
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
	var refused *refusedUpgrade
	switch {
	case errors.Is(err, errReauthRequired):
		writeError(w, http.StatusForbidden, "reauth_required", "enter the admin password again to do this")
	case errors.Is(err, errAgentTooOld):
		writeError(w, http.StatusConflict, "agent_too_old", agentTooOld)
	case errors.As(err, &refused):
		// The reason (a Kubernetes pod, an upgrade running) is no secret.
		writeError(w, http.StatusConflict, "cannot_upgrade", refused.Why)
	case errors.Is(err, policy.ErrBeyondCeiling):
		// Forwarded from another master: only its message is left.
		writeError(w, http.StatusConflict, "cannot_upgrade", err.Error())
	case errors.Is(err, policy.ErrDenied):
		writeError(w, http.StatusForbidden, "forbidden", "denied by policy")
	case errors.Is(err, ErrAgentNotConnected):
		writeError(w, http.StatusConflict, "agent_not_connected", "the device's agent is not connected")
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
