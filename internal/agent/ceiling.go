// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"

	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// The ceiling the hub manages (#346). The agent's flags are its own ceiling,
// which the hub cannot take away; the hub may add to it with a CeilingConfig,
// which the agent saves in CeilingFile and loads at startup, before any hub
// connects. The effective ceiling is the union of the two. An agent started
// with --local-ceiling ignores the hub's: its flags are then its whole
// ceiling. Whatever the hub sets, the agent enforces the effective ceiling
// itself on every request.

// CeilingFile holds the ceiling the hub last set for this device, as
// protojson of agentv1.Ceiling (0600).
const CeilingFile = "ceiling.json"

// maxCeilingFile bounds what is read of CeilingFile.
const maxCeilingFile = 64 << 10

// ceilingOf is c as a Ceiling.
func ceilingOf(c *agentv1.Ceiling) Ceiling {
	return Ceiling{
		Exec: slices.Clone(c.GetExec()), Restart: slices.Clone(c.GetRestart()), Probe: c.GetProbe(),
		Logs: slices.Clone(c.GetLogs()), Shell: c.GetShell(), Scan: slices.Clone(c.GetScan()),
		NetEdges: c.GetNetEdges(), Docker: c.GetDocker(), DockerRead: c.GetDockerRead(),
	}
}

// union is what c or o allows.
func (c Ceiling) union(o Ceiling) Ceiling {
	merge := func(a, b []string) []string {
		out := slices.Clone(a)
		for _, e := range b {
			if !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
		return out
	}
	return Ceiling{
		Exec: merge(c.Exec, o.Exec), Restart: merge(c.Restart, o.Restart), Probe: c.Probe || o.Probe,
		Logs: merge(c.Logs, o.Logs), Shell: c.Shell || o.Shell, Scan: merge(c.Scan, o.Scan),
		NetEdges: c.NetEdges || o.NetEdges, Docker: c.Docker || o.Docker, DockerRead: c.DockerRead || o.DockerRead,
	}
}

// equal reports whether c and o allow the same, entry for entry.
func (c Ceiling) equal(o Ceiling) bool {
	return slices.Equal(c.Exec, o.Exec) && slices.Equal(c.Restart, o.Restart) && c.Probe == o.Probe &&
		slices.Equal(c.Logs, o.Logs) && c.Shell == o.Shell && slices.Equal(c.Scan, o.Scan) &&
		c.NetEdges == o.NetEdges && c.Docker == o.Docker && c.DockerRead == o.DockerRead
}

// checkHubCeiling checks a ceiling the hub set, entry by entry
// (policy.CheckHubCeiling): one bad entry refuses all of it. A capability
// this platform's agent lacks (a shell on Windows, network edges off Linux)
// is dropped.
func checkHubCeiling(c Ceiling) (Ceiling, error) {
	if err := policy.CheckHubCeiling(c.proto()); err != nil {
		return Ceiling{}, err
	}
	c.Shell = c.Shell && ShellSupported
	c.NetEdges = c.NetEdges && NetEdgesSupported
	return c, nil
}

// readCeilingFile returns the ceiling saved in dataDir, checked, or the
// zero Ceiling if there is none.
func readCeilingFile(dataDir string) (Ceiling, error) {
	f, err := os.Open(filepath.Join(dataDir, CeilingFile))
	if errors.Is(err, os.ErrNotExist) {
		return Ceiling{}, nil
	}
	if err != nil {
		return Ceiling{}, fmt.Errorf("read %s: %w", CeilingFile, err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxCeilingFile+1))
	if err != nil {
		return Ceiling{}, fmt.Errorf("read %s: %w", CeilingFile, err)
	}
	if len(b) > maxCeilingFile {
		return Ceiling{}, fmt.Errorf("read %s: larger than %d bytes", CeilingFile, maxCeilingFile)
	}
	var pc agentv1.Ceiling
	if err := protojson.Unmarshal(b, &pc); err != nil {
		return Ceiling{}, fmt.Errorf("read %s: %w", CeilingFile, err)
	}
	c, err := checkHubCeiling(ceilingOf(&pc))
	if err != nil {
		return Ceiling{}, fmt.Errorf("read %s: %w", CeilingFile, err)
	}
	return c, nil
}

// writeCeilingFile replaces the ceiling saved in dataDir (0600) atomically.
func writeCeilingFile(dataDir string, c Ceiling) error {
	b, err := protojson.Marshal(c.proto())
	if err != nil {
		return fmt.Errorf("write %s: %w", CeilingFile, err)
	}
	if err := replaceFile(dataDir, CeilingFile, append(b, '\n')); err != nil {
		return fmt.Errorf("write %s: %w", CeilingFile, err)
	}
	return nil
}

// ceilings is the agent's ceiling: its flags, the hub's part, and their
// union, which every request reads. The union is swapped whole, so a reader
// on any goroutine sees one ceiling or the next, never a mix.
type ceilings struct {
	local  Ceiling
	locked bool
	// hub is the hub's part; only the session's receiving goroutine sets it.
	hub Ceiling
	eff atomic.Pointer[Ceiling]
}

func newCeilings(local, hub Ceiling, locked bool) *ceilings {
	c := &ceilings{local: local, locked: locked}
	if locked {
		hub = Ceiling{}
	}
	c.hub = hub
	eff := local.union(hub)
	c.eff.Store(&eff)
	return c
}

// get is the effective ceiling.
func (c *ceilings) get() Ceiling { return *c.eff.Load() }

// setHub makes hub the hub's part and reports whether that changed it.
func (c *ceilings) setHub(hub Ceiling) bool {
	if c.locked || hub.equal(c.hub) {
		return false
	}
	c.hub = hub
	eff := c.local.union(hub)
	c.eff.Store(&eff)
	return true
}
