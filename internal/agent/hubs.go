// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"connectrpc.com/connect"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// HubsFile holds the agent-facing URL of every known hub, one per line, in
// the order the agent tries them. Run rewrites it from each Welcome. HubURLFile
// stays the URL given to join and is always kept in the list.
const HubsFile = "hubs"

// mergeHubs returns the valid hub URLs from lists, in order, without
// duplicates. Invalid URLs are dropped: the agent connects only to https hubs.
func mergeHubs(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		for _, s := range l {
			u, err := parseHubURL(strings.TrimSpace(s))
			if err != nil {
				continue
			}
			if s := u.String(); !slices.Contains(out, s) {
				out = append(out, s)
			}
		}
	}
	return out
}

// readHubs returns the URLs in the hubs file, or none if there is no file.
// Invalid lines are skipped: the join URL alone is enough to reach the hub.
func readHubs(dataDir string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, HubsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read hub list: %w", err)
	}
	return mergeHubs(strings.Split(string(b), "\n")), nil
}

// writeHubs replaces the hubs file (0600) atomically, so a crash never leaves
// a partial list.
func writeHubs(dataDir string, hubs []string) error {
	if err := replaceFile(dataDir, HubsFile, []byte(strings.Join(hubs, "\n")+"\n")); err != nil {
		return fmt.Errorf("write hub list: %w", err)
	}
	return nil
}

// replaceFile replaces the file name in dataDir with data (0600) atomically.
func replaceFile(dataDir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dataDir, name+".tmp-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(dataDir, name))
	}
	return err
}

// notLeader returns the NotLeader detail of a hub's refusal, or nil if err is
// not one.
func notLeader(err error) *agentv1.NotLeader {
	var cerr *connect.Error
	if !errors.As(err, &cerr) || cerr.Code() != connect.CodeFailedPrecondition {
		return nil
	}
	for _, d := range cerr.Details() {
		if v, err := d.Value(); err == nil {
			if nl, ok := v.(*agentv1.NotLeader); ok {
				return nl
			}
		}
	}
	return nil
}
