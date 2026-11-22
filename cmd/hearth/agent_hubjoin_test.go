// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/cluster"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// The join the hub minted lands in the hub data dir, 0600, for `hearth hub
// --join-file`; a refusal writes nothing and says why.
func TestWriteHubJoin(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "hub")
	var out bytes.Buffer
	if err := writeHubJoin(dir, &agentv1.HubJoin{Refused: "the cluster has 5 storage members already"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "stays an agent") || !strings.Contains(out.String(), "5 storage") {
		t.Fatalf("output = %q", out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, cluster.JoinFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refusal wrote a join file: %v", err)
	}
	out.Reset()
	if err := writeHubJoin(dir, &agentv1.HubJoin{Url: "https://192.0.2.10:7443", Token: "hearthj1.s.f", Roles: []string{"storage", "master"}}, &out); err != nil { //nolint:gosec // G101: a fake join token
		t.Fatal(err)
	}
	path := filepath.Join(dir, cluster.JoinFileName)
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("join file: %v, mode %v; want 0600", err, fi.Mode())
	}
	j, err := cluster.ReadJoinFile(path)
	if err != nil || j.URL != "https://192.0.2.10:7443" || j.Token != "hearthj1.s.f" {
		t.Fatalf("join file = %+v, %v", j, err)
	}
	if strings.Contains(out.String(), "hearthj1.s.f") {
		t.Fatal("the join token was printed")
	}
}

// Without --hub-data-dir nothing is offered.
func TestHubOfferNeedsTheInstaller(t *testing.T) {
	var out bytes.Buffer
	if o := hubOffer(t.Context(), "", &out); o != nil || out.Len() != 0 {
		t.Fatalf("hubOffer without a hub data dir = %+v, %q", o, out.String())
	}
}
