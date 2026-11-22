// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gvart/hearth/internal/cluster"
	"github.com/gvart/hearth/internal/pki"
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

// make-hub writes the join a device's page made, 0600, with the token from
// stdin; it refuses a token in argv, a bad URL or token, and a hub data dir
// that holds a hub already.
func TestAgentMakeHub(t *testing.T) {
	ca, err := pki.LoadOrCreateCA(t.TempDir(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	tok, err := pki.NewToken(ca.Cert())
	if err != nil {
		t.Fatal(err)
	}
	enc := tok.EncodeJoin()
	run := func(dir string, stdin string, args ...string) (string, error) {
		cmd := newAgentMakeHubCmd()
		var out bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&out)
		cmd.SetIn(strings.NewReader(stdin))
		cmd.SetArgs(append([]string{"--hub-data-dir", dir}, args...))
		err := cmd.ExecuteContext(t.Context())
		return out.String(), err
	}
	dir := filepath.Join(t.TempDir(), "hub")
	for _, tc := range []struct {
		name, stdin string
		args        []string
		want        string
	}{
		{"token in argv", "", []string{"https://192.0.2.10:7443", enc}, "never in argv"},
		{"no token", "", []string{"https://192.0.2.10:7443"}, "no join token"},
		{"plain http", enc + "\n", []string{"http://192.0.2.10:7443", "-"}, "https://"},
		{"not a join token", "hearth2.x.y.z\n", []string{"https://192.0.2.10:7443", "-"}, "the join token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(joinTokenEnvVar, "")
			if _, err := run(dir, tc.stdin, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(dir, cluster.JoinFileName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("a refusal wrote a join file: %v", err)
			}
		})
	}

	out, err := run(dir, enc+"\n", "https://192.0.2.10:7443", "-")
	if err != nil {
		// A test host with little memory or disk cannot be a hub: say so.
		if strings.Contains(err.Error(), "cannot be a hub") {
			t.Skipf("this host cannot be a hub: %v", err)
		}
		t.Fatal(err)
	}
	path := filepath.Join(dir, cluster.JoinFileName)
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("join file: %v, mode %v; want 0600", err, fi.Mode())
	}
	if j, err := cluster.ReadJoinFile(path); err != nil || j.URL != "https://192.0.2.10:7443" || j.Token != enc {
		t.Fatalf("join file = %+v, %v", j, err)
	}
	if strings.Contains(out, enc) {
		t.Fatal("the join token was printed")
	}

	// A hub that joined already keeps its data dir: no second join.
	if err := os.WriteFile(filepath.Join(dir, pki.CACertFile), []byte("ca"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := run(dir, enc+"\n", "https://192.0.2.10:7443", "-"); err == nil || !strings.Contains(err.Error(), "holds a hub already") {
		t.Fatalf("make-hub over a hub = %v, want a refusal", err)
	}
}
