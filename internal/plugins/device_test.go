// SPDX-License-Identifier: AGPL-3.0-only

package plugins

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/policy"
)

// buildLamp builds the go-lamp example into a new directory, 0700, and
// returns its manifest, pointed at it, and its SHA-256.
func buildLamp(t *testing.T) (Manifest, string) {
	t.Helper()
	dir := tempDir(t)
	bin := filepath.Join(dir, "lamp")
	build := exec.Command("go", "build", "-o", bin, "../../examples/plugins/go-lamp") //nolint:gosec // a fixed build of the example
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	if err := os.Chmod(bin, 0o700); err != nil { //nolint:gosec // an executable
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join("..", "..", "examples", "plugins", "go-lamp", "plugin.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := ParseManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	m.Command, m.Dir = bin, dir
	prog, err := os.ReadFile(bin) //nolint:gosec // the test's build
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(prog)
	return m, hex.EncodeToString(sum[:])
}

func TestRunOnce(t *testing.T) {
	m, pin := buildLamp(t)
	res, err := RunOnce(t.Context(), m, pin, CommandRequest{Command: "turn_on", Device: "lamp"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Output != "lamp is on" {
		t.Errorf("output = %q", res.Output)
	}

	t.Run("wrong hash", func(t *testing.T) {
		_, err := RunOnce(t.Context(), m, strings.Repeat("0", 64), CommandRequest{Command: "turn_on"}, Options{})
		if !errors.Is(err, ErrPinMismatch) {
			t.Fatalf("err = %v, want ErrPinMismatch", err)
		}
	})
	t.Run("undeclared command", func(t *testing.T) {
		_, err := RunOnce(t.Context(), m, pin, CommandRequest{Command: "explode"}, Options{})
		if !errors.Is(err, policy.ErrDenied) {
			t.Fatalf("err = %v, want ErrDenied", err)
		}
	})
	t.Run("bad args", func(t *testing.T) {
		_, err := RunOnce(t.Context(), m, pin, CommandRequest{Command: "turn_on", Args: []byte(`[1]`)}, Options{})
		if !errors.Is(err, ErrBadRequest) {
			t.Fatalf("err = %v, want ErrBadRequest", err)
		}
	})
	t.Run("changed program", func(t *testing.T) {
		if err := os.WriteFile(m.Command, []byte("#!/bin/sh\necho pwned\n"), 0o700); err != nil { //nolint:gosec // an executable
			t.Fatal(err)
		}
		_, err := RunOnce(t.Context(), m, pin, CommandRequest{Command: "turn_on"}, Options{})
		if !errors.Is(err, ErrPinMismatch) {
			t.Fatalf("err = %v, want ErrPinMismatch", err)
		}
	})
}

func TestParseManifest(t *testing.T) {
	tests := []struct {
		name, yaml string
		ok         bool
	}{
		{"valid", "protocol: 1\nname: lamp\nversion: 1\ncapabilities: [command]\ncommands: [{name: on, class: safe}]\n", true},
		{"env", "protocol: 1\nname: lamp\nenv: {TOKEN: x}\n", false},
		{"unknown field", "protocol: 1\nname: lamp\nshell: true\n", false},
		{"bad class", "protocol: 1\nname: lamp\ncapabilities: [command]\ncommands: [{name: on, class: root}]\n", false},
		{"bad name", "protocol: 1\nname: ../lamp\n", false},
		{"protocol", "protocol: 2\nname: lamp\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseManifest([]byte(tt.yaml))
			if tt.ok != (err == nil) {
				t.Fatalf("ParseManifest = %v, want ok %v", err, tt.ok)
			}
		})
	}
}

func TestValidSHA256(t *testing.T) {
	good := strings.Repeat("ab", 32)
	for s, want := range map[string]bool{
		good: true, strings.ToUpper(good): false, good[:63]: false, good + "0": false,
		"../" + good[3:]: false, strings.Repeat("zz", 32): false,
	} {
		if ValidSHA256(s) != want {
			t.Errorf("ValidSHA256(%q) = %v", s, !want)
		}
	}
}
