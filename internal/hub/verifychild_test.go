// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// niceCheckArg runs the test binary as niceCheck.
const niceCheckArg = "__nice-check"

// TestMain lets the test binary stand in for hearth as the verifier child.
func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == VerifyChildArg {
		os.Exit(RunVerifyChild(os.Stdin, os.Stderr))
	}
	if len(os.Args) == 2 && os.Args[1] == niceCheckArg {
		os.Exit(niceCheck())
	}
	os.Exit(m.Run())
}

func TestChildVerifier(t *testing.T) {
	hash, err := hashPassword(testPassword, testArgon)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	verify := ChildVerifier(exe)
	tests := []struct {
		name, hash, password string
		want                 bool
		wantErr              bool
	}{
		{"right password", hash, testPassword, true, false},
		{"wrong password", hash, "nope-nope-nope", false, false},
		{"password with a newline", hash, testPassword + "\n", false, false},
		{"malformed hash", "$argon2id$garbage", testPassword, false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := verify(t.Context(), tt.hash, tt.password)
			if (err != nil) != tt.wantErr || ok != tt.want {
				t.Fatalf("verify = %v, %v; want %v, error %v", ok, err, tt.want, tt.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), tt.password) {
				t.Errorf("error %q contains the password", err)
			}
		})
	}
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if ok, err := verify(ctx, hash, testPassword); ok || !errors.Is(err, context.Canceled) {
			t.Fatalf("verify = %v, %v; want false, context.Canceled", ok, err)
		}
	})
	t.Run("missing binary", func(t *testing.T) {
		if ok, err := ChildVerifier(t.TempDir()+"/no-such-hearth")(t.Context(), hash, testPassword); ok || err == nil {
			t.Fatalf("verify = %v, %v; want an error", ok, err)
		}
	})
}

func TestRunVerifyChildMalformedRequest(t *testing.T) {
	var errOut bytes.Buffer
	if code := RunVerifyChild(strings.NewReader("not json"), &errOut); code != childError {
		t.Errorf("exit code = %d, want %d", code, childError)
	}
}
