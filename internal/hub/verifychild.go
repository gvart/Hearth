// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
)

// VerifyChildArg is the sole argument that runs the hearth binary as a
// password verifier child (RunVerifyChild) instead of its CLI.
const VerifyChildArg = "__verify-password"

// lowestPriority is the highest nice value.
const lowestPriority = 19

// PasswordVerifier reports whether password matches the argon2id hash.
type PasswordVerifier func(ctx context.Context, hash, password string) (bool, error)

// verifyInProcess is the PasswordVerifier used when Config.VerifyPassword is nil.
func verifyInProcess(_ context.Context, hash, password string) (bool, error) {
	return verifyPassword(hash, password)
}

type verifyRequest struct {
	Hash     string `json:"hash"`
	Password string `json:"password"`
}

// Exit codes of the verifier child.
const (
	childMatch    = 0
	childMismatch = 1
	childError    = 2
)

// ChildVerifier verifies each password in a child process, exe run with
// VerifyChildArg, that drops itself to the lowest CPU priority first. A hub
// under a hard CPU quota (a container limit) shares that quota with the
// child, and the kernel then runs the hub's own threads, Raft heartbeats among
// them, ahead of the hash. The hash and password go over stdin, never argv.
// Cancelling ctx kills the child.
func ChildVerifier(exe string) PasswordVerifier {
	return func(ctx context.Context, hash, password string) (bool, error) {
		in, err := json.Marshal(verifyRequest{Hash: hash, Password: password}) //nolint:gosec // G117: goes only to our own child's stdin
		if err != nil {
			return false, fmt.Errorf("verify password: %w", err)
		}
		cmd := exec.CommandContext(ctx, exe, VerifyChildArg)
		cmd.Stdin = bytes.NewReader(in)
		cmd.Env = append(cmd.Environ(), "GOMAXPROCS=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err = cmd.Run()
		var exit *exec.ExitError
		switch {
		case err == nil:
			return true, nil
		case ctx.Err() != nil:
			return false, ctx.Err()
		case errors.As(err, &exit) && exit.ExitCode() == childMismatch:
			return false, nil
		default:
			return false, fmt.Errorf("verify password in child: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
	}
}

// RunVerifyChild is the verifier child: it reads a request from in, lowers
// its own CPU priority, verifies, and returns the exit code. Errors go to errOut; they never
// include the password.
func RunVerifyChild(in io.Reader, errOut io.Writer) int {
	var req verifyRequest
	if err := json.NewDecoder(io.LimitReader(in, 64<<10)).Decode(&req); err != nil {
		_, _ = fmt.Fprintln(errOut, "read request: malformed JSON")
		return childError
	}
	if err := lowerPriority(); err != nil {
		// Still verify: this is no worse than verifying in the hub.
		_, _ = fmt.Fprintln(errOut, "lower priority:", err)
	}
	ok, err := verifyPassword(req.Hash, req.Password)
	switch {
	case err != nil:
		_, _ = fmt.Fprintln(errOut, err)
		return childError
	case !ok:
		return childMismatch
	}
	return childMatch
}
