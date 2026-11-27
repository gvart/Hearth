// SPDX-License-Identifier: AGPL-3.0-only

// Command sign writes FILE.sig, the Ed25519 signature agents check before
// they trust a release's checksums.txt (#359). The release workflow runs it:
//
//	HEARTH_RELEASE_SIGNING_KEY=<base64 seed> go run ./internal/release/cmd/sign dist/checksums.txt
//
// The key is the base64 of the 32-byte Ed25519 seed. It is never printed.
// The command refuses a key whose public half is not the one agents trust,
// so a wrong secret fails the release instead of shipping one no agent can
// upgrade to. It is not part of the hearth binary.
package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"

	"github.com/gvart/hearth/internal/release"
)

const keyEnv = "HEARTH_RELEASE_SIGNING_KEY"

func main() {
	trusted, err := release.TrustedKey()
	if err == nil {
		err = run(os.Args[1:], os.Getenv(keyEnv), trusted)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "sign:", err)
		os.Exit(1)
	}
}

// run signs args[0] with seed, the base64 Ed25519 seed whose public key must
// be trusted.
func run(args []string, seed string, trusted ed25519.PublicKey) error {
	if len(args) != 1 {
		return errors.New("usage: sign FILE (writes FILE" + release.SignatureSuffix + ")")
	}
	if seed == "" {
		return errors.New(keyEnv + " is empty: the release cannot be signed")
	}
	key, err := release.ParseSeed(seed)
	if err != nil {
		return fmt.Errorf("%s: %w", keyEnv, err)
	}
	if pub, _ := key.Public().(ed25519.PublicKey); !pub.Equal(trusted) {
		return errors.New(keyEnv + " is not the key whose public half agents trust (release.PublicKey)")
	}
	file := args[0]
	b, err := os.ReadFile(file) //nolint:gosec // the file to sign, named by the release workflow
	if err != nil {
		return err
	}
	sig := release.Sign(key, b)
	if err := release.Verify(trusted, b, sig); err != nil {
		return err
	}
	return os.WriteFile(file+release.SignatureSuffix, sig, 0o644) //nolint:gosec // a public release asset
}
