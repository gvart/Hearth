// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"

	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

// MinPasswordLen is the shortest admin password accepted.
const MinPasswordLen = 8

const (
	argonKeyLen  = 32
	argonSaltLen = 16
)

// argonParams are argon2id cost parameters. They are encoded in each hash, so
// verification always uses the parameters the hash was made with.
type argonParams struct {
	time    uint32
	memory  uint32 // KiB
	threads uint8
}

// defaultArgon is RFC 9106's second recommended option, with less memory so
// small hubs such as a Raspberry Pi cope, and one lane: x/crypto/argon2 runs a
// goroutine per lane, and on a single-core hub four of them starve the hub's
// cluster goroutines long enough for its peers to suspect it (#94). Parallelism does
// not add to an attacker's cost, and hashing is memory bound, so one lane is
// barely slower on a multi-core hub. Hashes made with p=4 still verify.
var defaultArgon = argonParams{time: 3, memory: 64 * 1024, threads: 1}

var b64 = base64.RawStdEncoding

// HashPassword returns an argon2id PHC string for password.
func HashPassword(password string) (string, error) {
	return hashPassword(password, defaultArgon)
}

func hashPassword(password string, p argonParams) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.memory, p.time, p.threads, b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// verifyPassword reports whether password matches the PHC string encoded.
func verifyPassword(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errors.New("verify password: unsupported hash format")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errors.New("verify password: unsupported argon2 version")
	}
	var p argonParams
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.time, &p.threads); err != nil {
		return false, fmt.Errorf("verify password: parameters: %w", err)
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("verify password: salt: %w", err)
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil || len(want) == 0 {
		return false, errors.New("verify password: bad key")
	}
	got := argon2.IDKey([]byte(password), salt, p.time, p.memory, p.threads, uint32(len(want))) //nolint:gosec // len(want) is a 32-byte key read from our own hash
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// CheckAdminPassword returns nil if password is the admin password stored in
// st, and otherwise an error that never holds the password. It is for the
// CLI on the hub host: the hub itself checks through its verification gate.
func CheckAdminPassword(ctx context.Context, st *store.Store, password string) error {
	if password == "" {
		return errNoPassword
	}
	hash, err := st.Admin().PasswordHash(ctx)
	if errors.Is(err, store.ErrNotFound) {
		return errors.New("admin password not set: run `hearth admin set-password` first")
	}
	if err != nil {
		return fmt.Errorf("read admin password: %w", err)
	}
	ok, err := verifyPassword(hash, password)
	if err != nil {
		return err
	}
	if !ok {
		return errWrongPassword
	}
	return nil
}

// SetAdminPassword validates and hashes password and stores it as the admin
// password, through policy, as the local admin actorID. It ends all sessions.
func SetAdminPassword(ctx context.Context, st *store.Store, pol *policy.Engine, actorID, password string) error {
	return setAdminPassword(ctx, st, pol, actorID, password, defaultArgon)
}

func setAdminPassword(ctx context.Context, st *store.Store, pol *policy.Engine, actorID, password string, p argonParams) error {
	if len(password) < MinPasswordLen {
		return fmt.Errorf("admin password must be at least %d characters", MinPasswordLen)
	}
	hash, err := hashPassword(password, p)
	if err != nil {
		return err
	}
	return pol.Do(ctx, policy.Request{
		ActorKind: policy.ActorAdmin,
		ActorID:   actorID,
		Action:    policy.AdminSetPassword,
	}, func(ctx context.Context) error {
		return st.Admin().SetPasswordHash(ctx, hash)
	})
}
