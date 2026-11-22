// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"errors"
	"testing"
	"time"
)

// A member not migrated to schema 32 still creates and spends unnamed
// enrollment tokens, and refuses a named one.
func TestTokenNameBelowSchema(t *testing.T) {
	ctx := t.Context()
	s := openAtSchema(t, tokenNameSchema-1)
	exp := time.Now().Add(time.Minute)
	if err := s.Tokens().CreateNamed(ctx, "named", "garage-pi", nil, exp); !errors.Is(err, ErrSchemaTooOld) {
		t.Fatalf("CreateNamed = %v, want ErrSchemaTooOld", err)
	}
	if err := s.Tokens().Create(ctx, "plain", map[string]string{"room": "attic"}, exp); err != nil {
		t.Fatal(err)
	}
	got, err := s.Tokens().Consume(ctx, "plain", time.Now())
	if err != nil || got.Name != "" || got.Labels["room"] != "attic" {
		t.Fatalf("Consume = %+v, %v", got, err)
	}
}
