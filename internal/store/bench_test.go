// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openBench(b *testing.B) *Store {
	b.Helper()
	s, err := Open(b.Context(), filepath.Join(b.TempDir(), "hearth.db"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = s.Close() })
	return s
}

// BenchmarkMarkSeen measures the heartbeat hot path: one MarkSeen per beat.
func BenchmarkMarkSeen(b *testing.B) {
	ctx := b.Context()
	s := openBench(b)
	now := time.Now()
	if err := s.Devices().Upsert(ctx, Device{ID: "pi", FirstSeen: now, LastSeen: now}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := range b.N {
		if _, _, err := s.Devices().MarkSeen(ctx, "pi", now.Add(time.Duration(i)*time.Millisecond)); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkMarkSeenCodec measures what a replicated log adds to MarkSeen
// besides consensus itself: encoding and decoding the command.
func BenchmarkMarkSeenCodec(b *testing.B) {
	cmd := MarkSeen{ID: "pi", Now: time.Now().UnixMilli()}
	for range b.N {
		buf, err := EncodeCommand(cmd)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := DecodeCommand(buf); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuditAppend measures the write every policy decision makes.
func BenchmarkAuditAppend(b *testing.B) {
	ctx := b.Context()
	s := openBench(b)
	e := AuditEntry{TS: time.Now(), ActorKind: "agent", ActorID: "pi", Action: "agent.heartbeat", Decision: "allow"}
	b.ResetTimer()
	for range b.N {
		if _, err := s.Audit().Append(ctx, e); err != nil {
			b.Fatal(err)
		}
	}
}
