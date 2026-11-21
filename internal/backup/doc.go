// SPDX-License-Identifier: AGPL-3.0-only

// Package backup writes and restores encrypted backups of a hub: its CA, a
// consistent copy of its store, and its per-hub configuration.
//
// # File format
//
// A backup is a fixed header followed by a sequence of sealed chunks:
//
//	magic "HEARTHBK" | format (1) | argon2id time (4) | memory KiB (4) |
//	threads (1) | salt (16) | nonce prefix (7) | HMAC-SHA-256 of the above (32)
//
// Argon2id turns the passphrase into an AES-256 key and an HMAC key. The HMAC
// tells a wrong passphrase apart from a damaged body. Chunks hold 64 KiB of
// plaintext sealed with AES-256-GCM, with the whole header as additional data
// and a nonce of the prefix, a 4-byte chunk counter and a final-chunk flag (the
// STREAM construction), so reordered, dropped, truncated or appended chunks
// fail to open.
//
// The plaintext is a list of entries, each a 2-byte name length, the name, an
// 8-byte size and the content, ended by a zero name length. The first entry is
// manifest.json. Names come from a fixed set (see validName), so a backup can
// never write outside the data dir.
//
// Cluster state is never part of a backup: a restored hub has no peers to contact.
package backup
