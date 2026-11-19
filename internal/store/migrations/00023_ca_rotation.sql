-- SPDX-License-Identifier: AGPL-3.0-only
-- Certificate fingerprints, which a hub CA rotation (#84) needs.
--
-- fingerprint is the SHA-256 of a certificate's DER encoding, lowercase hex
-- (pki.FingerprintHex), and ca_fp that of the CA certificate that issued it.
-- Both are NULL for a certificate recorded before this migration; a device's
-- are pinned while it is connected (trust on first use). A rotation renews
-- only certificates whose exact fingerprint is pinned: their serials and IDs
-- are no secret to whoever holds a copy of the database.
--
-- pin_mismatch_at is when a device presented another certificate with the
-- same serial and device ID as a pinned one: a certificate minted with the
-- CA key by someone else. It is never cleared.

-- +goose Up
ALTER TABLE certs ADD COLUMN fingerprint TEXT;
ALTER TABLE certs ADD COLUMN ca_fp TEXT;
ALTER TABLE certs ADD COLUMN pin_mismatch_at INTEGER;
ALTER TABLE hub_certs ADD COLUMN fingerprint TEXT;
ALTER TABLE hub_certs ADD COLUMN ca_fp TEXT;

-- +goose Down
ALTER TABLE hub_certs DROP COLUMN ca_fp;
ALTER TABLE hub_certs DROP COLUMN fingerprint;
ALTER TABLE certs DROP COLUMN pin_mismatch_at;
ALTER TABLE certs DROP COLUMN ca_fp;
ALTER TABLE certs DROP COLUMN fingerprint;
