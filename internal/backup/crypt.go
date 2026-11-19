// SPDX-License-Identifier: AGPL-3.0-only

package backup

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	magic          = "HEARTHBK"
	formatVersion  = 1
	saltLen        = 16
	noncePrefixLen = 7
	macLen         = sha256.Size
	// macOffset is the length of the header fields the MAC covers.
	macOffset = len(magic) + 1 + 4 + 4 + 1 + saltLen + noncePrefixLen
	headerLen = macOffset + macLen
	chunkSize = 64 << 10
	keyLen    = 32

	// Limits on the KDF cost read from a file, checked before running it, so
	// a crafted header cannot exhaust the host's memory.
	maxKDFTime    = 16
	maxKDFMemory  = 1 << 20 // KiB: 1 GiB
	maxKDFThreads = 16
)

// Errors of reading a backup.
var (
	// ErrWrongPassphrase means the passphrase does not open this backup. A
	// damaged header looks the same.
	ErrWrongPassphrase = errors.New("wrong passphrase, or the backup's header is damaged")
	// ErrCorrupt means the backup was damaged or cut short.
	ErrCorrupt = errors.New("the backup is corrupted or truncated")
	// ErrNotBackup means the file is not a Hearth backup.
	ErrNotBackup = errors.New("not a Hearth backup")
	// ErrUnsupportedFormat means a newer Hearth wrote the backup.
	ErrUnsupportedFormat = errors.New("backup format not supported by this binary")
)

// kdfParams are argon2id cost parameters, stored in each backup.
type kdfParams struct {
	time    uint32
	memory  uint32 // KiB
	threads uint8
}

// defaultKDF matches the admin password hash: RFC 9106's second recommended
// option with less memory, and one lane, because backups run next to a live
// hub and several lanes starve Raft on a single-core one (#94).
func defaultKDF() kdfParams { return kdfParams{time: 3, memory: 64 * 1024, threads: 1} }

func (p kdfParams) valid() bool {
	return p.time >= 1 && p.time <= maxKDFTime && p.memory >= 8 && p.memory <= maxKDFMemory &&
		p.threads >= 1 && p.threads <= maxKDFThreads
}

// header is the clear-text start of a backup file.
type header struct {
	kdf    kdfParams
	salt   [saltLen]byte
	prefix [noncePrefixLen]byte
}

// fields encodes everything the MAC covers.
func (h header) fields() []byte {
	b := make([]byte, 0, headerLen)
	b = append(b, magic...)
	b = append(b, formatVersion)
	b = binary.BigEndian.AppendUint32(b, h.kdf.time)
	b = binary.BigEndian.AppendUint32(b, h.kdf.memory)
	b = append(b, h.kdf.threads)
	b = append(b, h.salt[:]...)
	return append(b, h.prefix[:]...)
}

// keys derives the encryption and MAC keys.
func (h header) keys(passphrase string) (enc, mac []byte) {
	k := argon2.IDKey([]byte(passphrase), h.salt[:], h.kdf.time, h.kdf.memory, h.kdf.threads, 2*keyLen)
	return k[:keyLen], k[keyLen:]
}

func headerMAC(key, fields []byte) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write(fields) // a hash never fails
	return m.Sum(nil)
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("backup cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("backup cipher: %w", err)
	}
	return aead, nil
}

// chunkNonce is the nonce of chunk counter. The key is unique to the file (a
// random salt), so a counter never repeats under one key.
func chunkNonce(prefix [noncePrefixLen]byte, counter uint32, final bool) []byte {
	n := make([]byte, 0, noncePrefixLen+5)
	n = append(n, prefix[:]...)
	n = binary.BigEndian.AppendUint32(n, counter)
	if final {
		return append(n, 1)
	}
	return append(n, 0)
}

// sealer encrypts what is written to it into chunks on w. Close seals the
// final chunk; without it the backup is unreadable.
type sealer struct {
	w       io.Writer
	aead    cipher.AEAD
	prefix  [noncePrefixLen]byte
	aad     []byte
	counter uint32
	buf     []byte
	out     []byte
}

// newSealer writes the header for a new random salt and returns the sealer.
func newSealer(w io.Writer, passphrase string, kdf kdfParams) (*sealer, error) {
	h := header{kdf: kdf}
	if _, err := rand.Read(h.salt[:]); err != nil {
		return nil, fmt.Errorf("backup salt: %w", err)
	}
	if _, err := rand.Read(h.prefix[:]); err != nil {
		return nil, fmt.Errorf("backup nonce: %w", err)
	}
	enc, macKey := h.keys(passphrase)
	aead, err := newAEAD(enc)
	if err != nil {
		return nil, err
	}
	fields := h.fields()
	full := append(fields, headerMAC(macKey, fields)...)
	if _, err := w.Write(full); err != nil {
		return nil, fmt.Errorf("write backup header: %w", err)
	}
	return &sealer{
		w: w, aead: aead, prefix: h.prefix, aad: full,
		buf: make([]byte, 0, chunkSize), out: make([]byte, 0, chunkSize+aead.Overhead()),
	}, nil
}

// Write implements io.Writer. A full chunk is held back until more data
// arrives, so the last chunk is always the one Close seals as final.
func (s *sealer) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if len(s.buf) == chunkSize {
			if err := s.flush(false); err != nil {
				return 0, err
			}
		}
		k := min(chunkSize-len(s.buf), len(p))
		s.buf = append(s.buf, p[:k]...)
		p = p[k:]
	}
	return n, nil
}

// Close seals the final chunk.
func (s *sealer) Close() error { return s.flush(true) }

func (s *sealer) flush(final bool) error {
	if s.counter == 1<<32-1 {
		return errors.New("write backup: too large")
	}
	s.out = s.aead.Seal(s.out[:0], chunkNonce(s.prefix, s.counter, final), s.buf, s.aad)
	if _, err := s.w.Write(s.out); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	s.counter++
	s.buf = s.buf[:0]
	return nil
}

// opener decrypts the chunks of a backup. Read returns io.EOF only after the
// final chunk opened, so a reader that reaches EOF has seen the whole file.
type opener struct {
	r       *bufio.Reader
	aead    cipher.AEAD
	prefix  [noncePrefixLen]byte
	aad     []byte
	counter uint32
	buf     []byte
	plain   []byte
	done    bool
}

// newOpener reads and checks the header of r.
func newOpener(r io.Reader, passphrase string) (*opener, error) {
	br := bufio.NewReaderSize(r, chunkSize)
	full := make([]byte, headerLen)
	n, err := io.ReadFull(br, full)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, fmt.Errorf("read backup header: %w", err)
	}
	if err != nil {
		// Cut short: a start of the magic is a truncated backup.
		if n < len(magic) && strings.HasPrefix(magic, string(full[:n])) ||
			n >= len(magic) && string(full[:len(magic)]) == magic {
			return nil, ErrCorrupt
		}
		return nil, ErrNotBackup
	}
	if string(full[:len(magic)]) != magic {
		return nil, ErrNotBackup
	}
	rest := full[len(magic):]
	if rest[0] != formatVersion {
		return nil, fmt.Errorf("%w: format %d, this binary reads format %d", ErrUnsupportedFormat, rest[0], formatVersion)
	}
	h := header{kdf: kdfParams{
		time:    binary.BigEndian.Uint32(rest[1:]),
		memory:  binary.BigEndian.Uint32(rest[5:]),
		threads: rest[9],
	}}
	copy(h.salt[:], rest[10:])
	copy(h.prefix[:], rest[10+saltLen:])
	if !h.kdf.valid() {
		return nil, ErrCorrupt
	}
	enc, macKey := h.keys(passphrase)
	if !hmac.Equal(headerMAC(macKey, full[:macOffset]), full[macOffset:]) {
		return nil, ErrWrongPassphrase
	}
	aead, err := newAEAD(enc)
	if err != nil {
		return nil, err
	}
	return &opener{
		r: br, aead: aead, prefix: h.prefix, aad: full,
		buf: make([]byte, chunkSize+aead.Overhead()),
	}, nil
}

// Read implements io.Reader.
func (o *opener) Read(p []byte) (int, error) {
	for len(o.plain) == 0 {
		if o.done {
			return 0, io.EOF
		}
		if err := o.next(); err != nil {
			return 0, err
		}
	}
	n := copy(p, o.plain)
	o.plain = o.plain[n:]
	return n, nil
}

// next opens the next chunk. The last chunk of the file must carry the final
// flag and no other may, which is what detects a cut at a chunk boundary.
func (o *opener) next() error {
	n, err := io.ReadFull(o.r, o.buf)
	final := false
	switch {
	case errors.Is(err, io.EOF):
		return ErrCorrupt // the final chunk is missing
	case errors.Is(err, io.ErrUnexpectedEOF):
		final = true
	case err != nil:
		return fmt.Errorf("read backup: %w", err)
	default:
		_, perr := o.r.Peek(1)
		switch {
		case errors.Is(perr, io.EOF):
			final = true
		case perr != nil:
			return fmt.Errorf("read backup: %w", perr)
		}
	}
	plain, err := o.aead.Open(o.buf[:0], chunkNonce(o.prefix, o.counter, final), o.buf[:n], o.aad)
	if err != nil {
		return ErrCorrupt
	}
	o.plain, o.done = plain, final
	o.counter++
	return nil
}
