// SPDX-License-Identifier: AGPL-3.0-only

package esphome

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/flynn/noise"
)

// The ESPHome native API frames protobuf messages over TCP in one of two
// ways (esphome/components/api/api_frame_helper_*.cpp):
//
//   - plaintext: 0x00, varint length, varint message type, the message;
//   - Noise (Noise_NNpsk0_25519_ChaChaPoly_SHA256, the PSK being the
//     device's API encryption key): 0x01, 16-bit big-endian length, the
//     frame. After the handshake each frame is one encrypted message: the
//     16-bit message type, the 16-bit message length and the message.
//
// The Noise handshake: the client sends an empty hello frame and its first
// handshake frame (a 0x00 status byte, then the Noise message); the device
// answers with its server hello (0x01, the chosen protocol, then its name and
// MAC, each NUL-terminated) and its handshake frame (0x00 and the Noise
// message), or a reject (0x01 and the reason) when the key is wrong.
const (
	preamblePlain = 0x00
	preambleNoise = 0x01
	// maxFrame caps a plaintext frame: a device's own limit is far lower,
	// and what it sends is not trusted.
	maxFrame = 64 << 10
	// noiseOverhead is the ChaCha20-Poly1305 tag of each encrypted frame.
	noiseOverhead = 16
	// maxNoisePayload is the longest message a Noise frame carries.
	maxNoisePayload = 0xFFFF - noiseOverhead - 4
	// macFailure is the reject reason of a device given the wrong key.
	macFailure = "Handshake MAC failure"
)

// noisePrologue is "NoiseAPIInit" followed by the 16-bit length and the
// content of the client's hello frame, which is empty.
var noisePrologue = []byte("NoiseAPIInit\x00\x00")

// noiseSuite is the cipher suite of Noise_NNpsk0_25519_ChaChaPoly_SHA256.
var noiseSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// Errors of the framing and the handshake.
var (
	// ErrInvalidKey is returned when the device rejects the encryption key.
	ErrInvalidKey = errors.New("the device rejected the encryption key")
	// ErrNeedsKey is returned when the device speaks Noise and no key was
	// given.
	ErrNeedsKey = errors.New("the device requires an encryption key")
	// ErrNotEncrypted is returned when a key was given and the device
	// speaks plaintext.
	ErrNotEncrypted = errors.New("the device does not use encryption: adopt it without a key")
	// ErrProtocol is returned for anything the framing does not allow.
	ErrProtocol = errors.New("esphome protocol error")
)

// packet is one message: its type and its protobuf encoding.
type packet struct {
	typ  uint16
	data []byte
}

// framer reads and writes packets on a connection. Writes are not safe for
// concurrent use; the session serializes them.
type framer interface {
	read() (packet, error)
	write(pkts ...packet) error
}

// plainFramer is the plaintext framing.
type plainFramer struct {
	r *bufio.Reader
	w io.Writer
}

func newPlainFramer(rw io.ReadWriter) *plainFramer {
	return &plainFramer{r: bufio.NewReader(rw), w: rw}
}

func (f *plainFramer) read() (packet, error) {
	return readPlain(f.r)
}

// readPlain reads one plaintext frame.
func readPlain(r *bufio.Reader) (packet, error) {
	b, err := r.ReadByte()
	if err != nil {
		return packet{}, err
	}
	switch b {
	case preamblePlain:
	case preambleNoise:
		return packet{}, ErrNeedsKey
	default:
		return packet{}, fmt.Errorf("%w: bad preamble 0x%02x", ErrProtocol, b)
	}
	size, err := binary.ReadUvarint(r)
	if err != nil {
		return packet{}, fmt.Errorf("%w: frame length: %w", ErrProtocol, err)
	}
	if size > maxFrame {
		return packet{}, fmt.Errorf("%w: frame of %d bytes", ErrProtocol, size)
	}
	typ, err := binary.ReadUvarint(r)
	if err != nil {
		return packet{}, fmt.Errorf("%w: message type: %w", ErrProtocol, err)
	}
	if typ > 0xFFFF {
		return packet{}, fmt.Errorf("%w: message type %d", ErrProtocol, typ)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(r, data); err != nil {
		return packet{}, err
	}
	return packet{typ: uint16(typ), data: data}, nil
}

func (f *plainFramer) write(pkts ...packet) error {
	_, err := f.w.Write(encodePlain(pkts...))
	return err
}

// encodePlain frames pkts for the plaintext protocol.
func encodePlain(pkts ...packet) []byte {
	var buf bytes.Buffer
	for _, p := range pkts {
		buf.WriteByte(preamblePlain)
		buf.Write(binary.AppendUvarint(nil, uint64(len(p.data))))
		buf.Write(binary.AppendUvarint(nil, uint64(p.typ)))
		buf.Write(p.data)
	}
	return buf.Bytes()
}

// readNoiseFrame reads one Noise frame, encrypted or not. A plaintext
// preamble means the device does not use encryption.
func readNoiseFrame(r *bufio.Reader) ([]byte, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:1]); err != nil {
		return nil, err
	}
	switch hdr[0] {
	case preambleNoise:
	case preamblePlain:
		return nil, ErrNotEncrypted
	default:
		return nil, fmt.Errorf("%w: bad preamble 0x%02x", ErrProtocol, hdr[0])
	}
	if _, err := io.ReadFull(r, hdr[1:]); err != nil {
		return nil, err
	}
	frame := make([]byte, binary.BigEndian.Uint16(hdr[1:]))
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	return frame, nil
}

// appendNoiseFrame appends frame with its header to dst.
func appendNoiseFrame(dst, frame []byte) []byte {
	dst = append(dst, preambleNoise)
	dst = binary.BigEndian.AppendUint16(dst, uint16(len(frame))) //nolint:gosec // callers keep frames under 64 KiB
	return append(dst, frame...)
}

// noiseFramer is the Noise framing, once the handshake is done.
type noiseFramer struct {
	r       *bufio.Reader
	w       io.Writer
	encrypt *noise.CipherState
	decrypt *noise.CipherState
}

func (f *noiseFramer) read() (packet, error) {
	frame, err := readNoiseFrame(f.r)
	if err != nil {
		return packet{}, err
	}
	return decryptPacket(f.decrypt, frame)
}

// decryptPacket opens one encrypted frame.
func decryptPacket(cs *noise.CipherState, frame []byte) (packet, error) {
	msg, err := cs.Decrypt(nil, nil, frame)
	if err != nil {
		return packet{}, fmt.Errorf("%w: cannot decrypt a frame", ErrProtocol)
	}
	if len(msg) < 4 {
		return packet{}, fmt.Errorf("%w: encrypted message of %d bytes", ErrProtocol, len(msg))
	}
	n := int(binary.BigEndian.Uint16(msg[2:4]))
	if n > len(msg)-4 {
		return packet{}, fmt.Errorf("%w: message length %d beyond its frame", ErrProtocol, n)
	}
	return packet{typ: binary.BigEndian.Uint16(msg[:2]), data: msg[4 : 4+n]}, nil
}

func (f *noiseFramer) write(pkts ...packet) error {
	out, err := encryptPackets(f.encrypt, pkts...)
	if err != nil {
		return err
	}
	_, err = f.w.Write(out)
	return err
}

// encryptPackets frames pkts, each encrypted with cs.
func encryptPackets(cs *noise.CipherState, pkts ...packet) ([]byte, error) {
	var out []byte
	for _, p := range pkts {
		if len(p.data) > maxNoisePayload {
			return nil, fmt.Errorf("%w: message of %d bytes", ErrProtocol, len(p.data))
		}
		msg := make([]byte, 4, 4+len(p.data))
		binary.BigEndian.PutUint16(msg[:2], p.typ)
		binary.BigEndian.PutUint16(msg[2:4], uint16(len(p.data))) //nolint:gosec // checked above
		msg = append(msg, p.data...)
		frame, err := cs.Encrypt(nil, nil, msg)
		if err != nil {
			return nil, fmt.Errorf("encrypt: %w", err)
		}
		out = appendNoiseFrame(out, frame)
	}
	return out, nil
}

// serverHello is what a device's server hello says of it.
type serverHello struct {
	name, mac string
}

// noiseHandshake runs the client's side of the handshake on rw with psk, the
// 32-byte key, and returns the framer for the session.
func noiseHandshake(rw io.ReadWriter, psk []byte) (*noiseFramer, serverHello, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noiseSuite, Pattern: noise.HandshakeNN, Initiator: true,
		Prologue: noisePrologue, PresharedKey: psk, PresharedKeyPlacement: 0,
	})
	if err != nil {
		return nil, serverHello{}, fmt.Errorf("noise handshake: %w", err)
	}
	msg, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, serverHello{}, fmt.Errorf("noise handshake: %w", err)
	}
	// The empty client hello, then the first handshake message.
	out := appendNoiseFrame(nil, nil)
	out = appendNoiseFrame(out, append([]byte{0x00}, msg...))
	if _, err := rw.Write(out); err != nil {
		return nil, serverHello{}, err
	}
	r := bufio.NewReader(rw)
	frame, err := readNoiseFrame(r)
	if err != nil {
		return nil, serverHello{}, err
	}
	hello, err := parseServerHello(frame)
	if err != nil {
		return nil, serverHello{}, err
	}
	frame, err = readNoiseFrame(r)
	if err != nil {
		return nil, hello, err
	}
	if len(frame) == 0 {
		return nil, hello, fmt.Errorf("%w: empty handshake frame", ErrProtocol)
	}
	if frame[0] != 0x00 {
		reason := string(frame[1:])
		if reason == macFailure {
			return nil, hello, ErrInvalidKey
		}
		return nil, hello, fmt.Errorf("%w: handshake rejected: %.64q", ErrProtocol, reason)
	}
	_, send, recv, err := hs.ReadMessage(nil, frame[1:])
	if err != nil {
		// The device's answer does not open with our key.
		return nil, hello, ErrInvalidKey
	}
	if send == nil || recv == nil {
		return nil, hello, fmt.Errorf("%w: handshake did not finish", ErrProtocol)
	}
	return &noiseFramer{r: r, w: rw, encrypt: send, decrypt: recv}, hello, nil
}

// parseServerHello reads a server hello frame: the chosen protocol, then the
// device's name and MAC, each NUL-terminated (older firmware sends neither).
func parseServerHello(frame []byte) (serverHello, error) {
	if len(frame) == 0 {
		return serverHello{}, fmt.Errorf("%w: empty server hello", ErrProtocol)
	}
	if frame[0] != 0x01 {
		return serverHello{}, fmt.Errorf("%w: unknown protocol %d chosen", ErrProtocol, frame[0])
	}
	var h serverHello
	rest := frame[1:]
	if i := bytes.IndexByte(rest, 0); i >= 0 {
		h.name = clip(string(rest[:i]))
		rest = rest[i+1:]
		if j := bytes.IndexByte(rest, 0); j >= 0 {
			h.mac = clip(string(rest[:j]))
		}
	}
	return h, nil
}
