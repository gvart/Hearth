// SPDX-License-Identifier: AGPL-3.0-only

package esphome

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// DefaultPort is the port of the ESPHome native API.
const DefaultPort = 6053

// Encryption modes of a connection.
const (
	EncryptionNoise     = "noise"
	EncryptionPlaintext = "plaintext"
)

// ErrBadConnection is returned for an address, key or password that cannot
// be used.
var ErrBadConnection = errors.New("invalid ESPHome connection")

// Connection is how the hub reaches one device. It is sealed before it is
// stored: the key and the password never reach the store in the clear.
type Connection struct {
	// Address is the device's IP and port.
	Address string `json:"address"`
	// Key is the device's API encryption key, base64 of 32 bytes; empty for
	// a device that speaks plaintext.
	Key string `json:"key,omitempty"`
	// Password is the API password of firmware older than ESPHome 2026.1,
	// for a plaintext device only.
	Password string `json:"password,omitempty"`
	// Control allows switch and button calls (esphome.call). A device is
	// adopted read-only unless the admin turns it on.
	Control bool `json:"control,omitempty"`
}

// encryption names how the connection is secured.
func (c Connection) encryption() string {
	if c.Key != "" {
		return EncryptionNoise
	}
	return EncryptionPlaintext
}

// normalize checks c and returns it in its stored form: an IP address with
// its port, a key in standard base64.
func (c Connection) normalize() (Connection, error) {
	addr, err := normalizeAddress(c.Address)
	if err != nil {
		return Connection{}, err
	}
	c.Address = addr
	c.Key = strings.TrimSpace(c.Key)
	if c.Key != "" {
		psk, err := decodeKey(c.Key)
		if err != nil {
			return Connection{}, err
		}
		c.Key = base64.StdEncoding.EncodeToString(psk)
		if c.Password != "" {
			return Connection{}, fmt.Errorf("%w: a password is for plaintext devices only; give the key alone", ErrBadConnection)
		}
	}
	if len(c.Password) > 255 {
		return Connection{}, fmt.Errorf("%w: password too long", ErrBadConnection)
	}
	return c, nil
}

// normalizeAddress accepts an IP address, with or without a port. Host names
// are refused: a hub built without cgo cannot resolve .local names, and a
// name that resolves elsewhere would send the key there.
func normalizeAddress(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("%w: the address is required", ErrBadConnection)
	}
	if ip, err := netip.ParseAddr(strings.Trim(s, "[]")); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), DefaultPort).String(), nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return "", fmt.Errorf("%w: the address must be an IP address, optionally with a port", ErrBadConnection)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "", fmt.Errorf("%w: the address must be an IP address, not a host name", ErrBadConnection)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 {
		return "", fmt.Errorf("%w: invalid port %q", ErrBadConnection, port)
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(p)).String(), nil
}

// decodeKey decodes an API encryption key: base64 of 32 bytes, as the
// device's YAML has it.
func decodeKey(s string) ([]byte, error) {
	psk, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(psk) != 32 {
		// Neither the key nor the decoder's error, which quotes it, goes
		// into the message.
		return nil, fmt.Errorf("%w: the encryption key must be the base64 of 32 bytes, as in the device's YAML", ErrBadConnection)
	}
	return psk, nil
}
