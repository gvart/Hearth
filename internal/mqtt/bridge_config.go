// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Direction is which way a bridged prefix is forwarded.
type Direction string

// Directions.
const (
	In   Direction = "in"   // from the remote broker to the hub's
	Out  Direction = "out"  // from the hub's broker to the remote
	Both Direction = "both" // both ways
)

// BridgeTopic forwards every topic under Prefix on the hub's broker to the
// same topic under RemotePrefix on the remote broker, or back, or both.
type BridgeTopic struct {
	// Prefix is a topic prefix on the hub's broker, ending in '/', such as
	// sensors/.
	Prefix string `yaml:"prefix"`
	// RemotePrefix replaces Prefix on the remote broker (default Prefix).
	RemotePrefix string    `yaml:"remote_prefix"`
	Direction    Direction `yaml:"direction"`
}

// BridgeConfig is the bridge file: the remote broker the hub's broker
// connects to as a client, and the topics it forwards. It holds no secret:
// the password comes from HEARTH_MQTT_BRIDGE_PASSWORD or a 0600 file.
//
//	address: broker.lan:8883
//	ca_file: /etc/hearth/remote-ca.crt
//	client_id: hearth-hub1
//	username: hearth
//	password_file: /etc/hearth/mqtt-bridge.pass
//	topics:
//	  - prefix: sensors/
//	    remote_prefix: home/sensors/
//	    direction: both
type BridgeConfig struct {
	// Address is the remote broker's host:port. It is reached over TLS.
	Address string `yaml:"address"`
	// CAFile holds the CA certificates the remote broker's certificate is
	// checked against (default: the system's).
	CAFile string `yaml:"ca_file"`
	// ClientID is the hub's client ID on the remote broker (default
	// hearth-<hostname>). Each hub bridged to one broker needs its own.
	ClientID string `yaml:"client_id"`
	// Protocol is the MQTT version: 5 (default) or 4 (MQTT 3.1.1).
	Protocol byte   `yaml:"protocol"`
	Username string `yaml:"username"`
	// PasswordFile holds the password, on its first line. It must not be
	// readable by group or others.
	PasswordFile string `yaml:"password_file"`
	// CertFile and KeyFile are a client certificate and its key (0600).
	CertFile string        `yaml:"cert_file"`
	KeyFile  string        `yaml:"key_file"`
	Topics   []BridgeTopic `yaml:"topics"`

	// Password is the remote password, from PasswordFile or the
	// environment. It is never in the bridge file.
	Password string `yaml:"-"`
	// TLS is the client TLS configuration built from the file.
	TLS *tls.Config `yaml:"-"`
}

// LoadBridge reads the bridge file at path. password, if not empty (from
// HEARTH_MQTT_BRIDGE_PASSWORD), takes the place of password_file.
func LoadBridge(path, password string) (*BridgeConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read MQTT bridge file: %w", err)
	}
	c, err := ParseBridge(b)
	if err != nil {
		return nil, fmt.Errorf("MQTT bridge file %s: %w", path, err)
	}
	c.Password = password
	if c.Password == "" && c.PasswordFile != "" {
		p, err := readSecret(c.PasswordFile)
		if err != nil {
			return nil, fmt.Errorf("MQTT bridge password_file: %w", err)
		}
		c.Password = strings.TrimRight(strings.SplitN(string(p), "\n", 2)[0], "\r")
	}
	if c.Password != "" && c.Username == "" {
		return nil, errors.New("MQTT bridge: a password needs a username")
	}
	host, _, _ := net.SplitHostPort(c.Address)
	c.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, fmt.Errorf("MQTT bridge ca_file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("MQTT bridge ca_file %s: no PEM certificate", c.CAFile)
		}
		c.TLS.RootCAs = pool
	}
	if c.CertFile != "" {
		certPEM, err := os.ReadFile(c.CertFile)
		if err != nil {
			return nil, fmt.Errorf("MQTT bridge cert_file: %w", err)
		}
		keyPEM, err := readSecret(c.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("MQTT bridge key_file: %w", err)
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			// The error never quotes the key.
			return nil, fmt.Errorf("MQTT bridge cert_file and key_file: %w", err)
		}
		c.TLS.Certificates = []tls.Certificate{cert}
	}
	return c, nil
}

// readSecret reads a file that must be readable by its owner only.
func readSecret(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is accessible by group or others: chmod 600 it", path)
	}
	return os.ReadFile(path)
}

// ParseBridge parses and checks a bridge file.
func ParseBridge(b []byte) (*BridgeConfig, error) {
	var c BridgeConfig
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if _, port, err := net.SplitHostPort(c.Address); err != nil || port == "" {
		return nil, fmt.Errorf("address %q is not host:port", c.Address)
	}
	switch c.Protocol {
	case 0:
		c.Protocol = 5
	case 4, 5:
	default:
		return nil, fmt.Errorf("protocol must be 5 or 4 (MQTT 3.1.1), not %d", c.Protocol)
	}
	if c.ClientID == "" {
		host, _ := os.Hostname()
		c.ClientID = "hearth-" + host
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return nil, errors.New("cert_file and key_file go together")
	}
	if len(c.Topics) == 0 {
		return nil, errors.New("topics: at least one is required")
	}
	for i := range c.Topics {
		t := &c.Topics[i]
		if t.RemotePrefix == "" {
			t.RemotePrefix = t.Prefix
		}
		for _, p := range []string{t.Prefix, t.RemotePrefix} {
			if !strings.HasSuffix(p, "/") || strings.ContainsAny(p, "+#") || !validFilter(p+"#") {
				return nil, fmt.Errorf("topics[%d]: %q is not a topic prefix ending in '/', without wildcards", i, p)
			}
		}
		switch t.Direction {
		case In, Out, Both:
		default:
			return nil, fmt.Errorf("topics[%d]: direction must be in, out or both, not %q", i, t.Direction)
		}
	}
	return &c, nil
}
