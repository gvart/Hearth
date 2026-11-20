// SPDX-License-Identifier: AGPL-3.0-only

package talos

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// apidPort is the port of the Talos API (apid) when an endpoint names none.
const apidPort = "50000"

// maxConfigSize caps the talosconfig the hub reads.
const maxConfigSize = 1 << 20

// talosconfig is the part of a talosconfig file the hub reads.
type talosconfig struct {
	Context  string                   `yaml:"context"`
	Contexts map[string]contextConfig `yaml:"contexts"`
}

type contextConfig struct {
	Endpoints []string `yaml:"endpoints"`
	Nodes     []string `yaml:"nodes"`
	CA        string   `yaml:"ca"`
	Crt       string   `yaml:"crt"`
	Key       string   `yaml:"key"`
}

// Config is one context of a talosconfig, ready to connect with.
type Config struct {
	// Context is the name of the context used.
	Context string
	// Endpoints are host:port of the Talos API, tried in order.
	Endpoints []string
	// Nodes are the nodes read through the endpoint; the endpoints
	// themselves when the context names none.
	Nodes []string
	TLS   *tls.Config
}

// LoadConfig reads the talosconfig file at path and returns its context
// name, or its current context when name is "". nodes, when not empty,
// replaces the context's node list.
func LoadConfig(path, name string, nodes []string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("read talosconfig: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxConfigSize+1))
	if err != nil {
		return Config{}, fmt.Errorf("read talosconfig: %w", err)
	}
	if len(data) > maxConfigSize {
		return Config{}, errors.New("talosconfig is larger than 1 MiB")
	}
	var raw talosconfig
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return Config{}, fmt.Errorf("parse talosconfig %s: %w", path, err)
	}
	return parseConfig(raw, name, nodes)
}

func parseConfig(raw talosconfig, name string, nodes []string) (Config, error) {
	if name == "" {
		name = raw.Context
	}
	if name == "" {
		return Config{}, errors.New("talosconfig has no current context: name one with --talos-context")
	}
	c, ok := raw.Contexts[name]
	if !ok {
		return Config{}, fmt.Errorf("talosconfig has no context %q", name)
	}
	if len(c.Endpoints) == 0 {
		return Config{}, fmt.Errorf("talosconfig context %q has no endpoints", name)
	}
	tlsConf, err := clientTLS(c)
	if err != nil {
		return Config{}, fmt.Errorf("talosconfig context %q: %w", name, err)
	}
	out := Config{Context: name, TLS: tlsConf}
	for _, e := range c.Endpoints {
		out.Endpoints = append(out.Endpoints, withPort(e))
	}
	if len(nodes) == 0 {
		nodes = c.Nodes
	}
	if len(nodes) == 0 {
		nodes = c.Endpoints
	}
	for _, n := range nodes {
		if n = strings.TrimSpace(n); n != "" {
			out.Nodes = append(out.Nodes, n)
		}
	}
	return out, nil
}

// withPort adds the apid port to an endpoint that names none.
func withPort(e string) string {
	e = strings.TrimSpace(e)
	if _, _, err := net.SplitHostPort(e); err == nil {
		return e
	}
	return net.JoinHostPort(strings.Trim(e, "[]"), apidPort)
}

// clientTLS builds the mTLS config of a context: its client certificate,
// and its CA as the only root. TLS 1.3, as apid serves.
func clientTLS(c contextConfig) (*tls.Config, error) {
	ca, err := base64.StdEncoding.DecodeString(c.CA)
	if err != nil {
		return nil, errors.New("ca is not base64")
	}
	crt, err := base64.StdEncoding.DecodeString(c.Crt)
	if err != nil {
		return nil, errors.New("crt is not base64")
	}
	key, err := base64.StdEncoding.DecodeString(c.Key)
	if err != nil {
		return nil, errors.New("key is not base64")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("ca holds no certificate")
	}
	pair, err := tls.X509KeyPair(crt, key)
	if err != nil {
		return nil, errors.New("crt and key are not a certificate and its key")
	}
	return &tls.Config{
		RootCAs:      pool,
		Certificates: []tls.Certificate{pair},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2"},
	}, nil
}
