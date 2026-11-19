// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/gvart/hearth/internal/pki"
)

// HubURLFile holds the hub URL given to `hearth agent join`, as a single line.
const HubURLFile = "hub_url"

// ErrNotEnrolled is returned by Run when the data dir holds no complete identity.
var ErrNotEnrolled = errors.New("agent is not enrolled: run `hearth agent join` first")

// identity is what `hearth agent join` left in the data dir.
type identity struct {
	hubURL   *url.URL // the URL given to join
	hubs     []string // every known hub, in the order to try them; hubURL included
	deviceID string
	tls      *tls.Config
	// verifiedRoot is the CA that verified the last hub connected to.
	verifiedRoot atomic.Pointer[x509.Certificate]
}

// loadIdentity reads the agent key, certificate, hub CA, hub URL and hub list
// from dataDir and builds the mTLS client config: each hub is verified against
// the stored CA under the host name from its URL (the transport fills in
// ServerName per connection), and the agent certificate is presented.
func loadIdentity(dataDir string) (*identity, error) {
	for _, f := range []string{CertFile, KeyFile, CAFile, HubURLFile} {
		if _, err := os.Stat(filepath.Join(dataDir, f)); errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s is missing in %s", ErrNotEnrolled, f, dataDir)
		}
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dataDir, CertFile), filepath.Join(dataDir, KeyFile))
	if err != nil {
		return nil, fmt.Errorf("load agent certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse agent certificate: %w", err)
	}
	deviceID, err := pki.DeviceID(leaf)
	if err != nil {
		return nil, fmt.Errorf("agent certificate: %w", err)
	}
	caPEM, err := os.ReadFile(filepath.Join(dataDir, CAFile))
	if err != nil {
		return nil, fmt.Errorf("read hub CA: %w", err)
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, HubURLFile))
	if err != nil {
		return nil, fmt.Errorf("read hub URL: %w", err)
	}
	u, err := parseHubURL(strings.TrimSpace(string(raw)))
	if err != nil {
		return nil, err
	}
	known, err := readHubs(dataDir)
	if err != nil {
		return nil, err
	}

	// Every CA in the file: both while the hub CA is rotated.
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("parse hub CA: no certificate in " + CAFile)
	}
	id := &identity{
		hubURL:   u,
		hubs:     mergeHubs(known, []string{u.String()}),
		deviceID: deviceID,
	}
	id.tls = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{pair},
		// The CA that verified the hub decides which CAs a renewal may add.
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) > 0 {
				chain := cs.VerifiedChains[0]
				id.verifiedRoot.Store(chain[len(chain)-1])
			}
			return nil
		},
	}
	return id, nil
}

func parseHubURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("hub URL must be https://host[:port], got %q", s)
	}
	return u, nil
}

// writeHubURL stores the hub URL next to the identity.
func writeHubURL(dataDir string, u *url.URL) error {
	if err := os.WriteFile(filepath.Join(dataDir, HubURLFile), []byte(u.String()+"\n"), 0o600); err != nil {
		return fmt.Errorf("write hub URL: %w", err)
	}
	return nil
}
