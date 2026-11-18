// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testKubeconfig has two contexts; the current one uses a token.
const testKubeconfig = `apiVersion: v1
kind: Config
current-context: lab
clusters:
- name: lab
  cluster:
    server: https://192.0.2.10:6443
    insecure-skip-tls-verify: true
- name: work
  cluster:
    server: https://work.example:6443
contexts:
- name: lab
  context: {cluster: lab, user: lab-admin}
- name: work
  context: {cluster: work, user: work-user}
users:
- name: lab-admin
  user: {token: lab-secret-token}
- name: work-user
  user: {token: work-secret-token}
`

func TestParseKubeconfig(t *testing.T) {
	kc, err := parseKubeconfig([]byte(testKubeconfig))
	if err != nil {
		t.Fatal(err)
	}
	if kc.context != "lab" || kc.server != "https://192.0.2.10:6443" {
		t.Errorf("context, server = %q, %q", kc.context, kc.server)
	}
	raw := string(kc.raw)
	if strings.Contains(raw, "work") {
		t.Errorf("reduced kubeconfig keeps another context:\n%s", raw)
	}
	if !strings.Contains(raw, "lab-secret-token") {
		t.Errorf("reduced kubeconfig lost the current context's credential:\n%s", raw)
	}
	if kc.user.Token != "lab-secret-token" || !kc.cluster.InsecureSkipTLSVerify {
		t.Errorf("user, cluster = %+v, %+v", kc.user, kc.cluster)
	}
	// The reduced kubeconfig parses to the same cluster.
	again, err := parseKubeconfig(kc.raw)
	if err != nil || again.server != kc.server {
		t.Errorf("reparse = %+v, %v", again, err)
	}
}

func TestParseKubeconfigRefuses(t *testing.T) {
	user := func(u string) string {
		return strings.Replace(testKubeconfig, "user: {token: lab-secret-token}", "user: "+u, 1)
	}
	tests := map[string]string{
		"garbage":            "{not yaml",
		"empty":              "",
		"no current context": strings.Replace(testKubeconfig, "current-context: lab", "", 1),
		"unknown context":    strings.Replace(testKubeconfig, "current-context: lab", "current-context: nope", 1),
		"exec plugin": user(`
    exec: {apiVersion: client.authentication.k8s.io/v1, command: /bin/sh, args: ["-c", "id"]}`),
		"auth provider":        user(`{auth-provider: {name: oidc}}`),
		"relative cert path":   user(`{client-certificate: certs/admin.crt, client-key: certs/admin.key}`),
		"missing cert file":    user(`{client-certificate: /nonexistent/admin.crt, client-key: /nonexistent/admin.key}`),
		"cert data not base64": user(`{client-certificate-data: "!!", client-key-data: "!!"}`),
		"token file":           user(`{tokenFile: /var/lib/hearth/hub/ca.key}`),
		"CA data not PEM": strings.Replace(testKubeconfig, "insecure-skip-tls-verify: true",
			"certificate-authority-data: bm90IHBlbQ==", 1),
		"not an http server": strings.Replace(testKubeconfig, "https://192.0.2.10:6443", "unix:///run/k8s.sock", 1),
		"no server":          strings.Replace(testKubeconfig, "server: https://192.0.2.10:6443", "server: \"\"", 1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseKubeconfig([]byte(raw)); !errors.Is(err, ErrInvalidKubeconfig) {
				t.Errorf("parseKubeconfig = %v, want ErrInvalidKubeconfig", err)
			}
		})
	}
}

// Talos, k3s and kind kubeconfigs authenticate with a client certificate;
// one named by file path is read and inlined, so every hub can use it.
func TestParseKubeconfigInlinesFiles(t *testing.T) {
	dir := t.TempDir()
	certPEM, keyPEM := selfSigned(t)
	write := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	cfg := fmt.Sprintf(`apiVersion: v1
kind: Config
current-context: k3s
clusters:
- name: k3s
  cluster: {server: "https://192.168.2.131:6443", certificate-authority: %q}
contexts:
- name: k3s
  context: {cluster: k3s, user: k3s}
users:
- name: k3s
  user: {client-certificate: %q, client-key: %q}
`, write("ca.crt", certPEM), write("admin.crt", certPEM), write("admin.key", keyPEM))
	kc, err := parseKubeconfig([]byte(cfg))
	if err != nil {
		t.Fatal(err)
	}
	raw := string(kc.raw)
	if strings.Contains(raw, dir) || !strings.Contains(raw, "client-key-data") || !strings.Contains(raw, "certificate-authority-data") {
		t.Errorf("reduced kubeconfig still names files or lacks the inlined data:\n%s", raw)
	}
	again, err := parseKubeconfig(kc.raw)
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	hc, err := again.httpClient()
	if err != nil {
		t.Fatal(err)
	}
	tr, _ := hc.Transport.(*authTransport)
	if tls := tr.next.(*http.Transport).TLSClientConfig; len(tls.Certificates) != 1 || tls.RootCAs == nil {
		t.Errorf("TLS config = %+v, want the client certificate and the CA", tls)
	}
}

func selfSigned(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "admin"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb})
}
