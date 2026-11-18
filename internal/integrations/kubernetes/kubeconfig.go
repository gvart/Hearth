// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"go.yaml.in/yaml/v3"
)

// ErrInvalidKubeconfig is returned for a kubeconfig the hub cannot use.
var ErrInvalidKubeconfig = errors.New("invalid kubeconfig")

// kubeconfigFile is the part of the kubeconfig format the hub supports.
// Credential plugins (exec, auth-provider) are parsed only to refuse them.
type kubeconfigFile struct {
	APIVersion     string         `yaml:"apiVersion,omitempty"`
	Kind           string         `yaml:"kind,omitempty"`
	CurrentContext string         `yaml:"current-context"`
	Clusters       []namedCluster `yaml:"clusters"`
	Contexts       []namedContext `yaml:"contexts"`
	Users          []namedUser    `yaml:"users"`
}

type namedCluster struct {
	Name    string    `yaml:"name"`
	Cluster kcCluster `yaml:"cluster"`
}

type kcCluster struct {
	Server                   string `yaml:"server"`
	CertificateAuthority     string `yaml:"certificate-authority,omitempty"`
	CertificateAuthorityData string `yaml:"certificate-authority-data,omitempty"`
	InsecureSkipTLSVerify    bool   `yaml:"insecure-skip-tls-verify,omitempty"`
	TLSServerName            string `yaml:"tls-server-name,omitempty"`
	ProxyURL                 string `yaml:"proxy-url,omitempty"`
}

type namedContext struct {
	Name    string `yaml:"name"`
	Context struct {
		Cluster string `yaml:"cluster"`
		User    string `yaml:"user"`
	} `yaml:"context"`
}

type namedUser struct {
	Name string `yaml:"name"`
	User kcUser `yaml:"user"`
}

type kcUser struct {
	ClientCertificate     string     `yaml:"client-certificate,omitempty"`
	ClientCertificateData string     `yaml:"client-certificate-data,omitempty"`
	ClientKey             string     `yaml:"client-key,omitempty"`
	ClientKeyData         string     `yaml:"client-key-data,omitempty"`
	Token                 string     `yaml:"token,omitempty"`
	TokenFile             string     `yaml:"tokenFile,omitempty"`
	Username              string     `yaml:"username,omitempty"`
	Password              string     `yaml:"password,omitempty"`
	Exec                  *yaml.Node `yaml:"exec,omitempty"`
	AuthProvider          *yaml.Node `yaml:"auth-provider,omitempty"`
}

// kubeconfig is a parsed, validated kubeconfig reduced to its current
// context, with every credential inline.
type kubeconfig struct {
	// raw is the reduced kubeconfig, which is what the hub stores (sealed).
	raw []byte
	// context and server name the current context and its API server.
	context, server string
	cluster         kcCluster
	user            kcUser
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidKubeconfig, fmt.Sprintf(format, args...))
}

// parseKubeconfig parses raw and keeps only its current context, so the hub
// stores no credential it does not use. Certificate and key files named by
// absolute path are read on the hub host now and inlined: the stored
// kubeconfig must work on every hub of a cluster. It refuses credential
// plugins (exec, auth-provider), which would run programs on the hub, and
// tokenFile, which would send a hub file's contents to the API server.
func parseKubeconfig(raw []byte) (*kubeconfig, error) {
	var f kubeconfigFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, invalid("%v", err)
	}
	if f.CurrentContext == "" {
		return nil, invalid("no current-context")
	}
	var ctx *namedContext
	for i := range f.Contexts {
		if f.Contexts[i].Name == f.CurrentContext {
			ctx = &f.Contexts[i]
		}
	}
	if ctx == nil {
		return nil, invalid("context %q not found", f.CurrentContext)
	}
	var cluster *kcCluster
	for i := range f.Clusters {
		if f.Clusters[i].Name == ctx.Context.Cluster {
			cluster = &f.Clusters[i].Cluster
		}
	}
	if cluster == nil || cluster.Server == "" {
		return nil, invalid("the current context has no cluster server")
	}
	user := kcUser{}
	for i := range f.Users {
		if f.Users[i].Name == ctx.Context.User {
			user = f.Users[i].User
		}
	}
	switch {
	case user.Exec != nil || user.AuthProvider != nil:
		return nil, invalid("exec and auth-provider credentials are not supported; use a client certificate or a token")
	case user.TokenFile != "":
		return nil, invalid("tokenFile is not supported; put the token inline")
	}
	var err error
	if cluster.CertificateAuthorityData, err = inline(cluster.CertificateAuthority, cluster.CertificateAuthorityData); err != nil {
		return nil, err
	}
	if user.ClientCertificateData, err = inline(user.ClientCertificate, user.ClientCertificateData); err != nil {
		return nil, err
	}
	if user.ClientKeyData, err = inline(user.ClientKey, user.ClientKeyData); err != nil {
		return nil, err
	}
	cluster.CertificateAuthority, user.ClientCertificate, user.ClientKey = "", "", ""

	kc := &kubeconfig{context: f.CurrentContext, server: cluster.Server, cluster: *cluster, user: user}
	if _, err := kc.httpClient(); err != nil { // validates the server URL and the TLS material
		return nil, err
	}
	reduced := kubeconfigFile{
		APIVersion: "v1", Kind: "Config", CurrentContext: f.CurrentContext,
		Clusters: []namedCluster{{Name: ctx.Context.Cluster, Cluster: *cluster}},
		Contexts: []namedContext{*ctx},
		Users:    []namedUser{{Name: ctx.Context.User, User: user}},
	}
	if kc.raw, err = yaml.Marshal(reduced); err != nil {
		return nil, invalid("%v", err)
	}
	return kc, nil
}

// inline returns data, or the base64 of the file at path if data is empty.
func inline(path, data string) (string, error) {
	if data != "" || path == "" {
		return data, nil
	}
	if !filepath.IsAbs(path) {
		return "", invalid("%s: file paths must be absolute (or inline the -data field)", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", invalid("read %s: %v", path, err)
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func decodeData(field, data string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, invalid("%s is not base64", field)
	}
	return b, nil
}

// httpClient returns a client for the API server, with the kubeconfig's TLS
// settings and credentials. It has no overall timeout: watches are long
// lived, and every request carries a context.
func (k *kubeconfig) httpClient() (*http.Client, error) {
	u, err := url.Parse(k.cluster.Server)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, invalid("server %q is not an http(s) URL", k.cluster.Server)
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		ServerName:         k.cluster.TLSServerName,
		InsecureSkipVerify: k.cluster.InsecureSkipTLSVerify, //nolint:gosec // the kubeconfig's insecure-skip-tls-verify, set by its owner
	}
	if k.cluster.CertificateAuthorityData != "" {
		pem, err := decodeData("certificate-authority-data", k.cluster.CertificateAuthorityData)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, invalid("certificate-authority-data holds no PEM certificate")
		}
		tlsCfg.RootCAs = pool
	}
	if k.user.ClientCertificateData != "" || k.user.ClientKeyData != "" {
		certPEM, err := decodeData("client-certificate-data", k.user.ClientCertificateData)
		if err != nil {
			return nil, err
		}
		keyPEM, err := decodeData("client-key-data", k.user.ClientKeyData)
		if err != nil {
			return nil, err
		}
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, invalid("client certificate and key: %v", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	tr, _ := http.DefaultTransport.(*http.Transport)
	tr = tr.Clone()
	tr.TLSClientConfig = tlsCfg
	tr.ForceAttemptHTTP2 = true
	tr.ResponseHeaderTimeout = 30 * time.Second
	if k.cluster.ProxyURL != "" {
		p, err := url.Parse(k.cluster.ProxyURL)
		if err != nil {
			return nil, invalid("proxy-url %q: %v", k.cluster.ProxyURL, err)
		}
		tr.Proxy = http.ProxyURL(p)
	}
	return &http.Client{Transport: &authTransport{next: tr, user: k.user}}, nil
}

// authTransport adds the kubeconfig's token or basic credentials.
type authTransport struct {
	next http.RoundTripper
	user kcUser
}

func (t *authTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	switch {
	case t.user.Token != "":
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+t.user.Token)
	case t.user.Username != "":
		r = r.Clone(r.Context())
		r.SetBasicAuth(t.user.Username, t.user.Password)
	}
	return t.next.RoundTrip(r)
}
