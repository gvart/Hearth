// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"errors"
	"fmt"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// ErrInvalidKubeconfig is returned for a kubeconfig the hub cannot use.
var ErrInvalidKubeconfig = errors.New("invalid kubeconfig")

// kubeconfig is a parsed, validated kubeconfig reduced to its current
// context.
type kubeconfig struct {
	// raw is the reduced kubeconfig, which is what the hub stores (sealed).
	raw []byte
	// context and server name the current context and its API server.
	context, server string
	cfg             *clientcmdapi.Config
}

// parseKubeconfig parses raw and keeps only its current context, so the hub
// stores no credential it does not use. It refuses what would make the hub
// run a program (exec and auth-provider plugins) or read a file on the hub
// host (certificate, key or token paths): a kubeconfig must carry its
// credentials inline, which talosctl, k3s and kind all do.
func parseKubeconfig(raw []byte) (*kubeconfig, error) {
	cfg, err := clientcmd.Load(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKubeconfig, err)
	}
	if cfg.CurrentContext == "" {
		return nil, fmt.Errorf("%w: no current-context", ErrInvalidKubeconfig)
	}
	if err := clientcmdapi.MinifyConfig(cfg); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKubeconfig, err)
	}
	ctx := cfg.Contexts[cfg.CurrentContext]
	cluster := cfg.Clusters[ctx.Cluster]
	user := cfg.AuthInfos[ctx.AuthInfo]
	switch {
	case cluster == nil || cluster.Server == "":
		return nil, fmt.Errorf("%w: the current context has no cluster server", ErrInvalidKubeconfig)
	case cluster.CertificateAuthority != "":
		return nil, fmt.Errorf("%w: certificate-authority must be inline (certificate-authority-data)", ErrInvalidKubeconfig)
	}
	if user != nil {
		switch {
		case user.Exec != nil || user.AuthProvider != nil:
			return nil, fmt.Errorf("%w: exec and auth-provider credentials are not supported; use a client certificate or token", ErrInvalidKubeconfig)
		case user.ClientCertificate != "" || user.ClientKey != "":
			return nil, fmt.Errorf("%w: client-certificate and client-key must be inline (-data)", ErrInvalidKubeconfig)
		case user.TokenFile != "":
			return nil, fmt.Errorf("%w: tokenFile is not supported; put the token inline", ErrInvalidKubeconfig)
		}
	}
	out, err := clientcmd.Write(*cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKubeconfig, err)
	}
	return &kubeconfig{raw: out, context: cfg.CurrentContext, server: cluster.Server, cfg: cfg}, nil
}

// restConfig is the client configuration of the kubeconfig's current context.
func (k *kubeconfig) restConfig() (*rest.Config, error) {
	rc, err := clientcmd.NewDefaultClientConfig(*k.cfg, &clientcmd.ConfigOverrides{}).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKubeconfig, err)
	}
	rc.UserAgent = "hearth"
	return rc, nil
}
