// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"errors"
	"strings"
	"testing"
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
	rc, err := kc.restConfig()
	if err != nil {
		t.Fatal(err)
	}
	if rc.Host != "https://192.0.2.10:6443" || rc.BearerToken != "lab-secret-token" {
		t.Errorf("rest config host %q, token %q", rc.Host, rc.BearerToken)
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
		"auth provider":    user(`{auth-provider: {name: oidc}}`),
		"client cert file": user(`{client-certificate: /etc/hearth/ca.key, client-key: /etc/hearth/ca.key}`),
		"token file":       user(`{tokenFile: /var/lib/hearth/hub/ca.key}`),
		"CA file": strings.Replace(testKubeconfig, "insecure-skip-tls-verify: true",
			"certificate-authority: /etc/ssl/ca.pem", 1),
		"no server": strings.Replace(testKubeconfig, "server: https://192.0.2.10:6443", "server: \"\"", 1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseKubeconfig([]byte(raw)); !errors.Is(err, ErrInvalidKubeconfig) {
				t.Errorf("parseKubeconfig = %v, want ErrInvalidKubeconfig", err)
			}
		})
	}
}
