// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"bytes"
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// The parts of a Kubernetes DaemonSet the test reads.
type daemonSet struct {
	Kind string `yaml:"kind"`
	Spec struct {
		Template struct {
			Spec struct {
				HostPID        bool        `yaml:"hostPID"`
				HostNetwork    bool        `yaml:"hostNetwork"`
				AutomountToken *bool       `yaml:"automountServiceAccountToken"`
				InitContainers []container `yaml:"initContainers"`
				Containers     []container `yaml:"containers"`
				Volumes        []struct {
					Name     string `yaml:"name"`
					HostPath *struct {
						Path string `yaml:"path"`
					} `yaml:"hostPath"`
					Secret *struct {
						SecretName string `yaml:"secretName"`
						Optional   bool   `yaml:"optional"`
					} `yaml:"secret"`
				} `yaml:"volumes"`
			} `yaml:"spec"`
		} `yaml:"template"`
	} `yaml:"spec"`
}

type container struct {
	Name            string   `yaml:"name"`
	Args            []string `yaml:"args"`
	SecurityContext struct {
		Privileged             bool  `yaml:"privileged"`
		AllowEscalation        *bool `yaml:"allowPrivilegeEscalation"`
		ReadOnlyRootFilesystem bool  `yaml:"readOnlyRootFilesystem"`
		Capabilities           struct {
			Drop []string `yaml:"drop"`
			Add  []string `yaml:"add"`
		} `yaml:"capabilities"`
	} `yaml:"securityContext"`
	Resources struct {
		Limits map[string]string `yaml:"limits"`
	} `yaml:"resources"`
	VolumeMounts []struct {
		Name     string `yaml:"name"`
		ReadOnly bool   `yaml:"readOnly"`
	} `yaml:"volumeMounts"`
}

func loadDaemonSet(t *testing.T) daemonSet {
	t.Helper()
	b, err := os.ReadFile("kubernetes/agent-daemonset.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	for {
		var ds daemonSet
		if err := dec.Decode(&ds); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if ds.Kind == "DaemonSet" {
			return ds
		}
	}
	t.Fatal("no DaemonSet in the manifest")
	return daemonSet{}
}

// The agent DaemonSet only reads the node: no privilege, no capability, no
// host path it can write but its identity dir, an empty capability ceiling,
// bounded resources, and a token Secret it can start without.
func TestAgentDaemonSetOnlyReads(t *testing.T) {
	ds := loadDaemonSet(t)
	spec := ds.Spec.Template.Spec
	if spec.HostPID || !spec.HostNetwork {
		t.Errorf("hostPID %v, hostNetwork %v; want the node's network only", spec.HostPID, spec.HostNetwork)
	}
	if spec.AutomountToken == nil || *spec.AutomountToken {
		t.Error("the pod must not mount a service account token")
	}
	hostPaths := map[string]bool{}
	for _, v := range spec.Volumes {
		if v.HostPath != nil {
			hostPaths[v.Name] = true
		}
		if v.Secret != nil && !v.Secret.Optional {
			t.Errorf("secret volume %s is required: pods would hang once it is deleted after enrollment", v.Name)
		}
	}
	all := slices.Concat(spec.InitContainers, spec.Containers)
	if len(all) != 2 {
		t.Fatalf("%d containers; want join and agent", len(all))
	}
	for _, c := range all {
		sc := c.SecurityContext
		if sc.Privileged || sc.AllowEscalation == nil || *sc.AllowEscalation || !sc.ReadOnlyRootFilesystem ||
			!slices.Equal(sc.Capabilities.Drop, []string{"ALL"}) || len(sc.Capabilities.Add) != 0 {
			t.Errorf("container %s: security context %+v", c.Name, sc)
		}
		if c.Resources.Limits["cpu"] == "" || c.Resources.Limits["memory"] == "" {
			t.Errorf("container %s: no CPU or memory limit", c.Name)
		}
		for _, m := range c.VolumeMounts {
			if hostPaths[m.Name] && m.Name != "data" && !m.ReadOnly {
				t.Errorf("container %s mounts host path %s writable", c.Name, m.Name)
			}
		}
		for _, a := range c.Args {
			if strings.HasPrefix(a, "--allow-") {
				t.Errorf("container %s: %s raises the capability ceiling", c.Name, a)
			}
		}
	}
	join := strings.Join(spec.InitContainers[0].Args, " ")
	for _, want := range []string{"agent join", "--if-not-enrolled", "--token-file=/etc/hearth-tokens/$(NODE_NAME)"} {
		if !strings.Contains(join, want) {
			t.Errorf("join args %q lack %q", join, want)
		}
	}
}
