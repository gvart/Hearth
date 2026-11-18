// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/integrations/kubernetes"
	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// tool is one MCP tool and the lowest class of action it takes: a token
// whose scope is below it is not offered the tool.
type tool struct {
	class       policy.Class
	name        string
	description string
	schema      map[string]any
	call        func(ctx context.Context, args json.RawMessage) (any, error)
}

// newTool makes a tool whose arguments are In, a struct (see inputSchema),
// and whose handler answers a value, sent as JSON text (or as is, for a
// string), or an error, sent as a tool error.
func newTool[In any](class policy.Class, name, description string, h func(context.Context, In) (any, error)) tool {
	return tool{
		class: class, name: name, description: description, schema: inputSchema(reflect.TypeFor[In]()),
		call: func(ctx context.Context, args json.RawMessage) (any, error) {
			var in In
			if len(args) > 0 && string(args) != "null" {
				dec := json.NewDecoder(bytes.NewReader(args))
				dec.DisallowUnknownFields()
				if err := dec.Decode(&in); err != nil {
					return nil, fmt.Errorf("invalid arguments: %w", err)
				}
			}
			return h(ctx, in)
		},
	}
}

func (s *session) tools() []tool {
	out := []tool{
		newTool(policy.Read, "list_devices",
			"List the homelab's devices, or search them by id, name, hostname, OS, architecture, label key=value or label value.",
			s.listDevices),
		newTool(policy.Read, "get_device",
			"Get one device with all its facts: CPU, memory, disks, network interfaces, agent version and capability ceiling (what it lets the hub restart or run).",
			s.getDevice),
		newTool(policy.Read, "device_metrics",
			"Read a device's current CPU, memory and root disk usage, in percent, from Prometheus (node-exporter).",
			s.deviceMetrics),
		newTool(policy.Read, "plan_automation",
			"Validate an automation (YAML) and describe what it would do: its triggers, conditions, and each action with its policy class. Nothing runs.",
			s.planAutomation),
		newTool(policy.Safe, "restart_service",
			"Restart a systemd unit or Docker container on a device, through its agent. service is manager:name, "+
				"e.g. docker:pihole or systemd:nginx.service; the device's agent must allow it (--allow-restart).",
			s.restartService),
		newTool(policy.Dangerous, "exec_command",
			"Run a command on a device, through its agent; the program must be allowed by the agent (--allow-exec). "+
				"Dangerous: usually held until an operator approves it. Returns the exit code, not the output.",
			s.execCommand),
		newTool(policy.Dangerous, "apply_automation",
			"Write an automation (YAML) to the hub's automations directory as <id>.yaml, replacing that automation if it "+
				"exists; the hub loads and runs it. Dangerous: usually held until an operator approves it.",
			s.applyAutomation),
	}
	if s.cfg.Kube != nil {
		out = append(out,
			newTool(policy.Read, "list_kube_objects",
				"List adopted Kubernetes clusters (no cluster given), or one cluster's objects: nodes, namespaces, "+
					"workloads (Deployments, StatefulSets, DaemonSets), pods and recent events; filter by namespace and text.",
				s.listKubeObjects),
			newTool(policy.Read, "pod_logs",
				"Read the last lines of a pod container's log in an adopted Kubernetes cluster.",
				s.podLogs),
			newTool(policy.Safe, "kube_action",
				"Act on an adopted Kubernetes cluster: restart (Deployment, StatefulSet or DaemonSet), scale "+
					"(Deployment or StatefulSet), delete_pod, cordon, uncordon or drain (dangerous) a node. dry_run plans it only.",
				s.kubeAction),
		)
	}
	return out
}

// deviceView is a device as list_devices shows it.
type deviceView struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	Hostname string            `json:"hostname"`
	OS       string            `json:"os"`
	Arch     string            `json:"arch"`
	Status   string            `json:"status"`
	Labels   map[string]string `json:"labels,omitempty"`
	LastSeen time.Time         `json:"last_seen"`
}

func view(d store.Device) deviceView {
	return deviceView{
		ID: d.ID, Name: d.Name, Hostname: d.Hostname, OS: d.OS, Arch: d.Arch, Status: d.Status,
		Labels: d.Labels, LastSeen: d.LastSeen,
	}
}

type listDevicesIn struct {
	Query  string `json:"query,omitempty" jsonschema:"text to search for; empty lists every device"`
	Status string `json:"status,omitempty" jsonschema:"only devices with this status: online or offline"`
}

func (s *session) listDevices(ctx context.Context, in listDevicesIn) (any, error) {
	out := []deviceView{}
	err := s.do(ctx, policy.Request{
		Action: policy.DeviceRead, Target: "devices",
		Detail: map[string]any{"query": in.Query, "status": in.Status},
	}, func(ctx context.Context) error {
		devs, err := s.cfg.Devices.List(ctx)
		if err != nil {
			return err
		}
		for _, d := range devs {
			d = s.cfg.Live(d)
			if (in.Status == "" || d.Status == in.Status) && matches(d, in.Query) {
				out = append(out, view(d))
			}
		}
		return nil
	})
	return out, err
}

// matches reports whether d has query in its id, name, hostname, OS,
// architecture or labels (as key=value or a value), ignoring case.
func matches(d store.Device, query string) bool {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return true
	}
	fields := []string{d.ID, d.Name, d.Hostname, d.OS, d.Arch}
	for k, v := range d.Labels {
		fields = append(fields, k+"="+v, v)
	}
	return slices.ContainsFunc(fields, func(f string) bool { return strings.Contains(strings.ToLower(f), q) })
}

type deviceIn struct {
	Device string `json:"device" jsonschema:"the device's id, name or hostname"`
}

func (s *session) getDevice(ctx context.Context, in deviceIn) (any, error) {
	var out struct {
		deviceView
		FirstSeen time.Time       `json:"first_seen"`
		BootTime  *time.Time      `json:"boot_time,omitempty"`
		Facts     json.RawMessage `json:"facts,omitempty"`
	}
	err := s.do(ctx, policy.Request{Action: policy.DeviceRead, Target: in.Device}, func(ctx context.Context) error {
		d, err := s.resolve(ctx, in.Device)
		if err != nil {
			return err
		}
		d = s.cfg.Live(d)
		out.deviceView, out.FirstSeen, out.Facts = view(d), d.FirstSeen, d.Facts
		if !d.BootTime.IsZero() {
			out.BootTime = &d.BootTime
		}
		return nil
	})
	return out, err
}

// resolve returns the device whose id is ref, or else the only one whose
// name or hostname is ref.
func (s *session) resolve(ctx context.Context, ref string) (store.Device, error) {
	devs, err := s.cfg.Devices.List(ctx)
	if err != nil {
		return store.Device{}, err
	}
	var match []store.Device
	for _, d := range devs {
		if d.ID == ref {
			return d, nil
		}
		if d.Name == ref || strings.EqualFold(d.Hostname, ref) {
			match = append(match, d)
		}
	}
	switch len(match) {
	case 0:
		return store.Device{}, fmt.Errorf("no device %q: list_devices shows them", ref)
	case 1:
		return match[0], nil
	}
	return store.Device{}, fmt.Errorf("device %q is ambiguous: %d devices have that name or hostname; use the device id", ref, len(match))
}

func (s *session) deviceMetrics(ctx context.Context, in deviceIn) (any, error) {
	out := map[string]any{}
	err := s.do(ctx, policy.Request{Action: policy.DeviceMetrics, Target: in.Device}, func(ctx context.Context) error {
		if s.cfg.Metrics == nil {
			return errors.New("no Prometheus is configured on the hub (hearth hub --prometheus-url)")
		}
		for _, m := range []string{"cpu", "memory", "disk"} {
			v, err := s.cfg.Metrics.DeviceMetric(ctx, in.Device, m)
			if err != nil {
				out[m+"_error"] = err.Error()
				continue
			}
			out[m+"_percent"] = v
		}
		return nil
	})
	return out, err
}

type restartIn struct {
	Device         string `json:"device" jsonschema:"the device's id, name or hostname"`
	Service        string `json:"service" jsonschema:"manager:name, manager one of systemd, systemd-user, docker; e.g. docker:pihole"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"how long the restart may take; default 60, at most 600"`
	DryRun         bool   `json:"dry_run,omitempty" jsonschema:"only decide and audit whether it would be allowed; nothing runs"`
}

// serviceManagers are the managers a restart may name, as the agent's
// --allow-restart does.
var serviceManagers = []string{"systemd", "systemd-user", "docker"}

func (s *session) restartService(ctx context.Context, in restartIn) (any, error) {
	manager, name, ok := strings.Cut(in.Service, ":")
	if !ok || name == "" || !slices.Contains(serviceManagers, manager) {
		return nil, fmt.Errorf("service must be manager:name with manager one of %s, e.g. docker:pihole",
			strings.Join(serviceManagers, ", "))
	}
	req := &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Restart{
		Restart: &agentv1.RestartService{Manager: manager, Name: name},
	}}
	return s.agentAction(ctx, policy.DeviceRestart, in.Device, in.TimeoutSeconds, in.DryRun,
		map[string]any{"service": in.Service}, "restart "+in.Service, req)
}

type execIn struct {
	Device         string   `json:"device" jsonschema:"the device's id, name or hostname"`
	Command        []string `json:"command" jsonschema:"the program and its arguments, program first, e.g. [\"/usr/bin/df\", \"-h\"]; no shell"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"how long the command may run; default 60, at most 600"`
	DryRun         bool     `json:"dry_run,omitempty" jsonschema:"only decide and audit whether it would be allowed; nothing runs"`
}

func (s *session) execCommand(ctx context.Context, in execIn) (any, error) {
	if len(in.Command) == 0 || in.Command[0] == "" {
		return nil, errors.New("command is required: a list, program first")
	}
	req := &agentv1.ExecRequest{Action: &agentv1.ExecRequest_Command{Command: &agentv1.Command{Argv: in.Command}}}
	// The operator approving it must see what runs: the command is in the
	// approval and the audit log, as an automation's file shows it.
	return s.agentAction(ctx, policy.DeviceExec, in.Device, in.TimeoutSeconds, in.DryRun,
		map[string]any{"command": in.Command}, "exec "+in.Command[0], req)
}

const (
	defaultAgentTimeout = time.Minute
	maxAgentTimeout     = 10 * time.Minute
	// answerGrace is how long the hub waits past the timeout for the
	// agent's answer.
	answerGrace = 15 * time.Second
)

// agentAction runs req on device through policy. The hub refuses it, as
// policy denied, when it is beyond the ceiling the device's agent reported.
func (s *session) agentAction(ctx context.Context, action policy.Action, device string,
	timeoutSeconds int, dryRun bool, detail map[string]any, what string, req *agentv1.ExecRequest,
) (any, error) {
	timeout := time.Duration(timeoutSeconds) * time.Second
	switch {
	case timeoutSeconds == 0:
		timeout = defaultAgentTimeout
	case timeout < 0 || timeout > maxAgentTimeout:
		return nil, fmt.Errorf("timeout_seconds must be between 0 and %d", int(maxAgentTimeout.Seconds()))
	}
	if device == "" {
		return nil, errors.New("device is required")
	}
	var exitCode int32
	err := s.do(ctx, policy.Request{
		Action: action, Target: device, Detail: detail, DryRun: dryRun,
		Precheck: func(ctx context.Context) error { return s.cfg.Agents.Check(ctx, device, req) },
	}, func(ctx context.Context) error {
		req.Timeout = durationpb.New(timeout)
		ctx, cancel := context.WithTimeout(ctx, timeout+answerGrace)
		defer cancel()
		res, err := s.cfg.Agents.Exec(ctx, device, req)
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		exitCode = res.GetExitCode()
		if res.GetDenied() {
			return fmt.Errorf("%s on device %s: %w", what, device, policy.ErrBeyondCeiling)
		}
		if res.GetError() != "" {
			return fmt.Errorf("%s on device %s failed (exit code %d): %s", what, device, exitCode, res.GetError())
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if dryRun {
		return fmt.Sprintf("Dry run: %s on %s would be %s. Nothing ran.", what, device, s.outcome(action)), nil
	}
	return map[string]any{"ok": true, "exit_code": exitCode, "result": what + " on " + device + " succeeded"}, nil
}

// outcome says what policy does with action for this token, for a dry run
// it allowed: allowed, or held for approval.
func (s *session) outcome(action policy.Action) string {
	if d, _ := s.cfg.Policy.Check(policy.Request{ActorKind: policy.ActorMCP, ActorID: s.tok.Name, Action: action}); d == policy.Confirm {
		return "held for approval"
	}
	return "allowed"
}

type automationIn struct {
	YAML string `json:"yaml" jsonschema:"the automation file's content (YAML), as documented in docs/automations.md"`
}

// planKinds are the step types an automation file may use, without the
// hub's dependencies: enough to validate and plan it.
func planKinds() automation.Kinds {
	kinds := automation.Builtin(slog.New(slog.DiscardHandler))
	maps.Copy(kinds.Triggers, automation.Triggers(automation.TriggerDeps{}))
	maps.Copy(kinds.Actions, automation.Actions(automation.ActionDeps{}))
	return kinds
}

// maxAutomationBytes bounds an automation file from a client.
const maxAutomationBytes = 64 << 10

// plan parses an automation file and describes it.
func plan(yaml string) (*automation.Automation, string, error) {
	if len(yaml) > maxAutomationBytes {
		return nil, "", fmt.Errorf("automation is larger than %d KiB", maxAutomationBytes>>10)
	}
	a, err := automation.Parse("automation.yaml", []byte(yaml), planKinds())
	if err != nil {
		return nil, "", err
	}
	var b bytes.Buffer
	if err := automation.Plan(&b, a); err != nil {
		return nil, "", err
	}
	return a, b.String(), nil
}

func (s *session) planAutomation(ctx context.Context, in automationIn) (any, error) {
	var out string
	err := s.do(ctx, policy.Request{Action: policy.AutomationPlan}, func(context.Context) error {
		var err error
		_, out, err = plan(in.YAML)
		return err
	})
	return out, err
}

type applyIn struct {
	YAML   string `json:"yaml" jsonschema:"the automation file's content (YAML), as documented in docs/automations.md"`
	DryRun bool   `json:"dry_run,omitempty" jsonschema:"only validate it and decide and audit whether it would be allowed; nothing is written"`
}

func (s *session) applyAutomation(ctx context.Context, in applyIn) (any, error) {
	if s.cfg.AutomationsDir == "" {
		return nil, errors.New("this hub has no automations directory")
	}
	a, desc, err := plan(in.YAML)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(s.cfg.AutomationsDir, a.ID+".yaml")
	// The plan, in the approval and the audit log, is what the operator
	// approves.
	err = s.do(ctx, policy.Request{
		Action: policy.AutomationApply, Target: a.ID, DryRun: in.DryRun,
		Detail: map[string]any{"file": path, "plan": desc},
	}, func(context.Context) error { return s.writeAutomation(a.ID, path, []byte(in.YAML)) })
	if err != nil {
		return nil, err
	}
	if in.DryRun {
		return fmt.Sprintf("Dry run: applying %s would be %s. Nothing was written.\n\n%s",
			a.ID, s.outcome(policy.AutomationApply), desc), nil
	}
	return fmt.Sprintf("Wrote %s; the hub loads it within seconds.\n\n%s", path, desc), nil
}

// writeAutomation writes the automation id to path, unless another file of
// the automations directory has that id: two files with one id fail the
// hub's whole reload.
func (s *session) writeAutomation(id, path string, b []byte) error {
	existing, err := automation.LoadDir(s.cfg.AutomationsDir, planKinds())
	if err != nil {
		return fmt.Errorf("the automations directory does not load, fix it first: %w", err)
	}
	for _, e := range existing {
		if e.ID == id && e.File != path {
			return fmt.Errorf("automation %s is defined in %s: edit that file instead", id, e.File)
		}
	}
	if err := os.MkdirAll(s.cfg.AutomationsDir, 0o700); err != nil {
		return fmt.Errorf("create automations dir: %w", err)
	}
	tmp, err := os.CreateTemp(s.cfg.AutomationsDir, ".apply-*")
	if err != nil {
		return fmt.Errorf("write automation: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write automation: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("write automation: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("write automation: %w", err)
	}
	return nil
}

type kubeObjectsIn struct {
	Cluster   string `json:"cluster,omitempty" jsonschema:"the cluster's name or id; empty lists the clusters"`
	Kind      string `json:"kind,omitempty" jsonschema:"nodes, namespaces, workloads, pods or events; empty lists nodes, workloads and pods"`
	Namespace string `json:"namespace,omitempty" jsonschema:"only objects in this namespace"`
	Query     string `json:"query,omitempty" jsonschema:"only objects with this text in a field, ignoring case"`
}

func (s *session) listKubeObjects(ctx context.Context, in kubeObjectsIn) (any, error) {
	var out any
	target := in.Cluster
	if target == "" {
		target = "clusters"
	}
	err := s.do(ctx, policy.Request{
		Action: policy.KubeRead, Target: target,
		Detail: map[string]any{"kind": in.Kind, "namespace": in.Namespace, "query": in.Query},
	}, func(ctx context.Context) error {
		if in.Cluster == "" {
			out = s.cfg.Kube.Clusters()
			return nil
		}
		id, err := s.clusterID(in.Cluster)
		if err != nil {
			return err
		}
		snap, err := s.cfg.Kube.Snapshot(ctx, id)
		if err != nil {
			return err
		}
		m := map[string]any{}
		all := in.Kind == ""
		if all || in.Kind == "nodes" {
			m["nodes"] = filter(snap.Nodes, in.Namespace, in.Query)
		}
		if in.Kind == "namespaces" {
			m["namespaces"] = filter(snap.Namespaces, "", in.Query)
		}
		if all || in.Kind == "workloads" {
			m["workloads"] = filter(snap.Workloads, in.Namespace, in.Query)
		}
		if all || in.Kind == "pods" {
			m["pods"] = filter(snap.Pods, in.Namespace, in.Query)
		}
		if in.Kind == "events" {
			m["events"] = filter(snap.Events, in.Namespace, in.Query)
		}
		if len(m) == 0 {
			return fmt.Errorf("kind %q must be nodes, namespaces, workloads, pods or events", in.Kind)
		}
		out = m
		return nil
	})
	return out, err
}

// filter keeps the items in namespace (if set; an item without one, such
// as a node, is left out then) with query in one of their fields.
func filter[T any](items []T, namespace, query string) []T {
	q := strings.ToLower(query)
	out := []T{}
	for _, it := range items {
		b, err := json.Marshal(it)
		if err != nil {
			continue
		}
		var fields map[string]any
		if json.Unmarshal(b, &fields) != nil {
			continue
		}
		if ns, _ := fields["namespace"].(string); namespace != "" && ns != namespace {
			continue
		}
		if q != "" && !slices.ContainsFunc(slices.Collect(maps.Values(fields)), func(v any) bool {
			s, ok := v.(string)
			return ok && strings.Contains(strings.ToLower(s), q)
		}) {
			continue
		}
		out = append(out, it)
	}
	return out
}

// clusterID returns the id of the adopted cluster whose id or name is ref.
func (s *session) clusterID(ref string) (string, error) {
	for _, c := range s.cfg.Kube.Clusters() {
		if c.ID == ref || c.Name == ref {
			return c.ID, nil
		}
	}
	return "", fmt.Errorf("no Kubernetes cluster %q: list_kube_objects without a cluster lists them", ref)
}

type podLogsIn struct {
	Cluster   string `json:"cluster" jsonschema:"the cluster's name or id"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	Container string `json:"container,omitempty" jsonschema:"the container; may be empty for a pod with one container"`
	Tail      int    `json:"tail,omitempty" jsonschema:"how many of the last lines to read; default 200, at most 5000"`
}

func (s *session) podLogs(ctx context.Context, in podLogsIn) (any, error) {
	id, err := s.clusterID(in.Cluster)
	if err != nil {
		return nil, err
	}
	tail := in.Tail
	if tail <= 0 {
		tail = 200
	}
	// The manager decides and audits it, as this token.
	logs, err := s.cfg.Kube.Logs(s.scoped(ctx), policy.ActorMCP, s.tok.Name, id, in.Namespace, in.Pod, in.Container, tail)
	if err != nil {
		return nil, err
	}
	if logs == "" {
		return "(no log lines)", nil
	}
	return logs, nil
}

type kubeActionIn struct {
	Cluster        string `json:"cluster" jsonschema:"the cluster's name or id"`
	Action         string `json:"action" jsonschema:"restart, scale, delete_pod, cordon, uncordon or drain"`
	Kind           string `json:"kind,omitempty" jsonschema:"the workload's kind for restart (Deployment, StatefulSet, DaemonSet) or scale (Deployment, StatefulSet)"`
	Namespace      string `json:"namespace,omitempty" jsonschema:"the workload's or pod's namespace; empty for a node"`
	Name           string `json:"name" jsonschema:"the workload, pod or node"`
	Replicas       *int32 `json:"replicas,omitempty" jsonschema:"the target replicas of a scale"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty" jsonschema:"how long a drain may take"`
	DryRun         bool   `json:"dry_run,omitempty" jsonschema:"only plan the action: read what it would touch and change nothing"`
}

func (s *session) kubeAction(ctx context.Context, in kubeActionIn) (any, error) {
	id, err := s.clusterID(in.Cluster)
	if err != nil {
		return nil, err
	}
	// The manager decides and audits it, as this token: a drain is
	// dangerous, beyond a safe token's scope.
	return s.cfg.Kube.Act(s.scoped(ctx), policy.ActorMCP, s.tok.Name, id, kubernetes.ActionRequest{
		Action: in.Action, Kind: in.Kind, Namespace: in.Namespace, Name: in.Name,
		Replicas: in.Replicas, TimeoutSeconds: in.TimeoutSeconds, DryRun: in.DryRun,
	})
}
