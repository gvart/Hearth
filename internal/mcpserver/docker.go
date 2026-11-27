// SPDX-License-Identifier: AGPL-3.0-only

package mcpserver

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

const (
	// dockerTimeout is how long the agent has for a Docker request, as the
	// web API gives it: a stop waits up to 10 s before the engine kills.
	dockerTimeout = 30 * time.Second
	// dockerGrace is how much longer the hub waits for the agent's answer.
	dockerGrace = 5 * time.Second
	// defaultDockerLogTail is how many lines container_logs reads by default.
	defaultDockerLogTail = 100
)

// dockerActions are the policy actions of the container verbs.
var dockerActions = map[string]policy.Action{
	"start":   policy.DeviceDockerStart,
	"stop":    policy.DeviceDockerStop,
	"restart": policy.DeviceDockerRestart,
}

// dockerTools are the tools of a device's container engine.
func (s *session) dockerTools() []tool {
	return []tool{
		newTool(policy.Read, "list_containers",
			"List a device's Docker containers (with their Compose project and service) and images, through its agent; "+
				"the device's agent must allow Docker (--allow-docker).",
			s.listContainers),
		newTool(policy.Read, "container_logs",
			fmt.Sprintf("Read the last lines of a Docker container's log on a device, through its agent; at most %d lines.",
				policy.MaxDockerLogTail),
			s.containerLogs),
		newTool(policy.Safe, "container_action",
			"Start, stop or restart a Docker container on a device, through its agent; the device's agent must allow Docker (--allow-docker).",
			s.containerAction),
	}
}

// containerView is a container as list_containers shows it.
type containerView struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Image   string `json:"image"`
	State   string `json:"state"`
	Status  string `json:"status,omitempty"`
	Project string `json:"project,omitempty"`
	Service string `json:"service,omitempty"`
}

// imageView is an image as list_containers shows it.
type imageView struct {
	ID        string   `json:"id"`
	Tags      []string `json:"tags,omitempty"`
	SizeBytes int64    `json:"size_bytes"`
}

func (s *session) listContainers(ctx context.Context, in deviceIn) (any, error) {
	req := &agentv1.DockerRequest{Op: &agentv1.DockerRequest_List{List: &agentv1.DockerList{}}}
	res, err := s.docker(ctx, policy.DeviceDockerList, in.Device, nil, req)
	if err != nil {
		return nil, err
	}
	out := struct {
		Containers []containerView `json:"containers"`
		Images     []imageView     `json:"images"`
		Truncated  bool            `json:"truncated,omitempty"`
	}{Containers: []containerView{}, Images: []imageView{}, Truncated: res.GetTruncated()}
	for _, c := range res.GetContainers() {
		out.Containers = append(out.Containers, containerView{
			ID: c.GetId(), Name: c.GetName(), Image: c.GetImage(), State: c.GetState(), Status: c.GetStatus(),
			Project: c.GetComposeProject(), Service: c.GetComposeService(),
		})
	}
	slices.SortFunc(out.Containers, func(a, b containerView) int {
		return cmp.Or(strings.Compare(a.Project, b.Project), strings.Compare(a.Service, b.Service), strings.Compare(a.Name, b.Name))
	})
	for _, i := range res.GetImages() {
		out.Images = append(out.Images, imageView{ID: i.GetId(), Tags: i.GetTags(), SizeBytes: i.GetSizeBytes()})
	}
	return out, nil
}

type containerLogsIn struct {
	Device    string `json:"device" jsonschema:"the device's id, name or hostname"`
	Container string `json:"container" jsonschema:"the container's name or id, as list_containers shows it"`
	Tail      int    `json:"tail,omitempty" jsonschema:"how many of the last lines to read; default 100, at most 200"`
}

func (s *session) containerLogs(ctx context.Context, in containerLogsIn) (any, error) {
	if !policy.ValidContainer(in.Container) {
		return nil, errors.New("container must be a container's id or name")
	}
	tail := in.Tail
	switch {
	case tail == 0:
		tail = defaultDockerLogTail
	case tail < 0:
		return nil, errors.New("tail must be a positive number of lines")
	}
	tail = min(tail, policy.MaxDockerLogTail)
	req := &agentv1.DockerRequest{Op: &agentv1.DockerRequest_Logs{Logs: &agentv1.DockerLogs{
		Container: in.Container, Tail: uint32(tail),
	}}}
	res, err := s.docker(ctx, policy.DeviceDockerLogs, in.Device, map[string]any{"container": in.Container, "tail": tail}, req)
	if err != nil {
		return nil, err
	}
	if len(res.GetLines()) == 0 {
		return "(no log lines)", nil
	}
	var b strings.Builder
	if res.GetTruncated() {
		b.WriteString("(earlier lines left out)\n")
	}
	for _, l := range res.GetLines() {
		b.WriteString(l.GetText())
		b.WriteByte('\n')
	}
	return b.String(), nil
}

type containerActionIn struct {
	Device    string `json:"device" jsonschema:"the device's id, name or hostname"`
	Container string `json:"container" jsonschema:"the container's name or id, as list_containers shows it"`
	Action    string `json:"action" jsonschema:"start, stop or restart"`
}

func (s *session) containerAction(ctx context.Context, in containerActionIn) (any, error) {
	action, ok := dockerActions[in.Action]
	if !ok {
		return nil, fmt.Errorf("action must be one of %s", strings.Join(policy.DockerVerbs, ", "))
	}
	if !policy.ValidContainer(in.Container) {
		return nil, errors.New("container must be a container's id or name")
	}
	req := &agentv1.DockerRequest{Op: &agentv1.DockerRequest_Action{Action: &agentv1.DockerAction{
		Verb: in.Action, Container: in.Container,
	}}}
	if _, err := s.docker(ctx, action, in.Device, map[string]any{"container": in.Container}, req); err != nil {
		return nil, err
	}
	return fmt.Sprintf("%s %s on %s succeeded", in.Action, in.Container, in.Device), nil
}

// docker sends req to the agent of device through policy, as the web API
// does: the hub refuses it, as policy denied, when it is beyond the ceiling
// the device's agent reported, and so does the agent itself.
func (s *session) docker(ctx context.Context, action policy.Action, device string, detail map[string]any,
	req *agentv1.DockerRequest,
) (*agentv1.DockerResult, error) {
	if device == "" {
		return nil, errors.New("device is required")
	}
	var res *agentv1.DockerResult
	err := s.do(ctx, policy.Request{
		Action: action, Target: device, Detail: detail,
		Precheck: func(ctx context.Context) error { return s.cfg.Agents.CheckDocker(ctx, device, req) },
	}, func(ctx context.Context) error {
		ctx, cancel := context.WithTimeout(ctx, dockerTimeout+dockerGrace)
		defer cancel()
		var err error
		res, err = s.cfg.Agents.Docker(ctx, device, req, dockerTimeout)
		switch {
		case err != nil:
			return err
		case res.GetDenied():
			return fmt.Errorf("device %s: the agent refused: %s: %w", device, res.GetError(), policy.ErrBeyondCeiling)
		case res.GetError() != "":
			return fmt.Errorf("device %s: docker: %s", device, res.GetError())
		}
		return nil
	})
	return res, err
}
