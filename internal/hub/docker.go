// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

const (
	// dockerTimeout is how long the agent has for a Docker request. A stop
	// waits up to 10 s for the container to exit before the engine kills
	// it.
	dockerTimeout = 30 * time.Second
	// dockerGrace is how much longer the hub waits for the agent's answer.
	dockerGrace = 5 * time.Second
	// defaultDockerLogTail is how many lines a logs read returns by default.
	defaultDockerLogTail = 100
)

// dockerActions are the policy actions of the container verbs.
var dockerActions = map[string]policy.Action{
	"start":   policy.DeviceDockerStart,
	"stop":    policy.DeviceDockerStop,
	"restart": policy.DeviceDockerRestart,
}

// errDockerEngine is a request the agent took and the engine, or the
// agent's way to it, failed.
var errDockerEngine = errors.New("docker")

// dockerRoutes registers a device's containers, behind the admin session.
// Without Agents there is no route.
func (a *api) dockerRoutes(mux *http.ServeMux) {
	if a.agents == nil {
		return
	}
	mux.Handle("GET /api/v1/devices/{id}/docker", a.auth(a.deviceDocker))
	mux.Handle("GET /api/v1/devices/{id}/docker/logs", a.auth(a.deviceDockerLogs))
	mux.Handle("POST /api/v1/devices/{id}/docker/actions", a.auth(a.deviceDockerAction))
}

// DockerJSON is what a device's container engine holds: its Compose
// projects (stacks), the containers outside any, and its images.
type DockerJSON struct {
	Stacks     []DockerStackJSON     `json:"stacks"`
	Containers []DockerContainerJSON `json:"containers"`
	Images     []DockerImageJSON     `json:"images"`
	// Truncated is set when the agent left containers or images out to
	// keep the answer bounded.
	Truncated bool `json:"truncated"`
}

// DockerStackJSON is a Compose project: the containers labelled with it.
type DockerStackJSON struct {
	Project string `json:"project"`
	// Running counts its containers in the running state.
	Running    int                   `json:"running"`
	Containers []DockerContainerJSON `json:"containers"`
}

// DockerContainerJSON is a container.
type DockerContainerJSON struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Image string `json:"image"`
	// State is the engine's word: running, exited, created, paused, ...
	State string `json:"state"`
	// Status is the engine's summary, such as "Up 2 hours".
	Status string `json:"status"`
	// Service is its Compose service; empty outside a project.
	Service string     `json:"service"`
	Created *time.Time `json:"created"`
}

// DockerImageJSON is an image, in summary.
type DockerImageJSON struct {
	ID        string     `json:"id"`
	Tags      []string   `json:"tags"`
	SizeBytes int64      `json:"size_bytes"`
	Created   *time.Time `json:"created"`
}

// DockerLogsJSON is the last lines of a container's log.
type DockerLogsJSON struct {
	Lines []LogLineJSON `json:"lines"`
	// Truncated is set when lines before these were left out.
	Truncated bool `json:"truncated"`
}

// DockerActionJSON asks for a container action, and answers it.
type DockerActionJSON struct {
	// Action is start, stop or restart.
	Action    string `json:"action"`
	Container string `json:"container"`
	// Result is "ok" once the engine did it; empty in a request.
	Result string `json:"result,omitempty"`
}

// deviceDocker serves GET /api/v1/devices/{id}/docker: the containers and
// images of the device's engine, asked of its agent now. It is the policy
// action device.docker.list, audited; the agent must run with
// --allow-docker.
func (a *api) deviceDocker(w http.ResponseWriter, r *http.Request) {
	device := r.PathValue("id")
	req := &agentv1.DockerRequest{Op: &agentv1.DockerRequest_List{List: &agentv1.DockerList{}}}
	var res *agentv1.DockerResult
	err := a.policy.Do(r.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.DeviceDockerList, Target: device,
		Precheck: func(ctx context.Context) error { return a.agents.CheckDocker(ctx, device, req) },
	}, func(ctx context.Context) error {
		var err error
		res, err = a.docker(ctx, device, req)
		return err
	})
	if err != nil {
		a.writeDockerError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, dockerJSON(res))
}

// deviceDockerLogs serves GET /api/v1/devices/{id}/docker/logs?container=
// &tail=: the last lines of a container's log, at most
// policy.MaxDockerLogTail, read once. It is the policy action
// device.docker.logs, audited: logs may carry secrets.
func (a *api) deviceDockerLogs(w http.ResponseWriter, r *http.Request) {
	device, container := r.PathValue("id"), r.URL.Query().Get("container")
	if !policy.ValidContainer(container) {
		writeError(w, http.StatusBadRequest, "bad_request", "container must be a container's id or name")
		return
	}
	tail := uint64(defaultDockerLogTail)
	if s := r.URL.Query().Get("tail"); s != "" {
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil || n < 1 {
			writeError(w, http.StatusBadRequest, "bad_request", "tail must be a positive number of lines")
			return
		}
		tail = min(n, policy.MaxDockerLogTail)
	}
	req := &agentv1.DockerRequest{Op: &agentv1.DockerRequest_Logs{Logs: &agentv1.DockerLogs{
		Container: container, Tail: uint32(tail), //nolint:gosec // at most MaxDockerLogTail
	}}}
	var res *agentv1.DockerResult
	err := a.policy.Do(r.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: policy.DeviceDockerLogs, Target: device,
		Detail:   map[string]any{"container": container, "tail": tail},
		Precheck: func(ctx context.Context) error { return a.agents.CheckDocker(ctx, device, req) },
	}, func(ctx context.Context) error {
		var err error
		res, err = a.docker(ctx, device, req)
		return err
	})
	if err != nil {
		a.writeDockerError(w, r, err)
		return
	}
	out := DockerLogsJSON{Lines: logLinesJSON(&agentv1.LogLines{Lines: res.GetLines()}).Lines, Truncated: res.GetTruncated()}
	writeJSON(w, http.StatusOK, out)
}

// deviceDockerAction serves POST /api/v1/devices/{id}/docker/actions with
// a DockerActionJSON: start, stop or restart a container. It is the policy
// action device.docker.<action>, safe; an action policy holds for approval
// answers once it is decided.
func (a *api) deviceDockerAction(w http.ResponseWriter, r *http.Request) {
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		writeError(w, http.StatusUnsupportedMediaType, "bad_request", "content type must be application/json")
		return
	}
	var body DockerActionJSON
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "bad_request", `body must be an action: {"action": "restart", "container": "web"}`)
		return
	}
	action, ok := dockerActions[body.Action]
	if !ok {
		writeError(w, http.StatusBadRequest, "bad_request", "action must be one of "+strings.Join(policy.DockerVerbs, ", "))
		return
	}
	if !policy.ValidContainer(body.Container) {
		writeError(w, http.StatusBadRequest, "bad_request", "container must be a container's id or name")
		return
	}
	device := r.PathValue("id")
	req := &agentv1.DockerRequest{Op: &agentv1.DockerRequest_Action{Action: &agentv1.DockerAction{
		Verb: body.Action, Container: body.Container,
	}}}
	err := a.policy.Do(r.Context(), policy.Request{
		ActorKind: policy.ActorWeb, ActorID: remoteHost(r), Action: action, Target: device,
		Detail:   map[string]any{"container": body.Container},
		Precheck: func(ctx context.Context) error { return a.agents.CheckDocker(ctx, device, req) },
	}, func(ctx context.Context) error {
		_, err := a.docker(ctx, device, req)
		return err
	})
	if err != nil {
		a.writeDockerError(w, r, err)
		return
	}
	body.Result = "ok"
	writeJSON(w, http.StatusOK, body)
}

// docker sends req to the agent of device and turns a refusal or a failure
// it answers with into an error: a refusal wraps policy.ErrBeyondCeiling,
// a failure errDockerEngine.
func (a *api) docker(ctx context.Context, device string, req *agentv1.DockerRequest) (*agentv1.DockerResult, error) {
	ctx, cancel := context.WithTimeout(ctx, dockerTimeout+dockerGrace)
	defer cancel()
	res, err := a.agents.Docker(ctx, device, req, dockerTimeout)
	switch {
	case err != nil:
		return nil, err
	case res.GetDenied():
		return nil, fmt.Errorf("device %s: the agent refused: %s: %w", device, res.GetError(), policy.ErrBeyondCeiling)
	case res.GetError() != "":
		return nil, fmt.Errorf("%w: %s", errDockerEngine, res.GetError())
	}
	return res, nil
}

// dockerJSON groups a list's containers by Compose project.
func dockerJSON(res *agentv1.DockerResult) DockerJSON {
	out := DockerJSON{Stacks: []DockerStackJSON{}, Containers: []DockerContainerJSON{}, Images: []DockerImageJSON{}, Truncated: res.GetTruncated()}
	stacks := map[string]*DockerStackJSON{}
	for _, c := range res.GetContainers() {
		j := DockerContainerJSON{
			ID: c.GetId(), Name: cmp.Or(c.GetName(), shortID(c.GetId())), Image: c.GetImage(), State: c.GetState(),
			Status: c.GetStatus(), Service: c.GetComposeService(), Created: timeOf(c.GetCreated().AsTime(), c.GetCreated() != nil),
		}
		p := c.GetComposeProject()
		if p == "" {
			out.Containers = append(out.Containers, j)
			continue
		}
		s := stacks[p]
		if s == nil {
			s = &DockerStackJSON{Project: p}
			stacks[p] = s
		}
		s.Containers = append(s.Containers, j)
		if j.State == "running" {
			s.Running++
		}
	}
	for _, s := range stacks {
		slices.SortFunc(s.Containers, compareContainers)
		out.Stacks = append(out.Stacks, *s)
	}
	slices.SortFunc(out.Stacks, func(a, b DockerStackJSON) int { return strings.Compare(a.Project, b.Project) })
	slices.SortFunc(out.Containers, compareContainers)
	for _, i := range res.GetImages() {
		tags := i.GetTags()
		if tags == nil {
			tags = []string{}
		}
		out.Images = append(out.Images, DockerImageJSON{
			ID: i.GetId(), Tags: tags, SizeBytes: i.GetSizeBytes(), Created: timeOf(i.GetCreated().AsTime(), i.GetCreated() != nil),
		})
	}
	return out
}

func compareContainers(a, b DockerContainerJSON) int {
	return cmp.Or(strings.Compare(a.Service, b.Service), strings.Compare(a.Name, b.Name))
}

// shortID is the 12-character form of a container id.
func shortID(id string) string {
	id = strings.TrimPrefix(id, "sha256:")
	return id[:min(len(id), 12)]
}

func timeOf(t time.Time, ok bool) *time.Time {
	if !ok {
		return nil
	}
	return &t
}

// writeDockerError answers a Docker request that failed.
func (a *api) writeDockerError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, policy.ErrDenied):
		// The reason (beyond the ceiling, agent too old) is no secret, and
		// says what to change.
		writeError(w, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, ErrAgentNotConnected):
		writeError(w, http.StatusConflict, "agent_not_connected", "the device's agent is not connected to this hub")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", "no such device")
	case errors.Is(err, store.ErrUnavailable):
		writeUnavailable(w)
	case errors.Is(err, errDockerEngine):
		writeError(w, http.StatusBadGateway, "docker_error", strings.TrimPrefix(err.Error(), errDockerEngine.Error()+": "))
	default:
		a.log.ErrorContext(r.Context(), "docker request", "err", err)
		writeError(w, http.StatusBadGateway, "agent_error", err.Error())
	}
}
