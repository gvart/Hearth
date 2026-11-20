// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gvart/hearth/internal/policy"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
)

// The agent talks to the Docker Engine API over its unix socket with
// net/http, and uses only what Docker and Podman's compatible API both
// serve: GET /containers/json, POST /containers/{id}/start, stop and
// restart, GET /containers/{id}/logs (never with follow) and GET
// /images/json. Nothing else of the API is reachable from the hub: no exec,
// create, remove, pull or passthrough.

const (
	// defaultDockerTimeout applies when a request sets none. A stop waits
	// up to 10 s for the container to exit before the engine kills it.
	defaultDockerTimeout = 30 * time.Second
	// maxDockerTimeout caps what the hub may ask for.
	maxDockerTimeout = 2 * time.Minute
	// maxDockerContainers and maxDockerImages bound a list.
	maxDockerContainers = 500
	maxDockerImages     = 500
	// maxDockerBody bounds a JSON answer of the engine.
	maxDockerBody = 8 << 20
	// maxDockerLogBytes bounds the log bytes read for one request.
	maxDockerLogBytes = 4 << 20
	// maxDockerError bounds an error answer of the engine.
	maxDockerError = 4 << 10
)

// DefaultDockerSocket is the Docker engine's socket. Without
// --docker-socket the agent tries it, then rootless Podman's
// ($XDG_RUNTIME_DIR/podman/podman.sock), then rootful Podman's.
const DefaultDockerSocket = "/var/run/docker.sock"

// dockerSockets are the sockets to try, in order: only explicit when set
// (a unix:// prefix is allowed), else the Docker and Podman defaults.
func dockerSockets(explicit string) []string {
	if explicit != "" {
		return []string{strings.TrimPrefix(explicit, "unix://")}
	}
	out := []string{DefaultDockerSocket}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		out = append(out, filepath.Join(dir, "podman", "podman.sock"))
	}
	return append(out, "/run/podman/podman.sock")
}

// errNoDockerSocket says no socket was found.
var errNoDockerSocket = errors.New("no Docker or Podman socket")

// findDockerSocket is the first of sockets that exists and is a socket.
func findDockerSocket(sockets []string) (string, error) {
	for _, s := range sockets {
		if fi, err := os.Stat(s); err == nil && fi.Mode().Type() == fs.ModeSocket {
			return s, nil
		}
	}
	if len(sockets) == 1 {
		return "", fmt.Errorf("%w at %s: set --docker-socket to the engine's socket", errNoDockerSocket, sockets[0])
	}
	return "", fmt.Errorf("%w: tried %s; set --docker-socket to the engine's socket",
		errNoDockerSocket, strings.Join(sockets, ", "))
}

// dockerEngine reaches the engine on a unix socket. It keeps nothing open
// between requests: an agent that is never asked holds no connection and
// no buffer.
type dockerEngine struct {
	sockets []string
}

// docker answers a DockerRequest within the ceiling c.
func (d dockerEngine) docker(ctx context.Context, c Ceiling, req *agentv1.DockerRequest) *agentv1.DockerResult {
	res := &agentv1.DockerResult{Id: req.GetId()}
	if err := policy.DockerWithinCeiling(c.proto(), req); err != nil {
		res.Denied = errors.Is(err, policy.ErrDenied)
		res.Error = err.Error()
		return res
	}
	timeout := defaultDockerTimeout
	if t := req.GetTimeout().AsDuration(); t > 0 {
		timeout = min(t, maxDockerTimeout)
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	socket, err := findDockerSocket(d.sockets)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	cl := dockerClient(socket)
	defer cl.CloseIdleConnections()
	switch op := req.GetOp().(type) {
	case *agentv1.DockerRequest_List:
		err = dockerList(ctx, cl, res)
	case *agentv1.DockerRequest_Action:
		err = dockerAct(ctx, cl, op.Action.GetVerb(), op.Action.GetContainer())
	case *agentv1.DockerRequest_Logs:
		err = dockerLogs(ctx, cl, op.Logs.GetContainer(), op.Logs.GetTail(), res)
	}
	if err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("%w after %s: %w", ctx.Err(), timeout, err)
		}
		res.Error = err.Error()
	}
	return res
}

// dockerOp describes req for the agent's log: list, or verb and container.
func dockerOp(req *agentv1.DockerRequest) string {
	switch op := req.GetOp().(type) {
	case *agentv1.DockerRequest_List:
		return "list"
	case *agentv1.DockerRequest_Action:
		return op.Action.GetVerb() + " " + op.Action.GetContainer()
	case *agentv1.DockerRequest_Logs:
		return "logs " + op.Logs.GetContainer()
	}
	return "unknown"
}

// dockerClient is an HTTP client whose every connection dials socket.
func dockerClient(socket string) *http.Client {
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dl net.Dialer
			c, err := dl.DialContext(ctx, "unix", socket)
			if err != nil {
				return nil, fmt.Errorf("cannot reach the Docker engine at %s: %w", socket, err)
			}
			return c, nil
		},
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: tr}
}

// dockerURL is the engine URL of path, which callers build only from
// constants and containers ValidContainer accepted, escaped all the same.
func dockerURL(path string, q url.Values) string {
	u := url.URL{Scheme: "http", Host: "docker", Path: path, RawQuery: q.Encode()}
	return u.String()
}

// containerPath is /containers/{ref}/{op}.
func containerPath(ref, op string) string {
	return "/containers/" + url.PathEscape(ref) + "/" + op
}

// dockerDo sends a request and returns the answer when its status is
// 2xx or one of ok; any other status is an error with the engine's message.
func dockerDo(ctx context.Context, cl *http.Client, method, u string, ok ...int) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Do(req)
	if err != nil {
		var uerr *url.Error
		if errors.As(err, &uerr) {
			err = uerr.Err // the URL is ours and says nothing
		}
		return nil, err
	}
	if resp.StatusCode/100 == 2 || slices.Contains(ok, resp.StatusCode) {
		return resp, nil
	}
	defer func() { _ = resp.Body.Close() }()
	return nil, dockerError(resp)
}

// dockerError is the engine's error answer: its message, or its status.
func dockerError(resp *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxDockerError))
	var e struct {
		Message string `json:"message"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &e) == nil && e.Message != "" {
		msg = e.Message
	}
	if msg == "" {
		msg = http.StatusText(resp.StatusCode)
	}
	return fmt.Errorf("docker engine: %s (HTTP %d)", clipLine(msg), resp.StatusCode)
}

// getJSON GETs u and decodes its JSON answer into v.
func getJSON(ctx context.Context, cl *http.Client, u string, v any) error {
	resp, err := dockerDo(ctx, cl, http.MethodGet, u)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxDockerBody)).Decode(v); err != nil {
		return fmt.Errorf("docker engine: read answer: %w", err)
	}
	return nil
}

// Compose labels of a container.
const (
	composeProject = "com.docker.compose.project"
	composeService = "com.docker.compose.service"
)

// dockerList fills res with the engine's containers, running or not, and
// images.
func dockerList(ctx context.Context, cl *http.Client, res *agentv1.DockerResult) error {
	var cs []struct {
		ID      string            `json:"Id"`
		Names   []string          `json:"Names"`
		Image   string            `json:"Image"`
		State   string            `json:"State"`
		Status  string            `json:"Status"`
		Labels  map[string]string `json:"Labels"`
		Created int64             `json:"Created"`
	}
	if err := getJSON(ctx, cl, dockerURL("/containers/json", url.Values{"all": {"1"}}), &cs); err != nil {
		return fmt.Errorf("list containers: %w", err)
	}
	if len(cs) > maxDockerContainers {
		cs, res.Truncated = cs[:maxDockerContainers], true
	}
	for _, c := range cs {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}
		res.Containers = append(res.Containers, &agentv1.DockerContainer{
			Id: c.ID, Name: name, Image: c.Image, State: c.State, Status: c.Status,
			ComposeProject: c.Labels[composeProject], ComposeService: c.Labels[composeService],
			Created: unixTime(c.Created),
		})
	}
	var is []struct {
		ID       string   `json:"Id"`
		RepoTags []string `json:"RepoTags"`
		Size     int64    `json:"Size"`
		Created  int64    `json:"Created"`
	}
	if err := getJSON(ctx, cl, dockerURL("/images/json", nil), &is); err != nil {
		return fmt.Errorf("list images: %w", err)
	}
	if len(is) > maxDockerImages {
		is, res.Truncated = is[:maxDockerImages], true
	}
	for _, i := range is {
		img := &agentv1.DockerImage{Id: i.ID, SizeBytes: i.Size, Created: unixTime(i.Created)}
		for _, t := range i.RepoTags {
			if t != "<none>:<none>" {
				img.Tags = append(img.Tags, t)
			}
		}
		res.Images = append(res.Images, img)
	}
	return nil
}

func unixTime(s int64) *timestamppb.Timestamp {
	if s <= 0 {
		return nil
	}
	return timestamppb.New(time.Unix(s, 0))
}

// dockerAct starts, stops or restarts container. A container already
// started or stopped (304) is a success.
func dockerAct(ctx context.Context, cl *http.Client, verb, container string) error {
	resp, err := dockerDo(ctx, cl, http.MethodPost, dockerURL(containerPath(container, verb), nil), http.StatusNotModified)
	if err != nil {
		return fmt.Errorf("%s %s: %w", verb, container, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDockerError))
	_ = resp.Body.Close()
	return nil
}

// dockerLogs reads the last tail lines (at most policy.MaxDockerLogTail) of
// container's log, stdout and stderr, with their timestamps, once.
func dockerLogs(ctx context.Context, cl *http.Client, container string, tail uint32, res *agentv1.DockerResult) error {
	n := int(min(max(tail, 1), policy.MaxDockerLogTail))
	q := url.Values{"stdout": {"1"}, "stderr": {"1"}, "timestamps": {"1"}, "tail": {strconv.Itoa(n)}}
	resp, err := dockerDo(ctx, cl, http.MethodGet, dockerURL(containerPath(container, "logs"), q))
	if err != nil {
		return fmt.Errorf("logs of %s: %w", container, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := &limitedReader{r: resp.Body, left: maxDockerLogBytes}
	r, err := logStream(resp.Header.Get("Content-Type"), body)
	if err != nil {
		return fmt.Errorf("logs of %s: %w", container, err)
	}
	lines, dropped, err := lastLines(r, n)
	if err != nil {
		return fmt.Errorf("logs of %s: %w", container, err)
	}
	res.Lines = lines
	res.Truncated = dropped || body.hit
	return nil
}

// limitedReader is io.LimitReader that tells whether the limit cut the
// stream.
type limitedReader struct {
	r    io.Reader
	left int64
	hit  bool
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.left <= 0 {
		l.hit = true
		return 0, io.EOF
	}
	if int64(len(p)) > l.left {
		p = p[:l.left]
	}
	n, err := l.r.Read(p)
	l.left -= int64(n)
	return n, err
}

// Content types of the logs answer, API 1.42 and later.
const (
	multiplexedStream = "application/vnd.docker.multiplexed-stream"
	rawStream         = "application/vnd.docker.raw-stream"
)

// logStream is the log text of a logs answer. A container without a TTY
// answers with stdout and stderr multiplexed in frames, one with a TTY with
// the raw text. Engines that do not say which (older Docker, Podman) are
// sniffed: a frame starts with a stream number, 0 to 2, and three zero
// bytes, which no log line does.
func logStream(contentType string, body io.Reader) (io.Reader, error) {
	mt, _, _ := mime.ParseMediaType(contentType)
	switch mt {
	case multiplexedStream:
		return &demux{r: body}, nil
	case rawStream:
		return body, nil
	}
	br := bufio.NewReader(body)
	h, err := br.Peek(8)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(h) == 8 && h[0] <= 2 && h[1] == 0 && h[2] == 0 && h[3] == 0 {
		return &demux{r: br}, nil
	}
	return br, nil
}

// demux reads the payload of a multiplexed stream's frames, stdout and
// stderr as they came: an 8-byte header (stream, 0, 0, 0, big-endian
// payload size), then the payload.
type demux struct {
	r    io.Reader
	left uint32
}

func (d *demux) Read(p []byte) (int, error) {
	for d.left == 0 {
		var h [8]byte
		if _, err := io.ReadFull(d.r, h[:]); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				return 0, io.EOF // a cut frame header: the byte limit
			}
			return 0, err
		}
		if h[0] > 2 {
			return 0, errors.New("malformed log stream")
		}
		d.left = binary.BigEndian.Uint32(h[4:])
	}
	if uint64(len(p)) > uint64(d.left) {
		p = p[:d.left]
	}
	n, err := d.r.Read(p)
	d.left -= uint32(n) //nolint:gosec // n <= len(p) <= d.left
	return n, err
}

// lastLines reads r to its end and returns its last n lines, each parsed as
// a docker logs --timestamps line and clipped to maxLogLine; dropped tells
// whether lines before them were left out.
func lastLines(r io.Reader, n int) (lines []*agentv1.LogLine, dropped bool, err error) {
	br := bufio.NewReaderSize(r, maxLogLine+64)
	ring := make([]*agentv1.LogLine, 0, n)
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(line) < maxLogLine+64 {
			line = append(line, chunk[:min(len(chunk), maxLogLine+64-len(line))]...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue // a long line: keep its start only
		}
		if t := bytes.TrimRight(line, "\r\n"); len(t) > 0 || len(chunk) > 0 && err == nil {
			l := parseDockerLine(t)
			if len(ring) == n {
				copy(ring, ring[1:])
				ring, dropped = ring[:n-1], true
			}
			ring = append(ring, l)
		}
		line = line[:0]
		if errors.Is(err, io.EOF) {
			return ring, dropped, nil
		}
		if err != nil {
			return ring, dropped, err
		}
	}
}
