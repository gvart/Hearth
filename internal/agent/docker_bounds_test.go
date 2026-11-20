// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
)

// jsonArray encodes n elements made by elem as a JSON array.
func jsonArray(t *testing.T, n int, elem func(i int) any) []byte {
	t.Helper()
	var b bytes.Buffer
	b.WriteByte('[')
	for i := range n {
		if i > 0 {
			b.WriteByte(',')
		}
		e, err := json.Marshal(elem(i))
		if err != nil {
			t.Fatal(err)
		}
		b.Write(e)
	}
	b.WriteByte(']')
	return b.Bytes()
}

// An engine with huge names, labels and tags answers a list well under the
// hub's cap on an agent message, marked truncated.
func TestDockerListBounded(t *testing.T) {
	t.Parallel()
	f := startFakeDocker(t)
	// Over maxDockerField and maxDockerTags, yet small: the answer stays a
	// few MiB (20 KiB strings made a 1.6 GB one, over 6 GB of RSS under -race).
	big := strings.Repeat("x", 4*maxDockerField)
	f.containers = jsonArray(t, 400, func(i int) any {
		return map[string]any{
			"Id": big + strconv.Itoa(i), "Names": []string{"/" + big}, "Image": big, "State": big, "Status": big,
			"Labels": map[string]string{"com.docker.compose.project": big, "com.docker.compose.service": big},
		}
	})
	tags := make([]string, 2*maxDockerTags)
	for i := range tags {
		tags[i] = big + strconv.Itoa(i)
	}
	f.images = jsonArray(t, 400, func(i int) any { return map[string]any{"Id": big + strconv.Itoa(i), "RepoTags": tags} })

	res := dockerEngine{sockets: []string{f.socket}}.docker(t.Context(), dockerOn, listReq())
	if res.GetError() != "" {
		t.Fatal(res.GetError())
	}
	if n := proto.Size(res); n > maxDockerResult+64<<10 || !res.GetTruncated() {
		t.Errorf("result %d bytes, truncated %v; want under %d bytes, truncated", n, res.GetTruncated(), maxDockerResult)
	}
	if len(res.GetContainers()) == 0 {
		t.Fatal("no container kept")
	}
	c := res.GetContainers()[0]
	for _, s := range []string{c.GetId(), c.GetName(), c.GetImage(), c.GetState(), c.GetStatus(), c.GetComposeProject(), c.GetComposeService()} {
		if len(s) > maxDockerField {
			t.Errorf("a container field of %d bytes, want at most %d", len(s), maxDockerField)
		}
	}
	for _, i := range res.GetImages() {
		if len(i.GetTags()) > maxDockerTags || len(i.GetId()) > maxDockerField {
			t.Errorf("image with %d tags, id of %d bytes", len(i.GetTags()), len(i.GetId()))
		}
	}
}

// The agent decodes the list one container at a time, stops at the cap,
// never allocates labels other than Compose's, and reads no further: an
// answer far larger than the body limit costs little and comes back
// truncated, not as an error.
func TestDockerListStreams(t *testing.T) { //nolint:paralleltest // measures the process's allocations
	f := startFakeDocker(t)
	labels := map[string]string{"com.docker.compose.project": "media", "com.docker.compose.service": "web"}
	for i := range 64 {
		labels["org.example.label-"+strconv.Itoa(i)] = strings.Repeat("v", 64)
	}
	f.containers = jsonArray(t, 10000, func(i int) any {
		return map[string]any{"Id": "c" + strconv.Itoa(i), "Names": []string{"/web" + strconv.Itoa(i)}, "State": "running", "Labels": labels}
	})
	f.images = []byte(`[]`)
	if len(f.containers) < 50<<20 {
		t.Fatalf("the answer is only %d bytes", len(f.containers))
	}
	d := dockerEngine{sockets: []string{f.socket}}
	d.docker(t.Context(), dockerOn, listReq()) // warm up the client and server

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	res := d.docker(t.Context(), dockerOn, listReq())
	runtime.ReadMemStats(&after)
	if res.GetError() != "" {
		t.Fatal(res.GetError())
	}
	if len(res.GetContainers()) != maxDockerContainers || !res.GetTruncated() {
		t.Errorf("%d containers, truncated %v; want %d, truncated", len(res.GetContainers()), res.GetTruncated(), maxDockerContainers)
	}
	if c := res.GetContainers()[0]; c.GetComposeProject() != "media" || c.GetComposeService() != "web" || c.GetName() != "web0" {
		t.Errorf("first container = %v", c)
	}
	if alloc := after.TotalAlloc - before.TotalAlloc; alloc > 8<<20 {
		t.Errorf("listing allocated %d bytes for a %d-byte answer, want under 8 MiB", alloc, len(f.containers))
	}

	// An element beyond the body limit ends the list, truncated.
	f2 := startFakeDocker(t)
	f2.containers = jsonArray(t, 2, func(i int) any {
		if i == 0 {
			return map[string]any{"Id": "small", "Names": []string{"/small"}}
		}
		return map[string]any{"Id": "huge", "Labels": map[string]string{"x": strings.Repeat("v", maxDockerBody)}}
	})
	f2.images = []byte(`[]`)
	res = dockerEngine{sockets: []string{f2.socket}}.docker(t.Context(), dockerOn, listReq())
	if res.GetError() != "" || len(res.GetContainers()) != 1 || !res.GetTruncated() {
		t.Errorf("over the body limit: %d containers, truncated %v, error %q; want the first, truncated",
			len(res.GetContainers()), res.GetTruncated(), res.GetError())
	}
}

// A redirect from the engine is never followed: a 307 cannot re-send a
// POST to a path the agent did not choose.
func TestDockerNoRedirect(t *testing.T) {
	t.Parallel()
	f := startFakeDocker(t)
	res := dockerEngine{sockets: []string{f.socket}}.docker(t.Context(), dockerOn, actionReq("stop", "moved"))
	if res.GetError() == "" || !strings.Contains(res.GetError(), "307") {
		t.Errorf("stop answered with a redirect = %v, want an error", res)
	}
	for _, r := range f.requests() {
		if strings.Contains(r, "kill") {
			t.Errorf("the agent followed the redirect: %v", f.requests())
		}
	}
}

func TestLooksMultiplexed(t *testing.T) {
	t.Parallel()
	hdr := func(stream byte, n uint32) []byte {
		return frame(stream, strings.Repeat("a", int(n)))
	}
	two := append(hdr(1, 5), hdr(2, 3)...)
	for _, tc := range []struct {
		name string
		b    []byte
		want bool
	}{
		{"two frames", two, true},
		{"one frame", hdr(1, 5), true},
		{"second header cut", append(hdr(1, 5), 2, 0), true},
		{"stdin frame", hdr(0, 3), true},
		{"text", []byte("2026-11-20T11:36:27Z line 1\n"), false},
		{"short", []byte{1, 0, 0}, false},
		{"bad stream", hdr(3, 5), false},
		{"size too large", []byte{1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 'x'}, false},
		{"bad second header", append(hdr(1, 5), []byte("text after it")...), false},
	} {
		if got := looksMultiplexed(tc.b); got != tc.want {
			t.Errorf("%s: looksMultiplexed = %v, want %v", tc.name, got, tc.want)
		}
	}
	// A TTY log whose first bytes happen to look like a header stays text.
	r, err := logStream("", bytes.NewReader([]byte{1, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, '\n', 'h', 'i', '\n'}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := r.(*demux); ok {
		t.Error("a raw log was read as frames")
	}
}
