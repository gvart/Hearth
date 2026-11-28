// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/store"
)

// pushedTo records the Hubs messages sent on one fake stream.
type pushedTo struct {
	mu   sync.Mutex
	got  [][]string
	fail atomic.Bool
}

func (p *pushedTo) send(m *agentv1.HubMessage) error {
	if p.fail.Load() {
		return ErrAgentNotConnected
	}
	if h := m.GetHubs(); h != nil {
		p.mu.Lock()
		p.got = append(p.got, h.GetUrls())
		p.mu.Unlock()
	}
	return nil
}

func (p *pushedTo) lists() [][]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.got)
}

// attachFake attaches a stream whose Welcome listed welcomed.
func attachFake(a *Agents, id string, welcomed []string) *pushedTo {
	p := &pushedTo{}
	s, _ := a.attach(id, &agentv1.Hello{}, nil, p.send, func() {})
	s.setHubs(welcomed)
	return p
}

// hubList is a hub list a test changes under RunHubsPush.
type hubList struct {
	mu   sync.Mutex
	urls []string
}

func (l *hubList) set(urls ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.urls = urls
}

func (l *hubList) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.urls)
}

func TestPushHubsDedupes(t *testing.T) {
	const a, b, c = "https://a:7443", "https://b:7443", "https://c:7443"
	tests := []struct {
		name     string
		welcomed []string
		pushes   [][]string
		want     [][]string
	}{
		{name: "same as welcome", welcomed: []string{a, b}, pushes: [][]string{{a, b}}},
		{name: "new master", welcomed: []string{a}, pushes: [][]string{{a, b}}, want: [][]string{{a, b}}},
		{name: "repeated", welcomed: []string{a}, pushes: [][]string{{a, b}, {a, b}, {a, b}}, want: [][]string{{a, b}}},
		{name: "empty never sent", welcomed: []string{a}, pushes: [][]string{nil, {}}},
		{
			name: "master gone", welcomed: []string{a, b}, pushes: [][]string{{a, b, c}, {a, c}},
			want: [][]string{{a, b, c}, {a, c}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ag := NewAgents(store.Devices{})
			p := attachFake(ag, "dev", tt.welcomed)
			for _, urls := range tt.pushes {
				ag.PushHubs(urls)
			}
			if got := p.lists(); !slices.EqualFunc(got, tt.want, slices.Equal) {
				t.Errorf("pushed %v, want %v", got, tt.want)
			}
		})
	}
}

// TestPushHubsRetriesAfterFailedSend: a stream the list did not reach is
// sent it again on the next push.
func TestPushHubsRetriesAfterFailedSend(t *testing.T) {
	ag := NewAgents(store.Devices{})
	p := attachFake(ag, "dev", []string{"https://a:7443"})
	p.fail.Store(true)
	ag.PushHubs([]string{"https://a:7443", "https://b:7443"})
	p.fail.Store(false)
	ag.PushHubs([]string{"https://a:7443", "https://b:7443"})
	if got := p.lists(); len(got) != 1 {
		t.Errorf("pushed %v, want the list once", got)
	}
}

// TestRunHubsPushDebounces: a burst of master changes pushes once, to every
// stream, after the masters have been still for the debounce.
func TestRunHubsPushDebounces(t *testing.T) {
	ag := NewAgents(store.Devices{})
	ag.hubsDebounce, ag.hubsRecheck = 50*time.Millisecond, time.Hour
	list := &hubList{}
	list.set("https://a:7443")
	p1 := attachFake(ag, "dev1", list.get())
	p2 := attachFake(ag, "dev2", list.get())
	changed := make(chan struct{}, 1)
	go func() { _ = ag.RunHubsPush(t.Context(), list.get, changed) }()

	list.set("https://a:7443", "https://b:7443")
	for range 20 {
		changed <- struct{}{}
		time.Sleep(5 * time.Millisecond)
	}
	waitUntil(t, func() bool { return len(p1.lists()) == 1 && len(p2.lists()) == 1 })
	time.Sleep(200 * time.Millisecond) // no further pushes
	for _, p := range []*pushedTo{p1, p2} {
		if got := p.lists(); len(got) != 1 || !slices.Equal(got[0], list.get()) {
			t.Errorf("pushed %v, want [%v] once", got, list.get())
		}
	}
}

// TestRunHubsPushRechecksLateURL: a master whose URL is recorded after the
// ring changed still reaches the agents, by the periodic re-read.
func TestRunHubsPushRechecksLateURL(t *testing.T) {
	ag := NewAgents(store.Devices{})
	ag.hubsDebounce, ag.hubsRecheck = 10*time.Millisecond, 50*time.Millisecond
	list := &hubList{}
	list.set("https://a:7443")
	p := attachFake(ag, "dev", list.get())
	changed := make(chan struct{}, 1)
	go func() { _ = ag.RunHubsPush(t.Context(), list.get, changed) }()

	changed <- struct{}{} // the ring changed, the URL is not recorded yet
	time.Sleep(30 * time.Millisecond)
	if got := p.lists(); len(got) != 0 {
		t.Fatalf("pushed %v before the list changed", got)
	}
	list.set("https://a:7443", "https://b:7443")
	waitUntil(t, func() bool { return len(p.lists()) == 1 })
	time.Sleep(200 * time.Millisecond) // rechecks of an unchanged list push nothing
	if got := p.lists(); len(got) != 1 {
		t.Errorf("pushed %v, want the new list once", got)
	}
}
