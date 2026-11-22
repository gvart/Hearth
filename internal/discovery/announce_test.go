// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"net/netip"
	"slices"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func query(t *testing.T, id uint16, response bool, qs ...dnsmessage.Question) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: response})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			t.Fatal(err)
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

func q(name string, typ dnsmessage.Type, class dnsmessage.Class) dnsmessage.Question {
	return dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: typ, Class: class}
}

// TestLANNameReply: the announcer answers A (and ANY) questions for its
// name with the interface's addresses, in either case and with the
// unicast-response bit; an AAAA question gets an NSEC and the A records as
// additionals; it ignores other names, responses and having no address.
func TestLANNameReply(t *testing.T) {
	name := dnsmessage.MustNewName("hearth.local.")
	lan := []netip.Addr{netip.MustParseAddr("192.168.2.124"), netip.MustParseAddr("10.0.5.2")}
	in := dnsmessage.ClassINET
	qu := dnsmessage.ClassINET | classCacheFlush
	tests := []struct {
		name     string
		msg      []byte
		addrs    []netip.Addr
		legacy   bool
		answers  []dnsmessage.Type
		extras   []dnsmessage.Type
		noAnswer bool
	}{
		{
			name: "A", msg: query(t, 0, false, q("hearth.local.", dnsmessage.TypeA, in)), addrs: lan,
			answers: []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeA},
		},
		{
			name: "unicast-response bit", msg: query(t, 0, false, q("hearth.local.", dnsmessage.TypeA, qu)), addrs: lan,
			answers: []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeA},
		},
		{
			name: "mixed case", msg: query(t, 0, false, q("Hearth.LOCAL.", dnsmessage.TypeA, in)), addrs: lan[:1],
			answers: []dnsmessage.Type{dnsmessage.TypeA},
		},
		{
			name: "ANY", msg: query(t, 0, false, q("hearth.local.", dnsmessage.TypeALL, in)), addrs: lan[:1],
			answers: []dnsmessage.Type{dnsmessage.TypeA},
		},
		{
			name: "A and AAAA", msg: query(t, 0, false, q("hearth.local.", dnsmessage.TypeA, in), q("hearth.local.", dnsmessage.TypeAAAA, in)),
			addrs: lan[:1], answers: []dnsmessage.Type{dnsmessage.TypeA, typeNSEC},
		},
		{
			name: "AAAA only", msg: query(t, 0, false, q("hearth.local.", dnsmessage.TypeAAAA, in)), addrs: lan[:1],
			answers: []dnsmessage.Type{typeNSEC}, extras: []dnsmessage.Type{dnsmessage.TypeA},
		},
		{
			name: "legacy unicast", msg: query(t, 4242, false, q("hearth.local.", dnsmessage.TypeA, in)), addrs: lan[:1], legacy: true,
			answers: []dnsmessage.Type{dnsmessage.TypeA},
		},
		{name: "another name", msg: query(t, 0, false, q("nas.local.", dnsmessage.TypeA, in)), addrs: lan, noAnswer: true},
		{name: "a prefix of the name", msg: query(t, 0, false, q("x.hearth.local.", dnsmessage.TypeA, in)), addrs: lan, noAnswer: true},
		{name: "a response", msg: query(t, 0, true, q("hearth.local.", dnsmessage.TypeA, in)), addrs: lan, noAnswer: true},
		{name: "another class", msg: query(t, 0, false, q("hearth.local.", dnsmessage.TypeA, dnsmessage.ClassCHAOS)), addrs: lan, noAnswer: true},
		{name: "no address on the interface", msg: query(t, 0, false, q("hearth.local.", dnsmessage.TypeA, in)), noAnswer: true},
		{name: "garbage", msg: []byte{1, 2, 3}, addrs: lan, noAnswer: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reply, _ := lanNameReply(tt.msg, name, tt.addrs, tt.legacy)
			if tt.noAnswer {
				if reply != nil {
					t.Fatalf("got a reply, want none")
				}
				return
			}
			var m dnsmessage.Message
			if err := m.Unpack(reply); err != nil {
				t.Fatal(err)
			}
			if !m.Response || !m.Authoritative {
				t.Errorf("header %+v, want an authoritative response", m.Header)
			}
			var answers, extras []dnsmessage.Type
			var got []netip.Addr
			check := func(r dnsmessage.Resource) {
				if r.Header.Name.String() != "hearth.local." || r.Header.TTL != announceTTL {
					t.Errorf("record %v, want hearth.local. with TTL %d", r.Header, announceTTL)
				}
				if flush := r.Header.Class&classCacheFlush != 0; flush == tt.legacy {
					t.Errorf("legacy %v: record class %#x", tt.legacy, uint16(r.Header.Class))
				}
				if a, ok := r.Body.(*dnsmessage.AResource); ok {
					got = append(got, netip.AddrFrom4(a.A))
				}
			}
			for _, r := range m.Answers {
				answers = append(answers, r.Header.Type)
				check(r)
			}
			for _, r := range m.Additionals {
				extras = append(extras, r.Header.Type)
				check(r)
			}
			if !slices.Equal(answers, tt.answers) || !slices.Equal(extras, tt.extras) {
				t.Errorf("answers %v, additionals %v; want %v, %v", answers, extras, tt.answers, tt.extras)
			}
			if !slices.Equal(got, tt.addrs) {
				t.Errorf("addresses %v, want %v", got, tt.addrs)
			}
			if tt.legacy {
				if m.ID != 4242 || len(m.Questions) != 1 {
					t.Errorf("legacy reply ID %d, questions %v; want the query's", m.ID, m.Questions)
				}
			} else if m.ID != 0 || len(m.Questions) != 0 {
				t.Errorf("multicast reply ID %d, questions %v; want 0 and none", m.ID, m.Questions)
			}
		})
	}
}

// TestLANNameNSEC: the NSEC record says hearth.local has A records only.
func TestLANNameNSEC(t *testing.T) {
	name := dnsmessage.MustNewName("hearth.local.")
	reply, err := lanNameReply(query(t, 0, false, q("hearth.local.", dnsmessage.TypeAAAA, dnsmessage.ClassINET)), name,
		[]netip.Addr{netip.MustParseAddr("192.168.2.124")}, false)
	if err != nil {
		t.Fatal(err)
	}
	var m dnsmessage.Message
	if err := m.Unpack(reply); err != nil {
		t.Fatal(err)
	}
	u, ok := m.Answers[0].Body.(*dnsmessage.UnknownResource)
	if !ok {
		t.Fatalf("answer %T, want an NSEC", m.Answers[0].Body)
	}
	want := append([]byte("\x06hearth\x05local\x00"), 0, 1, 0x40)
	if !slices.Equal(u.Data, want) {
		t.Errorf("NSEC data %q, want %q", u.Data, want)
	}
}

// TestLANNameAnnouncement: an announcement carries the A records with the
// cache-flush bit, so clients replace another master's addresses; a goodbye
// has TTL 0.
func TestLANNameAnnouncement(t *testing.T) {
	name := dnsmessage.MustNewName("hearth.local.")
	addrs := []netip.Addr{netip.MustParseAddr("192.168.2.124")}
	for _, ttl := range []uint32{announceTTL, 0} {
		msg, err := lanNameAnnouncement(name, addrs, ttl)
		if err != nil {
			t.Fatal(err)
		}
		var m dnsmessage.Message
		if err := m.Unpack(msg); err != nil {
			t.Fatal(err)
		}
		if !m.Response || len(m.Questions) != 0 || len(m.Answers) != 1 {
			t.Fatalf("announcement %+v, want one answer and no question", m)
		}
		h := m.Answers[0].Header
		a, ok := m.Answers[0].Body.(*dnsmessage.AResource)
		if !ok || netip.AddrFrom4(a.A) != addrs[0] || h.TTL != ttl || h.Class != dnsmessage.ClassINET|classCacheFlush {
			t.Errorf("record %v %v, want A %v TTL %d with the cache-flush bit", h, m.Answers[0].Body, addrs[0], ttl)
		}
	}
	if _, err := lanNameAnnouncement(name, nil, announceTTL); err == nil {
		t.Error("announcement without an address: want an error")
	}
}
