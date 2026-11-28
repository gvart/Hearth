// SPDX-License-Identifier: AGPL-3.0-only

package ai

import (
	"fmt"
	"strings"
)

// DefaultContextBytes bounds what one question sends about its subject,
// before redaction: about 6000 tokens, which fits the default context window
// of a small local model with room for the answer.
const DefaultContextBytes = 24 << 10

// maxQuestion bounds the operator's own question.
const maxQuestion = 2000

// DefaultQuestion is asked when the operator asks nothing in particular.
const DefaultQuestion = "Is anything wrong with it? If so, what is the most likely cause, and how would I fix it?"

// Section is one piece of evidence: an ID the answer cites, a title, and the
// text itself.
type Section struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	Body  string `json:"body"`
	// KeepTail cuts a section too long from its start, keeping its newest
	// lines: for logs.
	KeepTail bool `json:"-"`
}

// Explain is a question about one subject (a device, an entity) and the
// evidence gathered for it, most useful first.
type Explain struct {
	// Subject names what is asked about, such as "device pi4 (raspberrypi)".
	Subject  string
	Question string
	Sections []Section
}

// Prepared is an explain request as it will be sent: redacted and within its
// limits. Request is exactly what goes to the provider.
type Prepared struct {
	Request Request
	// Redactions counts the values Redact replaced.
	Redactions int
	// Truncated names the sections cut to fit.
	Truncated []string
}

// explainSystem tells the model what it is for. It never acts: what it
// suggests, the operator runs through Hearth, where policy decides.
const explainSystem = `You are the troubleshooting assistant of Hearth, a self-hosted control plane for a homelab.
You are given evidence about one device or entity: its facts, its status, a summary of its recent metrics, recent entries of Hearth's audit log about it, and sometimes the tail of a log.
Explain what is most likely wrong, or say plainly that nothing looks wrong. Be concise and concrete.
Cite the evidence you rely on by its section ID in square brackets, such as [metrics] or [audit], and quote the line that matters when there is one.
Do not invent facts that are not in the evidence; say what else you would need to look at.
You cannot run anything. If an action would help, suggest it as a step the operator can take (a Hearth action in the web UI, or a command to run on the device), and say what it changes.
Values shown as [REDACTED] were removed before you saw them.`

// PrepareExplain builds the request for e: the evidence cut to maxBytes
// (0: DefaultContextBytes), shared fairly between sections, then redacted as
// a whole, the question too.
func PrepareExplain(e Explain, maxBytes int) Prepared {
	if maxBytes <= 0 {
		maxBytes = DefaultContextBytes
	}
	question := strings.TrimSpace(e.Question)
	if question == "" {
		question = DefaultQuestion
	}
	if len(question) > maxQuestion {
		question = strings.ToValidUTF8(question[:maxQuestion], "")
	}

	var p Prepared
	var b strings.Builder
	fmt.Fprintf(&b, "Subject: %s\n\nQuestion: %s\n\nEvidence:\n", e.Subject, question)
	remaining := maxBytes
	for i, s := range e.Sections {
		// Each section gets its share of what is left; a short one leaves
		// the rest to those after it.
		share := remaining / (len(e.Sections) - i)
		body := strings.TrimRight(s.Body, "\n")
		if body == "" {
			body = "(none)"
		}
		if len(body) > share {
			p.Truncated = append(p.Truncated, s.ID)
			body = cut(body, share, s.KeepTail)
		}
		remaining -= len(body)
		fmt.Fprintf(&b, "\n## [%s] %s\n%s\n", s.ID, s.Title, body)
	}
	r := Redact(b.String())
	p.Redactions = r.Count
	p.Request = Request{System: explainSystem, Messages: []Message{{Role: RoleUser, Content: r.Text}}}
	return p
}

// cut shortens s to at most n bytes at a line break, keeping its start, or
// its end with tail, and says so.
func cut(s string, n int, tail bool) string {
	const note = "… (cut to fit)"
	if n <= len(note)+1 {
		return note
	}
	n -= len(note) + 1
	if tail {
		s = s[len(s)-n:]
		if i := strings.IndexByte(s, '\n'); i >= 0 && i < len(s)-1 {
			s = s[i+1:]
		}
		return note + "\n" + strings.ToValidUTF8(s, "")
	}
	s = s[:n]
	if i := strings.LastIndexByte(s, '\n'); i > 0 {
		s = s[:i]
	}
	return strings.ToValidUTF8(s, "") + "\n" + note
}
