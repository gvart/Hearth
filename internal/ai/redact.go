// SPDX-License-Identifier: AGPL-3.0-only

package ai

import (
	"regexp"
	"strings"
)

// Redacted is text with credentials replaced by placeholders.
type Redacted struct {
	Text string
	// Count is the number of values replaced.
	Count int
}

// Mask replaces a redacted value.
const Mask = "[REDACTED]"

// redaction is one pattern and what a match becomes; repl may use the
// pattern's groups.
type redaction struct {
	re   *regexp.Regexp
	repl string
}

// redactions run in order: whole blocks first, then values that name
// themselves (headers, URLs, known token formats), then key = value pairs.
var redactions = []redaction{
	// PEM blocks: private keys, and certificates, which are never sent in
	// full either. A block cut off before its END line goes to the end.
	{regexp.MustCompile(`-----BEGIN [A-Z0-9 ]+-----[\s\S]*?(?:-----END [A-Z0-9 ]+-----|\z)`), "[REDACTED PEM BLOCK]"},
	// SSH public and private key bodies on one line (authorized_keys).
	{regexp.MustCompile(`\b(ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp\d+) AAAA[A-Za-z0-9+/=]{20,}`), "$1 " + Mask},
	// Authorization headers, whatever the scheme.
	{regexp.MustCompile(`(?i)\b((?:proxy-)?authorization\s*[:=]\s*)(?:(?:bearer|basic|token|digest)\s+)?[^\s"',;]+`), "${1}" + Mask},
	// A bearer token anywhere else.
	{regexp.MustCompile(`(?i)\b(bearer\s+)[A-Za-z0-9\-._~+/]{8,}=*`), "${1}" + Mask},
	// Credentials in a URL: scheme://user:password@host.
	{regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]*://[^/\s:@]*:)[^/\s@]+@`), "${1}" + Mask + "@"},
	// Hearth's own enrollment, join, MCP and dashboard tokens.
	{regexp.MustCompile(`\bhearth(?:1|2|j1)\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+`), Mask},
	{regexp.MustCompile(`\bhearth_[a-z]+_[A-Za-z0-9_\-]{16,}`), Mask},
	// Well-known API key and token formats.
	{regexp.MustCompile(`\bsk-(?:ant-|proj-)?[A-Za-z0-9_\-]{16,}`), Mask},
	{regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|glpat-[A-Za-z0-9_\-]{20,})`), Mask},
	{regexp.MustCompile(`\bxox[abposr]-[A-Za-z0-9\-]{10,}`), Mask},
	{regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), Mask},
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), Mask},
	// JSON web tokens.
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`), Mask},
	// key = value, key: value and "key": "value", where the key names a
	// secret: PASSWORD=..., api_key: ..., "token": "...".
	{
		regexp.MustCompile(`(?i)\b([\w.\-]*(?:passw(?:or)?d|passphrase|pwd|secret|token|api[_\-]?key|access[_\-]?key|private[_\-]?key|credentials?|auth[_\-]?key|session[_\-]?id|cookie)[\w.\-]*["']?\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s,;&"']+)`),
		"${1}" + Mask,
	},
}

// Redact replaces the credentials in s: PEM blocks, authorization headers and
// bearer tokens, passwords in URLs, Hearth's tokens, well-known API key
// formats, JSON web tokens, and the values of keys that name a secret
// (password, token, api_key, secret...). It errs on the side of hiding:
// "token_count: 5" loses its 5.
func Redact(s string) Redacted {
	out := Redacted{Text: s}
	for _, r := range redactions {
		out.Text = r.re.ReplaceAllStringFunc(out.Text, func(m string) string {
			repl := r.re.ReplaceAllString(m, r.repl)
			// A value already masked is not counted again.
			if strings.Contains(m, Mask) || strings.Contains(m, "[REDACTED PEM BLOCK]") {
				return m
			}
			out.Count++
			return repl
		})
	}
	return out
}
