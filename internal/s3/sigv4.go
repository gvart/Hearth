// SPDX-License-Identifier: AGPL-3.0-only

package s3

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	sigAlgorithm = "AWS4-HMAC-SHA256"
	// amzDate is the layout of X-Amz-Date.
	amzDate = "20060102T150405Z"
	// emptySHA256 is the hex SHA-256 of an empty payload.
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// credentials sign requests. They are never logged or put into an error.
type credentials struct {
	accessKeyID     string
	secretAccessKey string
}

// sign adds the X-Amz-Date and Authorization headers of AWS Signature
// Version 4 to req. Every header req holds at that point is signed, with
// Host. payloadHash is the hex SHA-256 of the body.
func sign(req *http.Request, creds credentials, region, service, payloadHash string, now time.Time) {
	now = now.UTC()
	req.Header.Set("X-Amz-Date", now.Format(amzDate))
	day := now.Format("20060102")

	names, canonHeaders := canonicalHeaders(req)
	canonReq := strings.Join([]string{
		req.Method,
		canonicalURI(req.URL),
		canonicalQuery(req.URL.RawQuery),
		canonHeaders,
		names,
		payloadHash,
	}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	toSign := sigAlgorithm + "\n" + now.Format(amzDate) + "\n" + scope + "\n" + hexSHA256([]byte(canonReq))

	key := hmacSHA256([]byte("AWS4"+creds.secretAccessKey), day)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, service)
	key = hmacSHA256(key, "aws4_request")
	sig := hex.EncodeToString(hmacSHA256(key, toSign))

	req.Header.Set("Authorization", sigAlgorithm+" Credential="+creds.accessKeyID+"/"+scope+
		", SignedHeaders="+names+", Signature="+sig)
}

// canonicalHeaders returns the signed header names and the canonical
// headers block: lowercase names, sorted, values trimmed with inner runs of
// spaces collapsed.
func canonicalHeaders(req *http.Request) (names, block string) {
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	values := map[string]string{"host": host}
	for k, vs := range req.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" {
			continue
		}
		trimmed := make([]string, len(vs))
		for i, v := range vs {
			trimmed[i] = strings.Join(strings.Fields(v), " ")
		}
		values[lk] = strings.Join(trimmed, ",")
	}
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte(':')
		b.WriteString(values[k])
		b.WriteByte('\n')
	}
	return strings.Join(keys, ";"), b.String()
}

// canonicalURI is the path exactly as it is sent. S3 paths are encoded once.
func canonicalURI(u *url.URL) string {
	if p := u.EscapedPath(); p != "" {
		return p
	}
	return "/"
}

// canonicalQuery sorts the query by key and value, each encoded as SigV4
// requires: a space is %20, never +.
func canonicalQuery(raw string) string {
	if raw == "" {
		return ""
	}
	vals, err := url.ParseQuery(raw)
	if err != nil {
		// Only this package builds queries, and it builds valid ones.
		return raw
	}
	var pairs []string
	for k, vs := range vals {
		for _, v := range vs {
			pairs = append(pairs, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	sort.Strings(pairs)
	return strings.Join(pairs, "&")
}

// uriEncode percent-encodes every byte but the unreserved characters, and
// '/' when keepSlash is set.
func uriEncode(s string, keepSlash bool) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := range len(s) {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~', keepSlash && c == '/':
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0xf])
		}
	}
	return b.String()
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	_, _ = m.Write([]byte(data))
	return m.Sum(nil)
}

func hexSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
