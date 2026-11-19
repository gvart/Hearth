// SPDX-License-Identifier: AGPL-3.0-only

package s3

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeS3 is an S3 API for one bucket that checks every signature the way S3
// does: from the request it received, with the secret it knows.
type fakeS3 struct {
	t      *testing.T
	bucket string
	id     string
	secret string
	region string
	// vhost expects the bucket in the host name.
	vhost bool
	// pageSize is the most keys one listing page holds.
	pageSize int

	mu      sync.Mutex
	objects map[string][]byte
	// requests counts the requests that reached the handler.
	requests int
}

func newFakeS3(t *testing.T) *fakeS3 {
	return &fakeS3{
		t: t, bucket: "backups", id: rand.Text(), secret: rand.Text(), region: "eu-central-1",
		pageSize: 1000, objects: map[string][]byte{},
	}
}

func (f *fakeS3) fail(w http.ResponseWriter, status int, code string) {
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<?xml version=\"1.0\"?><Error><Code>%s</Code><Message>%s, secret %s</Message></Error>", code, code, f.secret)
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests++
	body, err := io.ReadAll(r.Body)
	if err != nil {
		f.fail(w, http.StatusBadRequest, "IncompleteBody")
		return
	}
	if code := f.verify(r, body); code != "" {
		f.fail(w, http.StatusForbidden, code)
		return
	}
	path := r.URL.Path
	if !f.vhost {
		rest, ok := strings.CutPrefix(path, "/"+f.bucket)
		if !ok {
			f.fail(w, http.StatusNotFound, "NoSuchBucket")
			return
		}
		path = rest
	}
	key := strings.TrimPrefix(path, "/")
	switch {
	case r.Method == http.MethodPut && key != "":
		if r.ContentLength != int64(len(body)) || len(r.TransferEncoding) > 0 {
			f.fail(w, http.StatusLengthRequired, "MissingContentLength")
			return
		}
		f.objects[key] = body
	case r.Method == http.MethodDelete && key != "":
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodGet && key == "" && r.URL.Query().Get("list-type") == "2":
		f.list(w, r.URL.Query())
	default:
		f.fail(w, http.StatusNotImplemented, "NotImplemented")
	}
}

func (f *fakeS3) list(w http.ResponseWriter, q url.Values) {
	var keys []string
	for k := range f.objects {
		if strings.HasPrefix(k, q.Get("prefix")) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if tok := q.Get("continuation-token"); tok != "" {
		after, err := base64.StdEncoding.DecodeString(tok)
		if err != nil {
			f.fail(w, http.StatusBadRequest, "InvalidArgument")
			return
		}
		keys = keys[sort.SearchStrings(keys, string(after)+"\x00"):]
	}
	truncated := len(keys) > f.pageSize
	if truncated {
		keys = keys[:f.pageSize]
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
	for _, k := range keys {
		fmt.Fprintf(&b, "<Contents><Key>%s</Key><Size>%d</Size></Contents>", xmlEscape(k), len(f.objects[k]))
	}
	fmt.Fprintf(&b, "<IsTruncated>%v</IsTruncated>", truncated)
	if truncated {
		// Base64 holds '/', '+' and '=', as real tokens do.
		fmt.Fprintf(&b, "<NextContinuationToken>%s</NextContinuationToken>",
			base64.StdEncoding.EncodeToString([]byte(keys[len(keys)-1])))
	}
	b.WriteString("</ListBucketResult>")
	_, _ = io.WriteString(w, b.String())
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
}

// verify signs again what it received and returns the S3 error code of a
// mismatch, or "".
func (f *fakeS3) verify(r *http.Request, body []byte) string {
	auth := r.Header.Get("Authorization")
	cred, rest, ok := strings.Cut(strings.TrimPrefix(auth, sigAlgorithm+" Credential="), ", SignedHeaders=")
	if !ok {
		return "AccessDenied"
	}
	signed, _, ok := strings.Cut(rest, ", Signature=")
	if !ok {
		return "AccessDenied"
	}
	if id, _, _ := strings.Cut(cred, "/"); id != f.id {
		return "InvalidAccessKeyId"
	}
	if !strings.Contains(cred, "/"+f.region+"/s3/aws4_request") {
		return "AuthorizationHeaderMalformed"
	}
	if r.Header.Get("X-Amz-Content-Sha256") != hexSHA256(body) {
		return "XAmzContentSHA256Mismatch"
	}
	at, err := time.Parse(amzDate, r.Header.Get("X-Amz-Date"))
	if err != nil {
		return "AccessDenied"
	}
	again := &http.Request{
		Method: r.Method, Host: r.Host, Header: http.Header{},
		URL: &url.URL{Path: r.URL.Path, RawPath: r.URL.RawPath, RawQuery: r.URL.RawQuery},
	}
	for _, h := range strings.Split(signed, ";") {
		if h != "host" && h != "x-amz-date" {
			again.Header[http.CanonicalHeaderKey(h)] = r.Header.Values(h)
		}
	}
	sign(again, credentials{accessKeyID: f.id, secretAccessKey: f.secret}, f.region, "s3", hexSHA256(body), at)
	if again.Header.Get("Authorization") != auth {
		return "SignatureDoesNotMatch"
	}
	return ""
}

// start serves f and returns a client of it.
func (f *fakeS3) start(t *testing.T) *Client {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cfg := Config{Endpoint: srv.URL, Region: f.region, Bucket: f.bucket, AccessKeyID: f.id, SecretAccessKey: f.secret}
	if f.vhost {
		// bucket.127.0.0.1 resolves nowhere: dial the server whatever the host.
		addr := srv.Listener.Addr().String()
		cfg.VirtualHost = true
		cfg.HTTPClient = &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, addr)
			},
		}}
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestPutListDelete(t *testing.T) {
	for _, tc := range []struct {
		name  string
		vhost bool
	}{{"path style", false}, {"virtual host", true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeS3(t)
			f.vhost = tc.vhost
			f.pageSize = 2 // three pages for five keys
			c := f.start(t)
			ctx := t.Context()
			keys := []string{"hearth/a.hbk", "hearth/b $+=.hbk", "hearth/c.hbk", "hearth/d/e.hbk", "hearth/f.hbk"}
			for i, k := range keys {
				data := bytes.Repeat([]byte{byte(i)}, 1000*i)
				if err := c.Put(ctx, k, bytes.NewReader(data), int64(len(data))); err != nil {
					t.Fatalf("put %s: %v", k, err)
				}
				if !bytes.Equal(f.objects[k], data) {
					t.Fatalf("%s: stored %d bytes, want %d", k, len(f.objects[k]), len(data))
				}
			}
			if err := c.Put(ctx, "other/x.hbk", bytes.NewReader(nil), 0); err != nil {
				t.Fatal(err)
			}
			got, err := c.List(ctx, "hearth/")
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, keys) {
				t.Fatalf("list = %q, want %q", got, keys)
			}
			if err := c.Delete(ctx, "hearth/b $+=.hbk"); err != nil {
				t.Fatal(err)
			}
			if err := c.Delete(ctx, "hearth/missing.hbk"); err != nil {
				t.Fatalf("delete of a missing key: %v", err)
			}
			if _, ok := f.objects["hearth/b $+=.hbk"]; ok {
				t.Fatal("object not deleted")
			}
			if _, ok := f.objects["other/x.hbk"]; !ok {
				t.Fatal("object outside the prefix deleted")
			}
		})
	}
}

func TestRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*Config)
		code   string
	}{
		{"wrong secret", func(c *Config) { c.SecretAccessKey = rand.Text() }, "SignatureDoesNotMatch"},
		{"unknown access key", func(c *Config) { c.AccessKeyID = rand.Text() }, "InvalidAccessKeyId"},
		{"wrong region", func(c *Config) { c.Region = "us-west-2" }, "AuthorizationHeaderMalformed"},
		{"wrong bucket", func(c *Config) { c.Bucket = "elsewhere" }, "NoSuchBucket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeS3(t)
			srv := httptest.NewServer(f)
			t.Cleanup(srv.Close)
			cfg := Config{Endpoint: srv.URL, Region: f.region, Bucket: f.bucket, AccessKeyID: f.id, SecretAccessKey: f.secret}
			tc.change(&cfg)
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			err = c.Put(t.Context(), "k", strings.NewReader("data"), 4)
			if !errors.Is(err, ErrHTTP) || !strings.Contains(err.Error(), tc.code) {
				t.Fatalf("put: %v, want %s", err, tc.code)
			}
			for _, secret := range []string{f.secret, cfg.SecretAccessKey} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error holds a secret: %v", err)
				}
			}
			if _, err := c.List(t.Context(), ""); !errors.Is(err, ErrHTTP) {
				t.Fatalf("list: %v", err)
			}
			if len(f.objects) != 0 {
				t.Fatal("refused put stored an object")
			}
		})
	}
}

func TestUnreachableEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	endpoint := srv.URL
	srv.Close()
	c, err := New(Config{Endpoint: endpoint, Bucket: "bkt", AccessKeyID: rand.Text(), SecretAccessKey: rand.Text()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := c.Put(ctx, "k", strings.NewReader("x"), 1); err == nil || errors.Is(err, ErrHTTP) {
		t.Fatalf("put to a closed port: %v", err)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var hits int
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	t.Cleanup(other.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(srv.Close)
	c, err := New(Config{Endpoint: srv.URL, Bucket: "bkt", AccessKeyID: rand.Text(), SecretAccessKey: rand.Text()})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Put(t.Context(), "k", strings.NewReader("x"), 1); !errors.Is(err, ErrHTTP) || !strings.Contains(err.Error(), "307") {
		t.Fatalf("put: %v", err)
	}
	if hits != 0 {
		t.Fatal("redirect followed: the signed request went to another host")
	}
}

func TestNewRefusesBadConfig(t *testing.T) {
	id, secret := rand.Text(), rand.Text()
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		{"no scheme", Config{Endpoint: "minio.lan:9000", Bucket: "bkt", AccessKeyID: id, SecretAccessKey: secret}},
		{"ftp", Config{Endpoint: "ftp://minio.lan", Bucket: "bkt", AccessKeyID: id, SecretAccessKey: secret}},
		{"path", Config{Endpoint: "http://minio.lan/bucket", Bucket: "bkt", AccessKeyID: id, SecretAccessKey: secret}},
		{"user info", Config{Endpoint: "http://user@minio.lan", Bucket: "bkt", AccessKeyID: id, SecretAccessKey: secret}},
		{"no bucket", Config{Endpoint: "http://minio.lan", AccessKeyID: id, SecretAccessKey: secret}},
		{"bucket with slash", Config{Endpoint: "http://minio.lan", Bucket: "a/b", AccessKeyID: id, SecretAccessKey: secret}},
		{"no access key", Config{Endpoint: "http://minio.lan", Bucket: "bkt", SecretAccessKey: secret}},
		{"no secret", Config{Endpoint: "http://minio.lan", Bucket: "bkt", AccessKeyID: id}},
		// Credentials in the endpoint never reach the error.
		{"credentials in the endpoint", Config{Endpoint: "https://" + id + ":" + secret + "@minio.lan", Bucket: "bkt", AccessKeyID: id, SecretAccessKey: secret}},
		{"unparsable endpoint with credentials", Config{Endpoint: "https://" + id + ":" + secret + "@[::1", Bucket: "bkt", AccessKeyID: id, SecretAccessKey: secret}},
		{"bucket name with capitals", Config{Endpoint: "http://minio.lan", Bucket: "Backups", AccessKeyID: id, SecretAccessKey: secret}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("accepted")
			} else if strings.Contains(err.Error(), secret) {
				t.Fatalf("error holds the secret: %v", err)
			}
		})
	}
}
