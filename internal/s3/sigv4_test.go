// SPDX-License-Identifier: AGPL-3.0-only

package s3

import (
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

type vectorFile struct {
	Keys map[string]struct {
		ID     string `json:"id"`
		Secret string `json:"secret"`
	} `json:"keys"`
	Vectors []struct {
		Name          string      `json:"name"`
		Keys          string      `json:"keys"`
		Service       string      `json:"service"`
		Date          string      `json:"date"`
		Method        string      `json:"method"`
		Path          string      `json:"path"`
		Query         string      `json:"query"`
		Headers       [][2]string `json:"headers"`
		Payload       string      `json:"payload"`
		SignedHeaders string      `json:"signed_headers"`
		Signature     string      `json:"signature"`
	} `json:"vectors"`
}

// TestSignMatchesAWSVectors signs AWS's published requests and compares the
// result with AWS's published signatures.
func TestSignMatchesAWSVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/sigv4-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(b, &vf); err != nil {
		t.Fatal(err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range vf.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			at, err := time.Parse(amzDate, v.Date)
			if err != nil {
				t.Fatal(err)
			}
			u := &url.URL{Scheme: "https", Path: v.Path, RawPath: uriEncode(v.Path, true), RawQuery: v.Query}
			req := &http.Request{Method: v.Method, URL: u, Header: http.Header{}}
			for _, h := range v.Headers {
				if strings.EqualFold(h[0], "host") {
					req.Host, u.Host = h[1], h[1]
					continue
				}
				req.Header.Add(h[0], h[1])
			}
			payloadHash := hexSHA256([]byte(v.Payload))
			if v.Service == service {
				req.Header.Set("X-Amz-Content-Sha256", payloadHash)
			}
			k := vf.Keys[v.Keys]
			sign(req, credentials{accessKeyID: k.ID, secretAccessKey: k.Secret}, "us-east-1", v.Service, payloadHash, at)
			want := sigAlgorithm + " Credential=" + k.ID + "/" + v.Date[:8] + "/us-east-1/" + v.Service +
				"/aws4_request, SignedHeaders=" + v.SignedHeaders + ", Signature=" + v.Signature
			if got := req.Header.Get("Authorization"); got != want {
				t.Errorf("Authorization\n got %s\nwant %s", got, want)
			}
		})
	}
}

func TestURIEncode(t *testing.T) {
	for _, tc := range []struct {
		in        string
		keepSlash bool
		want      string
	}{
		{"hearth/hearth-20261119T120000Z.hbk", true, "hearth/hearth-20261119T120000Z.hbk"},
		{"a b+c", false, "a%20b%2Bc"},
		{"a/b", false, "a%2Fb"},
		{"test$file.text", true, "test%24file.text"},
		{"ключ", true, "%D0%BA%D0%BB%D1%8E%D1%87"},
	} {
		if got := uriEncode(tc.in, tc.keepSlash); got != tc.want {
			t.Errorf("uriEncode(%q, %v) = %q, want %q", tc.in, tc.keepSlash, got, tc.want)
		}
	}
}

func TestCanonicalQueryEncodesSpaceAsPercent20(t *testing.T) {
	// A continuation token holds '=' and '/'; a prefix may hold a space.
	got := canonicalQuery("prefix=a%20b&continuation-token=1%2Fx%3D%3D&list-type=2")
	want := "continuation-token=1%2Fx%3D%3D&list-type=2&prefix=a%20b"
	if got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}
