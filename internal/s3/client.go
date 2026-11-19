// SPDX-License-Identifier: AGPL-3.0-only

// Package s3 is a small client of the S3 API for one bucket: put, list and
// delete objects, signed with AWS Signature Version 4. It works with AWS S3
// and S3-compatible stores such as MinIO, Garage and Backblaze B2. Errors
// never hold the credentials or a response body, only the S3 error code.
package s3

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	service = "s3"
	// maxListBody bounds a ListObjectsV2 answer, about 1000 keys.
	maxListBody = 8 << 20
	// maxErrorBody bounds the error document read for its code.
	maxErrorBody = 64 << 10
	// maxListPages bounds a listing at a million keys.
	maxListPages = 1000
	// maxErrorCode bounds the S3 error code put into an error.
	maxErrorCode = 64
)

// bucketName is an S3 bucket name: 3 to 63 lowercase letters, digits, dots
// and hyphens, starting and ending with a letter or a digit.
var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// validBucket applies the S3 bucket naming rules.
func validBucket(name string) bool {
	return bucketName.MatchString(name) && !strings.Contains(name, "..") && net.ParseIP(name) == nil
}

// ErrHTTP is the error of a request S3 answered with a failure status.
var ErrHTTP = errors.New("s3 request failed")

// Config configures a Client.
type Config struct {
	// Endpoint is the S3 API's base URL, such as
	// https://s3.eu-central-1.amazonaws.com or http://minio.lan:9000.
	Endpoint string
	// Region is the signing region; empty means us-east-1.
	Region string
	Bucket string
	// AccessKeyID and SecretAccessKey sign the requests.
	AccessKeyID     string
	SecretAccessKey string
	// VirtualHost addresses the bucket as a host name (bucket.endpoint)
	// rather than as the first path segment.
	VirtualHost bool
	// HTTPClient sends the requests; nil means one that follows no redirect.
	HTTPClient *http.Client
	// now is the signing clock, for tests.
	now func() time.Time
}

// Client puts, lists and deletes the objects of one bucket.
type Client struct {
	base   *url.URL
	region string
	bucket string
	creds  credentials
	vhost  bool
	http   *http.Client
	now    func() time.Time
}

// New checks cfg and returns its client.
func New(cfg Config) (*Client, error) {
	// Neither error quotes the endpoint as given: it may hold credentials.
	u, err := url.Parse(cfg.Endpoint)
	if err != nil {
		return nil, errors.New("endpoint: not a URL; want http(s)://host[:port]")
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("endpoint %s: want http(s)://host[:port], with no credentials and no path", u.Redacted())
	}
	if !validBucket(cfg.Bucket) {
		return nil, fmt.Errorf("bucket %q: not a valid S3 bucket name (3 to 63 lowercase letters, digits, dots and hyphens)", cfg.Bucket)
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, errors.New("an access key ID and a secret access key are needed")
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{
			// A redirect would replay the signed request to another URL.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	now := cfg.now
	if now == nil {
		now = time.Now
	}
	return &Client{
		base: &url.URL{Scheme: u.Scheme, Host: u.Host}, region: region, bucket: cfg.Bucket,
		creds: credentials{accessKeyID: cfg.AccessKeyID, secretAccessKey: cfg.SecretAccessKey},
		vhost: cfg.VirtualHost, http: hc, now: now,
	}, nil
}

// objectURL is the URL of key, or of the bucket when key is empty.
func (c *Client) objectURL(key string, query string) *url.URL {
	u := *c.base
	p := "/" + key
	if c.vhost {
		u.Host = c.bucket + "." + u.Host
	} else if key == "" {
		p = "/" + c.bucket
	} else {
		p = "/" + c.bucket + p
	}
	u.Path = p
	u.RawPath = uriEncode(p, true)
	u.RawQuery = query
	return &u
}

// do signs and sends one request, and fails unless S3 answers 2xx. The
// caller closes the body of a successful answer.
func (c *Client) do(ctx context.Context, method string, u *url.URL, body io.Reader, size int64, payloadHash string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("s3 %s: %w", method, err)
	}
	// String() keeps RawPath, so the path sent is the path signed.
	req.URL = u
	if body != nil {
		req.ContentLength = size
	}
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	sign(req, c.creds, c.region, service, payloadHash, c.now())
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("s3 %s %s: %w", method, u.Redacted(), err)
	}
	if resp.StatusCode/100 == 2 {
		return resp, nil
	}
	defer resp.Body.Close()
	return nil, fmt.Errorf("%w: %s %s: HTTP %d%s", ErrHTTP, method, u.Redacted(), resp.StatusCode, errorCode(resp.Body))
}

// errorCode reads the code of an S3 error document, such as AccessDenied.
func errorCode(r io.Reader) string {
	var doc struct {
		Code string `xml:"Code"`
	}
	if xml.NewDecoder(io.LimitReader(r, maxErrorBody)).Decode(&doc) != nil || doc.Code == "" {
		return ""
	}
	if len(doc.Code) > maxErrorCode {
		doc.Code = doc.Code[:maxErrorCode]
	}
	return " " + doc.Code
}

// Put uploads size bytes of body as key, replacing any object of that name.
// body is read twice: once for its hash, then to send it.
func (c *Client) Put(ctx context.Context, key string, body io.ReadSeeker, size int64) error {
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(body, size)); err != nil {
		return fmt.Errorf("s3 put %s: hash: %w", key, err)
	}
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("s3 put %s: %w", key, err)
	}
	// NoBody for an empty object, so ContentLength 0 is sent as such.
	r := io.LimitReader(body, size)
	if size == 0 {
		r = http.NoBody
	}
	resp, err := c.do(ctx, http.MethodPut, c.objectURL(key, ""), r, size, hex.EncodeToString(h.Sum(nil)))
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
	return resp.Body.Close()
}

// Delete removes key. Deleting a key that does not exist succeeds.
func (c *Client) Delete(ctx context.Context, key string) error {
	resp, err := c.do(ctx, http.MethodDelete, c.objectURL(key, ""), nil, 0, emptySHA256)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

// List returns the keys under prefix, in the order S3 lists them (UTF-8
// binary order).
func (c *Client) List(ctx context.Context, prefix string) ([]string, error) {
	var keys []string
	token := ""
	for range maxListPages {
		q := "list-type=2&prefix=" + uriEncode(prefix, false)
		if token != "" {
			q += "&continuation-token=" + uriEncode(token, false)
		}
		page, err := c.listPage(ctx, q)
		if err != nil {
			return nil, err
		}
		for _, o := range page.Contents {
			keys = append(keys, o.Key)
		}
		if !page.IsTruncated {
			return keys, nil
		}
		if page.NextContinuationToken == "" {
			return nil, errors.New("s3 list: truncated answer without a continuation token")
		}
		token = page.NextContinuationToken
	}
	return nil, fmt.Errorf("s3 list: more than %d pages", maxListPages)
}

type listResult struct {
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
	IsTruncated           bool   `xml:"IsTruncated"`
	NextContinuationToken string `xml:"NextContinuationToken"`
}

func (c *Client) listPage(ctx context.Context, query string) (listResult, error) {
	resp, err := c.do(ctx, http.MethodGet, c.objectURL("", query), nil, 0, emptySHA256)
	if err != nil {
		return listResult{}, err
	}
	defer resp.Body.Close()
	var page listResult
	if err := xml.NewDecoder(io.LimitReader(resp.Body, maxListBody)).Decode(&page); err != nil {
		return listResult{}, fmt.Errorf("s3 list: decode answer: %w", err)
	}
	return page, nil
}
