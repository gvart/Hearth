// SPDX-License-Identifier: AGPL-3.0-only

package kubernetes

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
)

// apiClient talks to a Kubernetes API server: lists, watches and pod logs,
// and the few writes of the Kubernetes actions (patch, delete, eviction).
type apiClient struct {
	base *url.URL
	http *http.Client
}

func newAPIClient(k *kubeconfig) (*apiClient, error) {
	hc, err := k.httpClient()
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(strings.TrimSuffix(k.cluster.Server, "/"))
	if err != nil {
		return nil, invalid("server: %v", err)
	}
	return &apiClient{base: base, http: hc}, nil
}

// apiError is a non-2xx answer of the API server.
type apiError struct {
	Code    int
	Message string
}

func (e *apiError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("kubernetes API: HTTP %d", e.Code)
	}
	return fmt.Sprintf("kubernetes API: %s (HTTP %d)", e.Message, e.Code)
}

func hasCode(err error, code int) bool {
	var ae *apiError
	return errors.As(err, &ae) && ae.Code == code
}

// get sends GET path?q and returns the response of a 2xx answer; the
// caller closes its body.
func (c *apiClient) get(ctx context.Context, path string, q url.Values) (*http.Response, error) {
	return c.do(ctx, http.MethodGet, path, q, "", nil)
}

// do sends method path?q with body, of contentType, and returns the
// response of a 2xx answer; the caller closes its body. A write that got a
// connection and no answer fails with an error wrapping ErrWriteOutcomeUnknown.
func (c *apiClient) do(ctx context.Context, method, path string, q url.Values, contentType string, body []byte) (*http.Response, error) {
	var connected atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
	})
	u := *c.base
	u.Path += path
	u.RawQuery = q.Encode()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		if method != http.MethodGet && connected.Load() {
			return nil, fmt.Errorf("%w: %w", err, ErrWriteOutcomeUnknown)
		}
		return nil, err
	}
	if resp.StatusCode/100 == 2 {
		return resp, nil
	}
	defer resp.Body.Close()
	var st status
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if json.Unmarshal(b, &st) != nil || st.Message == "" {
		st.Message = strings.TrimSpace(string(b))
		if len(st.Message) > 200 {
			st.Message = st.Message[:200]
		}
	}
	return nil, &apiError{Code: resp.StatusCode, Message: st.Message}
}

// listPage is one page of a list.
type listPage struct {
	Metadata struct {
		ResourceVersion string `json:"resourceVersion"`
		Continue        string `json:"continue"`
	} `json:"metadata"`
	Items []json.RawMessage `json:"items"`
}

// list returns every item of path and the list's resource version,
// following continue tokens.
func (c *apiClient) list(ctx context.Context, path string) ([]json.RawMessage, string, error) {
	return c.listSelected(ctx, path, "")
}

// listSelected is list with a field selector, if not empty.
func (c *apiClient) listSelected(ctx context.Context, path, fieldSelector string) ([]json.RawMessage, string, error) {
	var (
		items []json.RawMessage
		cont  string
	)
	for {
		q := url.Values{"limit": {"500"}}
		if fieldSelector != "" {
			q.Set("fieldSelector", fieldSelector)
		}
		if cont != "" {
			q.Set("continue", cont)
		}
		resp, err := c.get(ctx, path, q)
		if err != nil {
			return nil, "", err
		}
		var page listPage
		err = json.NewDecoder(resp.Body).Decode(&page)
		_ = resp.Body.Close()
		if err != nil {
			return nil, "", fmt.Errorf("decode %s: %w", path, err)
		}
		items = append(items, page.Items...)
		if page.Metadata.Continue == "" {
			return items, page.Metadata.ResourceVersion, nil
		}
		cont = page.Metadata.Continue
	}
}

// watchTimeout bounds one watch request; the reflector then watches again
// from where it was.
const watchTimeout = 5 * 60

// watch streams the changes of path after resource version rv. The caller
// closes the body.
func (c *apiClient) watch(ctx context.Context, path, rv string) (io.ReadCloser, error) {
	resp, err := c.get(ctx, path, url.Values{
		"watch":               {"1"},
		"resourceVersion":     {rv},
		"allowWatchBookmarks": {"true"},
		"timeoutSeconds":      {strconv.Itoa(watchTimeout)},
	})
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

type podLogOptions struct {
	container  string
	tailLines  int64
	limitBytes int64
}

// logs reads the last lines of a pod container's log.
func (c *apiClient) logs(ctx context.Context, namespace, pod string, o podLogOptions) ([]byte, error) {
	q := url.Values{
		"tailLines":  {strconv.FormatInt(o.tailLines, 10)},
		"limitBytes": {strconv.FormatInt(o.limitBytes, 10)},
	}
	if o.container != "" {
		q.Set("container", o.container)
	}
	// The names are validated DNS names (see validObjectName): nothing to escape.
	resp, err := c.get(ctx, "/api/v1/namespaces/"+namespace+"/pods/"+pod+"/log", q)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(io.LimitReader(resp.Body, o.limitBytes+1))
}

// Content types of the writes.
const (
	mergePatch     = "application/merge-patch+json"
	strategicPatch = "application/strategic-merge-patch+json"
)

// getObject decodes the object at path into v.
func (c *apiClient) getObject(ctx context.Context, path string, v any) error {
	resp, err := c.get(ctx, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

// send sends method path with a JSON body of contentType (application/json
// if empty) and drops the answer.
func (c *apiClient) send(ctx context.Context, method, path, contentType string, body any) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	if contentType == "" {
		contentType = "application/json"
	}
	resp, err := c.do(ctx, method, path, nil, contentType, b)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.Body.Close()
}

// deleteObject deletes the object at path.
func (c *apiClient) deleteObject(ctx context.Context, path string) error {
	resp, err := c.do(ctx, http.MethodDelete, path, nil, "", nil)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.Body.Close()
}
