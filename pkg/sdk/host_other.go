// SPDX-License-Identifier: Apache-2.0

//go:build !wasip1

package sdk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

// stdin is the plugin's stdin.
func stdin() io.Reader { return os.Stdin }

func doHTTP(req HTTPRequest) (HTTPResponse, error) {
	if len(req.Body) > 64<<10 {
		return HTTPResponse{}, fmt.Errorf("sdk: http: body larger than %d bytes", 64<<10)
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	hr, err := http.NewRequestWithContext(context.Background(), method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return HTTPResponse{}, fmt.Errorf("sdk: http: %w", err)
	}
	for k, v := range req.Header {
		hr.Header.Set(k, v)
	}
	// The limits of the hub's http host function.
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(hr)
	if err != nil {
		return HTTPResponse{}, fmt.Errorf("sdk: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		return HTTPResponse{}, fmt.Errorf("sdk: http: %w", err)
	}
	if len(body) > 1<<20 {
		return HTTPResponse{}, fmt.Errorf("sdk: http: response larger than %d bytes", 1<<20)
	}
	h := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		h[k] = resp.Header.Get(k)
	}
	return HTTPResponse{Status: resp.StatusCode, Header: h, Body: body}, nil
}
