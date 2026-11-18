// SPDX-License-Identifier: AGPL-3.0-only

// Package prometheus reads metrics from an existing Prometheus server over its
// HTTP API (/api/v1/query and /api/v1/query_range), maps node-exporter targets
// to Hearth devices, and serves the series behind device charts. It only reads;
// it never writes to Prometheus.
package prometheus

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Sample is one value at one time.
type Sample struct {
	T time.Time
	V float64
}

// Series is a labelled time series. An instant query yields one sample per
// series.
type Series struct {
	Labels  map[string]string
	Samples []Sample
}

// Querier runs PromQL. Client implements it; automation triggers or tests can
// reuse or fake it.
type Querier interface {
	// Query evaluates q at t and returns the resulting vector.
	Query(ctx context.Context, q string, t time.Time) ([]Series, error)
	// QueryRange evaluates q from start to end every step.
	QueryRange(ctx context.Context, q string, start, end time.Time, step time.Duration) ([]Series, error)
}

// maxBody caps a Prometheus response the hub will read.
const maxBody = 32 << 20

// Client is a Querier over the Prometheus HTTP API.
type Client struct {
	base *url.URL
	hc   *http.Client
}

// NewClient returns a client for the Prometheus server at rawURL (for example
// http://prometheus.lan:9090, optionally with a path prefix and user:password).
// A nil hc uses a client with a 10 s timeout.
func NewClient(rawURL string, hc *http.Client) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse prometheus url: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, errors.New("prometheus url must be http(s)://host[:port][/prefix]")
	}
	if hc == nil {
		hc = &http.Client{Timeout: 10 * time.Second}
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return &Client{base: u, hc: hc}, nil
}

// Query implements Querier.
func (c *Client) Query(ctx context.Context, q string, t time.Time) ([]Series, error) {
	v := url.Values{"query": {q}, "time": {formatTime(t)}}
	return c.do(ctx, "/api/v1/query", v)
}

// QueryRange implements Querier.
func (c *Client) QueryRange(ctx context.Context, q string, start, end time.Time, step time.Duration) ([]Series, error) {
	v := url.Values{
		"query": {q},
		"start": {formatTime(start)},
		"end":   {formatTime(end)},
		"step":  {strconv.FormatFloat(step.Seconds(), 'f', -1, 64)},
	}
	return c.do(ctx, "/api/v1/query_range", v)
}

func formatTime(t time.Time) string {
	return strconv.FormatFloat(float64(t.UnixMilli())/1000, 'f', 3, 64)
}

// apiResponse is the envelope of every Prometheus API answer.
type apiResponse struct {
	Status    string `json:"status"`
	ErrorType string `json:"errorType"`
	Error     string `json:"error"`
	Data      struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	} `json:"data"`
}

type apiSeries struct {
	Metric map[string]string   `json:"metric"`
	Value  []json.RawMessage   `json:"value"`  // vector: [ts, "v"]
	Values [][]json.RawMessage `json:"values"` // matrix: [[ts, "v"], ...]
}

func (c *Client) do(ctx context.Context, path string, v url.Values) ([]Series, error) {
	u := *c.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(v.Encode()))
	if err != nil {
		return nil, fmt.Errorf("prometheus %s: %w", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		// net/http redacts any password in the URL of this error.
		return nil, fmt.Errorf("prometheus %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("prometheus %s: read: %w", path, err)
	}
	var r apiResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("prometheus %s: status %d: not a Prometheus API response", path, resp.StatusCode)
	}
	if r.Status != "success" {
		return nil, fmt.Errorf("prometheus %s: %s: %s", path, r.ErrorType, r.Error)
	}
	return parseResult(r.Data.ResultType, r.Data.Result)
}

func parseResult(typ string, raw json.RawMessage) ([]Series, error) {
	if typ != "vector" && typ != "matrix" {
		return nil, fmt.Errorf("prometheus: unsupported result type %q", typ)
	}
	var in []apiSeries
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, fmt.Errorf("prometheus: decode %s: %w", typ, err)
	}
	out := make([]Series, 0, len(in))
	for _, s := range in {
		pairs := s.Values
		if typ == "vector" {
			pairs = [][]json.RawMessage{s.Value}
		}
		ser := Series{Labels: s.Metric, Samples: make([]Sample, 0, len(pairs))}
		for _, p := range pairs {
			smp, err := parseSample(p)
			if err != nil {
				return nil, err
			}
			ser.Samples = append(ser.Samples, smp)
		}
		out = append(out, ser)
	}
	return out, nil
}

func parseSample(p []json.RawMessage) (Sample, error) {
	if len(p) != 2 {
		return Sample{}, errors.New("prometheus: malformed sample")
	}
	var ts float64
	var vs string
	if err := json.Unmarshal(p[0], &ts); err != nil {
		return Sample{}, fmt.Errorf("prometheus: sample time: %w", err)
	}
	if err := json.Unmarshal(p[1], &vs); err != nil {
		return Sample{}, fmt.Errorf("prometheus: sample value: %w", err)
	}
	v, err := strconv.ParseFloat(vs, 64)
	if err != nil {
		return Sample{}, fmt.Errorf("prometheus: sample value: %w", err)
	}
	sec, frac := math.Modf(ts)
	return Sample{T: time.Unix(int64(sec), int64(math.Round(frac*1e3))*int64(time.Millisecond)).UTC(), V: v}, nil
}
