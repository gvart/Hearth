// SPDX-License-Identifier: AGPL-3.0-only

// Package ai talks to a language model the operator chose: an
// OpenAI-compatible chat completions API (Ollama, LM Studio, vLLM, OpenAI) or
// Anthropic's Messages API. It never runs anything: it sends text and returns
// text. The hub decides, through policy, what may be asked and audits it;
// Redact takes credentials out of whatever is sent first.
package ai

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Roles of a Message.
const (
	RoleUser      = "user"
	RoleAssistant = "assistant"
)

// Message is one turn of a conversation.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Request is one completion: a system prompt and the conversation so far.
type Request struct {
	System   string    `json:"system"`
	Messages []Message `json:"messages"`
	// MaxTokens bounds the answer; 0 is the provider's default.
	MaxTokens int `json:"max_tokens,omitempty"`
}

// Size is the number of bytes of text req carries.
func (r Request) Size() int {
	n := len(r.System)
	for _, m := range r.Messages {
		n += len(m.Content)
	}
	return n
}

// Response is a model's answer.
type Response struct {
	Text string
	// Model is the model that answered, as the provider names it.
	Model        string
	InputTokens  int
	OutputTokens int
	// StopReason is why the model stopped, as the provider says it.
	StopReason string
}

// Provider completes a conversation. Implementations are safe for concurrent
// use, never log, and never put the API key in an error.
type Provider interface {
	// Name is the provider kind: ProviderOpenAI or ProviderAnthropic.
	Name() string
	// Model is the model it asks.
	Model() string
	Complete(ctx context.Context, req Request) (Response, error)
}

// Errors of Complete. Each is wrapped in an *APIError when the provider
// answered.
var (
	// ErrAuth is a refused API key (HTTP 401 or 403).
	ErrAuth = errors.New("the provider refused the API key")
	// ErrNotFound is an unknown model or endpoint (HTTP 404).
	ErrNotFound = errors.New("the provider has no such model or endpoint")
	// ErrRateLimited is HTTP 429: too many requests, or out of credit.
	ErrRateLimited = errors.New("the provider is rate limiting requests")
	// ErrBadRequest is any other refusal of the request (HTTP 4xx).
	ErrBadRequest = errors.New("the provider refused the request")
	// ErrUnavailable is a provider that cannot be reached or failed (5xx).
	ErrUnavailable = errors.New("the provider is unavailable")
	// ErrNoAnswer is an answer without text: a refusal, or the token limit
	// reached before any text.
	ErrNoAnswer = errors.New("the model gave no answer")
)

// APIError is a provider's error answer.
type APIError struct {
	Provider string
	Status   int
	// Message is the provider's own message, shortened.
	Message string
	Kind    error
}

func (e *APIError) Error() string {
	msg := fmt.Sprintf("%s: HTTP %d: %v", e.Provider, e.Status, e.Kind)
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}

func (e *APIError) Unwrap() error { return e.Kind }

// kindOf maps an HTTP status to an error of Complete.
func kindOf(status int) error {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return ErrAuth
	case status == http.StatusNotFound:
		return ErrNotFound
	case status == http.StatusTooManyRequests:
		return ErrRateLimited
	case status >= 500:
		return ErrUnavailable
	}
	return ErrBadRequest
}

// Limits of what is read from a provider.
const (
	maxAnswerBody = 4 << 20
	maxErrorBody  = 64 << 10
	maxErrorText  = 300
)

// DefaultTimeout bounds one completion: a local model on a small machine
// can take minutes.
const DefaultTimeout = 5 * time.Minute

// newHTTPClient is a client that follows no redirect: a redirect would carry
// the API key to wherever it points.
func newHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// post sends body to url with headers and returns the answer's body, or an
// *APIError, or ErrUnavailable when the provider could not be reached. No
// error quotes a header: they carry the key.
func post(ctx context.Context, c *http.Client, provider, url string, headers map[string]string, body []byte,
	errText func([]byte) string,
) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("%s: build request: %w", provider, err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s: %w", provider, ctx.Err())
		}
		return nil, fmt.Errorf("%s: %w: %v", provider, ErrUnavailable, transportError(err)) //nolint:errorlint // the cause is text only
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
		msg := ""
		if errText != nil {
			msg = errText(b)
		}
		if resp.StatusCode < 400 {
			msg = "redirects are not followed: give the provider's final address"
		}
		return nil, &APIError{Provider: provider, Status: resp.StatusCode, Message: shorten(Redact(msg).Text), Kind: kindOf(resp.StatusCode)}
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswerBody+1))
	if err != nil {
		return nil, fmt.Errorf("%s: read the answer: %w", provider, err)
	}
	if len(b) > maxAnswerBody {
		return nil, fmt.Errorf("%s: the answer is larger than %d bytes", provider, maxAnswerBody)
	}
	return b, nil
}

// transportError is err without the request's URL, which Go's client puts
// in: the error says what failed, the configuration says where.
func transportError(err error) string {
	var ue interface{ Unwrap() error }
	if errors.As(err, &ue) {
		if inner := ue.Unwrap(); inner != nil {
			return inner.Error()
		}
	}
	return err.Error()
}

func shorten(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > maxErrorText {
		return s[:maxErrorText] + "…"
	}
	return s
}
