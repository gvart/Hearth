// SPDX-License-Identifier: AGPL-3.0-only

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// AnthropicVersion is the version of the Messages API the client speaks.
const AnthropicVersion = "2026-10-21"

// Anthropic is Anthropic's Messages API: POST {BaseURL}/v1/messages.
type Anthropic struct {
	// BaseURL is DefaultAnthropicURL, or a proxy that speaks the same API.
	BaseURL string
	ModelID string
	APIKey  string
	HTTP    *http.Client
}

// Name implements Provider.
func (*Anthropic) Name() string { return ProviderAnthropic }

// Model implements Provider.
func (p *Anthropic) Model() string { return p.ModelID }

// anthropicRequest is the least the API takes: no sampling, thinking or
// effort settings, so any model the operator names accepts it.
type anthropicRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system,omitempty"`
	Messages  []Message `json:"messages"`
}

type anthropicResponse struct {
	Model   string `json:"model"`
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	StopReason string `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

// Complete implements Provider.
func (p *Anthropic) Complete(ctx context.Context, req Request) (Response, error) {
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = DefaultMaxTokens
	}
	body, err := json.Marshal(anthropicRequest{Model: p.ModelID, MaxTokens: maxTokens, System: req.System, Messages: req.Messages})
	if err != nil {
		return Response{}, fmt.Errorf("%s: encode request: %w", ProviderAnthropic, err)
	}
	headers := map[string]string{"x-api-key": p.APIKey, "anthropic-version": AnthropicVersion}
	hc := p.HTTP
	if hc == nil {
		hc = newHTTPClient(0)
	}
	b, err := post(ctx, hc, ProviderAnthropic, strings.TrimRight(p.BaseURL, "/")+"/v1/messages", headers, body, anthropicErrorText)
	if err != nil {
		return Response{}, err
	}
	var out anthropicResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return Response{}, fmt.Errorf("%s: the answer is not a message", ProviderAnthropic)
	}
	// Only text blocks are the answer: a model that thinks first sends
	// thinking blocks before them.
	var text strings.Builder
	for _, c := range out.Content {
		if c.Type == "text" {
			text.WriteString(c.Text)
		}
	}
	if strings.TrimSpace(text.String()) == "" || out.StopReason == "refusal" {
		return Response{}, fmt.Errorf("%s: %w (stop reason %q)", ProviderAnthropic, ErrNoAnswer, out.StopReason)
	}
	model := out.Model
	if model == "" {
		model = p.ModelID
	}
	return Response{
		Text: text.String(), Model: model, StopReason: out.StopReason,
		InputTokens: out.Usage.InputTokens, OutputTokens: out.Usage.OutputTokens,
	}, nil
}

// anthropicErrorText is the message of an error body:
// {"type": "error", "error": {"type": "...", "message": "..."}}.
func anthropicErrorText(b []byte) string {
	var e struct {
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &e) != nil {
		return ""
	}
	if e.Error.Type != "" && e.Error.Message != "" {
		return e.Error.Type + ": " + e.Error.Message
	}
	return e.Error.Message
}
