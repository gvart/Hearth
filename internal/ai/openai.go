// SPDX-License-Identifier: AGPL-3.0-only

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// OpenAI is an OpenAI-compatible chat completions API: POST
// {BaseURL}/chat/completions. Ollama, LM Studio, vLLM and llama.cpp's server
// speak it, as OpenAI does.
type OpenAI struct {
	// BaseURL is up to and with the API's version, such as
	// http://127.0.0.1:11434/v1.
	BaseURL string
	ModelID string
	// APIKey, if set, is sent as a bearer token.
	APIKey string
	HTTP   *http.Client
}

// Name implements Provider.
func (*OpenAI) Name() string { return ProviderOpenAI }

// Model implements Provider.
func (p *OpenAI) Model() string { return p.ModelID }

type openAIRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
	// MaxTokens is sent only when set: servers differ on the field.
	MaxTokens int  `json:"max_tokens,omitempty"`
	Stream    bool `json:"stream"`
}

type openAIResponse struct {
	Model   string `json:"model"`
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

// Complete implements Provider.
func (p *OpenAI) Complete(ctx context.Context, req Request) (Response, error) {
	msgs := make([]Message, 0, len(req.Messages)+1)
	if req.System != "" {
		msgs = append(msgs, Message{Role: "system", Content: req.System})
	}
	msgs = append(msgs, req.Messages...)
	body, err := json.Marshal(openAIRequest{Model: p.ModelID, Messages: msgs, MaxTokens: req.MaxTokens})
	if err != nil {
		return Response{}, fmt.Errorf("%s: encode request: %w", ProviderOpenAI, err)
	}
	headers := map[string]string{}
	if p.APIKey != "" {
		headers["Authorization"] = "Bearer " + p.APIKey
	}
	hc := p.HTTP
	if hc == nil {
		hc = newHTTPClient(0)
	}
	b, err := post(ctx, hc, ProviderOpenAI, strings.TrimRight(p.BaseURL, "/")+"/chat/completions", headers, body, openAIErrorText)
	if err != nil {
		return Response{}, err
	}
	var out openAIResponse
	if err := json.Unmarshal(b, &out); err != nil {
		return Response{}, fmt.Errorf("%s: the answer is not a chat completion", ProviderOpenAI)
	}
	if len(out.Choices) == 0 || strings.TrimSpace(out.Choices[0].Message.Content) == "" {
		reason := ""
		if len(out.Choices) > 0 {
			reason = out.Choices[0].FinishReason
		}
		return Response{}, fmt.Errorf("%s: %w (finish reason %q)", ProviderOpenAI, ErrNoAnswer, reason)
	}
	model := out.Model
	if model == "" {
		model = p.ModelID
	}
	return Response{
		Text: out.Choices[0].Message.Content, Model: model, StopReason: out.Choices[0].FinishReason,
		InputTokens: out.Usage.PromptTokens, OutputTokens: out.Usage.CompletionTokens,
	}, nil
}

// openAIErrorText is the message of an OpenAI-style error body:
// {"error": {"message": "..."}} or, from some servers, {"error": "..."}.
func openAIErrorText(b []byte) string {
	var e struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(b, &e) != nil || len(e.Error) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(e.Error, &s) == nil {
		return s
	}
	var obj struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(e.Error, &obj)
	return obj.Message
}
