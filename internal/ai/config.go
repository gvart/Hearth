// SPDX-License-Identifier: AGPL-3.0-only

package ai

import (
	"bytes"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Provider kinds.
const (
	// ProviderOpenAI is any OpenAI-compatible chat completions API: Ollama,
	// LM Studio, vLLM, llama.cpp's server, OpenAI.
	ProviderOpenAI = "openai"
	// ProviderAnthropic is Anthropic's Messages API.
	ProviderAnthropic = "anthropic"
)

// Defaults for Anthropic. An OpenAI-compatible provider has none: its
// address and model are the operator's.
const (
	DefaultAnthropicURL   = "https://api.anthropic.com"
	DefaultAnthropicModel = "claude-sonnet-5-5"
)

// Config is the hub's ai.yaml: which model to ask. No provider is AI off,
// the default.
type Config struct {
	Provider string `yaml:"provider,omitempty"`
	// BaseURL is the API's address: for an OpenAI-compatible API up to and
	// with /v1 (http://127.0.0.1:11434/v1 for Ollama); for Anthropic,
	// DefaultAnthropicURL unless set.
	BaseURL string `yaml:"base_url,omitempty"`
	Model   string `yaml:"model,omitempty"`
	// APIKey is optional for a local OpenAI-compatible server.
	APIKey string `yaml:"api_key,omitempty"`
	// MaxTokens bounds an answer; 0 is DefaultMaxTokens.
	MaxTokens int `yaml:"max_tokens,omitempty"`
	// TimeoutSeconds bounds one answer; 0 is DefaultTimeout.
	TimeoutSeconds int `yaml:"timeout_seconds,omitempty"`
	// MaxContextBytes bounds what a question sends about a device; 0 is
	// DefaultContextBytes. A local model with a small context window wants
	// it smaller.
	MaxContextBytes int `yaml:"max_context_bytes,omitempty"`
}

// DefaultMaxTokens bounds an answer unless the configuration says otherwise.
const DefaultMaxTokens = 4096

// Limits of a Config.
const (
	maxMaxTokens       = 64000
	maxTimeoutSeconds  = 3600
	minContextBytes    = 2 << 10
	maxContextBytesCap = 512 << 10
)

// Enabled reports whether a provider is configured.
func (c Config) Enabled() bool { return c.Provider != "" }

// URL is the base URL in effect.
func (c Config) URL() string {
	if c.BaseURL == "" && c.Provider == ProviderAnthropic {
		return DefaultAnthropicURL
	}
	return c.BaseURL
}

// ModelName is the model in effect.
func (c Config) ModelName() string {
	if c.Model == "" && c.Provider == ProviderAnthropic {
		return DefaultAnthropicModel
	}
	return c.Model
}

// Tokens is the answer bound in effect.
func (c Config) Tokens() int {
	if c.MaxTokens == 0 {
		return DefaultMaxTokens
	}
	return c.MaxTokens
}

// ContextBytes is the context bound in effect.
func (c Config) ContextBytes() int {
	if c.MaxContextBytes == 0 {
		return DefaultContextBytes
	}
	return c.MaxContextBytes
}

// Timeout is the time bound in effect.
func (c Config) Timeout() time.Duration {
	if c.TimeoutSeconds == 0 {
		return DefaultTimeout
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// Validate checks c. No error quotes the API key.
func (c Config) Validate() error {
	switch c.Provider {
	case "":
		return nil
	case ProviderOpenAI, ProviderAnthropic:
	default:
		return fmt.Errorf("provider %q: want %s or %s", c.Provider, ProviderOpenAI, ProviderAnthropic)
	}
	if err := checkURL(c.URL()); err != nil {
		return err
	}
	if c.ModelName() == "" {
		return errors.New("model is required for an OpenAI-compatible provider (such as llama3.2 for Ollama)")
	}
	if c.Provider == ProviderAnthropic && c.APIKey == "" {
		return errors.New("api_key is required for Anthropic")
	}
	if strings.ContainsAny(c.APIKey, "\r\n") {
		return errors.New("api_key must be one line")
	}
	if c.MaxTokens < 0 || c.MaxTokens > maxMaxTokens {
		return fmt.Errorf("max_tokens must be between 1 and %d", maxMaxTokens)
	}
	if c.TimeoutSeconds < 0 || c.TimeoutSeconds > maxTimeoutSeconds {
		return fmt.Errorf("timeout_seconds must be between 1 and %d", maxTimeoutSeconds)
	}
	if c.MaxContextBytes != 0 && (c.MaxContextBytes < minContextBytes || c.MaxContextBytes > maxContextBytesCap) {
		return fmt.Errorf("max_context_bytes must be between %d and %d", minContextBytes, maxContextBytesCap)
	}
	return nil
}

// checkURL accepts an http or https address with a host and without
// credentials, a query or a fragment.
func checkURL(s string) error {
	if s == "" {
		return errors.New("base_url is required for an OpenAI-compatible provider (such as http://127.0.0.1:11434/v1 for Ollama)")
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return errors.New("base_url must be an http:// or https:// address")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("base_url must carry no credentials, query or fragment: put a key in api_key")
	}
	return nil
}

// ParseConfig reads ai.yaml. An empty document is AI off.
func ParseConfig(b []byte) (Config, error) {
	var c Config
	if len(bytes.TrimSpace(b)) == 0 {
		return c, nil
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return Config{}, errors.New("not a valid ai.yaml: want provider, base_url, model, api_key, max_tokens, timeout_seconds, max_context_bytes")
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Marshal is c as ai.yaml.
func (c Config) Marshal() ([]byte, error) {
	if !c.Enabled() {
		return []byte{}, nil
	}
	return yaml.Marshal(c)
}

// ErrDisabled is AI off: no provider is configured.
var ErrDisabled = errors.New("AI is off: no provider is configured")

// New is the provider c names, or ErrDisabled.
func New(c Config) (Provider, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	hc := newHTTPClient(c.Timeout())
	switch c.Provider {
	case ProviderOpenAI:
		return &OpenAI{BaseURL: c.URL(), ModelID: c.ModelName(), APIKey: c.APIKey, HTTP: hc}, nil
	case ProviderAnthropic:
		return &Anthropic{BaseURL: c.URL(), ModelID: c.ModelName(), APIKey: c.APIKey, HTTP: hc}, nil
	}
	return nil, ErrDisabled
}
