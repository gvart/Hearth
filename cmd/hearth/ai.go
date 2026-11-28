// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/ai"
	"github.com/gvart/hearth/internal/hub"
)

// aiClientTimeout bounds one request of `hearth ai`: a local model on a
// small machine can take minutes to answer.
const aiClientTimeout = time.Hour + 30*time.Second

func newAICmd() *cobra.Command {
	var hubURL string
	cmd := &cobra.Command{
		Use:   "ai",
		Short: "Ask the language model the hub is set up with what is wrong with a device (see docs/ai.md)",
		Long: "AI is off until an admin sets up a provider: an OpenAI-compatible API (Ollama, LM Studio, vLLM,\n" +
			"OpenAI) or Anthropic. These commands use the hub's API with a signed-in session: the admin password\n" +
			"comes from HEARTH_ADMIN_PASSWORD or is asked for. The model never runs anything.",
	}
	cmd.PersistentFlags().StringVar(&hubURL, "hub-url", envOr("HEARTH_HUB_URL", "http://127.0.0.1:"+defaultHTTPPort),
		"the hub's web address (env HEARTH_HUB_URL)")
	client := func(cmd *cobra.Command) (*runbookClient, error) {
		lines := &lineReader{in: cmd.InOrStdin(), buf: bufio.NewReader(cmd.InOrStdin()), prompt: cmd.ErrOrStderr()}
		c, err := loginRunbookClient(cmd.Context(), hubURL, lines)
		if err != nil {
			return nil, err
		}
		c.http.Timeout = aiClientTimeout
		return c, nil
	}
	cmd.AddCommand(newAIExplainCmd(client), newAIStatusCmd(client), newAISetCmd(client))
	return cmd
}

type aiClientFunc func(*cobra.Command) (*runbookClient, error)

func newAIExplainCmd(client aiClientFunc) *cobra.Command {
	var (
		question       string
		logs           []string
		preview, shown bool
	)
	cmd := &cobra.Command{
		Use:   "explain <device-id>",
		Short: "Explain what is wrong with a device, from its facts, metrics, audit entries and log tails",
		Long: "Gathers what the hub knows about the device, redacts credentials from it, and asks the model.\n" +
			"--preview prints what would be sent and sends nothing; --show-sent prints it with the answer.\n" +
			"Each --log source (manager:name, as the device's log viewer names them) is read as a device.logs\n" +
			"action of its own, if the device's agent allows it. The question is ai.explain, audited.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client(cmd)
			if err != nil {
				return err
			}
			return c.explain(cmd.Context(), args[0], hub.ExplainRequestJSON{Question: question, Logs: logs, Preview: preview},
				preview || shown, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVarP(&question, "question", "q", "", "what to ask (default: whether anything is wrong, and why)")
	cmd.Flags().StringArrayVar(&logs, "log", nil, "a log source whose tail to include, such as systemd:nginx.service (up to 3)")
	cmd.Flags().BoolVar(&preview, "preview", false, "print what would be sent, and send nothing")
	cmd.Flags().BoolVar(&shown, "show-sent", false, "print what was sent, after the answer")
	return cmd
}

func (c *runbookClient) explain(ctx context.Context, device string, req hub.ExplainRequestJSON, showSent bool, out io.Writer) error {
	var res hub.ExplainJSON
	if err := c.do(ctx, http.MethodPost, "/api/v1/devices/"+url.PathEscape(device)+"/explain", req, &res); err != nil {
		return fmt.Errorf("explain %s: %w", device, err)
	}
	if !res.Preview {
		_, _ = fmt.Fprintf(out, "%s\n\n", strings.TrimSpace(res.Answer))
	}
	for _, n := range res.Notes {
		_, _ = fmt.Fprintf(out, "Note: %s\n", n)
	}
	where := fmt.Sprintf("%s %s at %s", res.Provider, res.Model, res.BaseURL)
	if res.Preview {
		_, _ = fmt.Fprintf(out, "Would send %d bytes to %s, %d values redacted:\n", res.SentBytes, where, res.Redactions)
	} else {
		_, _ = fmt.Fprintf(out, "Asked %s: sent %d bytes, %d values redacted.\n", where, res.SentBytes, res.Redactions)
	}
	if !showSent {
		return nil
	}
	_, _ = fmt.Fprintf(out, "\n--- system ---\n%s\n", res.Sent.System)
	for _, m := range res.Sent.Messages {
		_, _ = fmt.Fprintf(out, "\n--- %s ---\n%s\n", m.Role, m.Content)
	}
	return nil
}

func newAIStatusCmd(client aiClientFunc) *cobra.Command {
	return &cobra.Command{
		Use: "status", Short: "Show the AI settings (never the API key)", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := client(cmd)
			if err != nil {
				return err
			}
			var res hub.AIConfigJSON
			if err := c.do(cmd.Context(), http.MethodGet, "/api/v1/ai", nil, &res); err != nil {
				return err
			}
			printAIConfig(cmd.OutOrStdout(), res)
			return nil
		},
	}
}

func printAIConfig(out io.Writer, res hub.AIConfigJSON) {
	if !res.Enabled {
		_, _ = fmt.Fprintln(out, "AI is off.")
		return
	}
	key := "not set"
	if res.APIKeySet {
		key = "set"
	}
	_, _ = fmt.Fprintf(out, "Provider: %s\nAddress:  %s\nModel:    %s\nAPI key:  %s\n", res.Provider, res.BaseURL, res.Model, key)
}

func newAISetCmd(client aiClientFunc) *cobra.Command {
	var (
		body    hub.AIConfigJSON
		keyFile string
		off     bool
	)
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set up the provider, or turn AI off with --off",
		Long: "Writes the hub's ai.yaml through policy (config.import), sealed in the store. The API key comes\n" +
			"from --api-key-file, else HEARTH_AI_API_KEY; without either the stored key is kept, if the provider\n" +
			"and address stay the same. Examples:\n" +
			"  hearth ai set --provider openai --base-url http://127.0.0.1:11434/v1 --model llama3.2\n" +
			"  HEARTH_AI_API_KEY=sk-ant-... hearth ai set --provider anthropic",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !off && body.Provider == "" {
				return errors.New("give --provider openai or anthropic, or --off")
			}
			key := os.Getenv("HEARTH_AI_API_KEY")
			if keyFile != "" {
				b, err := os.ReadFile(keyFile)
				if err != nil {
					return fmt.Errorf("read --api-key-file: %w", err)
				}
				key = strings.TrimSpace(string(b))
			}
			c, err := client(cmd)
			if err != nil {
				return err
			}
			var cur hub.AIConfigJSON
			if err := c.do(cmd.Context(), http.MethodGet, "/api/v1/ai", nil, &cur); err != nil {
				return err
			}
			req := map[string]any{
				"provider": body.Provider, "base_url": body.BaseURL, "model": body.Model, "api_key": key,
				"max_tokens": body.MaxTokens, "timeout_seconds": body.TimeoutSeconds, "max_context_bytes": body.MaxContextBytes,
				"revision": cur.Revision,
			}
			if off {
				req = map[string]any{"provider": "", "revision": cur.Revision}
			}
			var res hub.AIConfigJSON
			if err := c.do(cmd.Context(), http.MethodPut, "/api/v1/ai/config", req, &res); err != nil {
				return err
			}
			printAIConfig(cmd.OutOrStdout(), res)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&body.Provider, "provider", "", "openai (any OpenAI-compatible API: Ollama, LM Studio, vLLM) or anthropic")
	f.StringVar(&body.BaseURL, "base-url", "", "the API's address, with /v1 for an OpenAI-compatible one (default for anthropic: "+ai.DefaultAnthropicURL+")")
	f.StringVar(&body.Model, "model", "", "the model (default for anthropic: "+ai.DefaultAnthropicModel+")")
	f.StringVar(&keyFile, "api-key-file", "", "a file holding the API key (else env HEARTH_AI_API_KEY)")
	f.IntVar(&body.MaxTokens, "max-tokens", 0, "bound on an answer's tokens (default 4096 for anthropic, the server's for openai)")
	f.IntVar(&body.TimeoutSeconds, "timeout-seconds", 0, "bound on one answer (default 300)")
	f.IntVar(&body.MaxContextBytes, "max-context-bytes", 0, "bound on the evidence sent per question (default 24576)")
	f.BoolVar(&off, "off", false, "turn AI off")
	return cmd
}
