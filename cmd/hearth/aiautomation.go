// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/hub"
)

// errDraftInvalid fails `hearth ai automation` when even the second draft
// does not validate: the file is still printed, to fix by hand.
var errDraftInvalid = errors.New("the draft does not validate: fix the problems above before you import it")

func newAIAutomationCmd(client aiClientFunc) *cobra.Command {
	var preview bool
	cmd := &cobra.Command{
		Use:   `automation "<what it should do>"`,
		Short: "Draft an automation file from a description; prints the YAML and saves nothing",
		Long: "Asks the model for an automation that does what you describe, grounded in the automation\n" +
			"schema and the names of the hub's devices, notification channels, clusters and plugins (redacted),\n" +
			"validates it as the editor's save does, and asks once more with the problems if it does not\n" +
			"validate. Only the YAML goes to stdout; notes and problems go to stderr. Nothing is saved: review\n" +
			"the file, then save it in the web editor or with `hearth config import`. --preview prints what\n" +
			"would be sent and sends nothing. The draft is ai.automation.draft, audited.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client(cmd)
			if err != nil {
				return err
			}
			req := hub.AutomationDraftRequestJSON{Text: strings.Join(args, " "), Preview: preview}
			return c.draftAutomation(cmd.Context(), req, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().BoolVar(&preview, "preview", false, "print what would be sent, and send nothing")
	return cmd
}

func (c *runbookClient) draftAutomation(ctx context.Context, req hub.AutomationDraftRequestJSON, out, notes io.Writer) error {
	var res hub.AutomationDraftJSON
	if err := c.do(ctx, http.MethodPost, "/api/v1/automations/draft", req, &res); err != nil {
		return fmt.Errorf("draft an automation: %w", err)
	}
	where := fmt.Sprintf("%s %s at %s", res.Provider, res.Model, res.BaseURL)
	if res.Preview {
		_, _ = fmt.Fprintf(out, "Would send %d bytes to %s, %d values redacted:\n", res.SentBytes, where, res.Redactions)
		_, _ = fmt.Fprintf(out, "\n--- system ---\n%s\n", res.Sent.System)
		for _, m := range res.Sent.Messages {
			_, _ = fmt.Fprintf(out, "\n--- %s ---\n%s\n", m.Role, m.Content)
		}
		return nil
	}
	_, _ = io.WriteString(out, res.YAML)
	_, _ = fmt.Fprintf(notes, "Drafted by %s: %d answer(s), sent %d bytes, %d values redacted. Nothing was saved.\n",
		where, res.Attempts, res.SentBytes, res.Redactions)
	if res.Valid {
		return nil
	}
	for _, p := range res.Problems {
		if p.Line > 0 {
			_, _ = fmt.Fprintf(notes, "line %d: %s\n", p.Line, p.Message)
		} else {
			_, _ = fmt.Fprintln(notes, p.Message)
		}
	}
	return errDraftInvalid
}
