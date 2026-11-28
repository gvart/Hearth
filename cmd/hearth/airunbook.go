// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/hub"
)

func newAIRecordingsCmd(client aiClientFunc) *cobra.Command {
	return &cobra.Command{
		Use:   "recordings <device>",
		Short: "List the terminal sessions of a device recorded for a runbook (never what they hold)",
		Long: "A terminal session is recorded only when it is opened with Record for a runbook, in the web\n" +
			"terminal. The hub serving the terminal keeps the recording in its memory until a runbook is drafted\n" +
			"from it, it is discarded, or an hour after the session ended.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client(cmd)
			if err != nil {
				return err
			}
			var res struct {
				Recordings []hub.RecordingJSON `json:"recordings"`
			}
			if err := c.do(cmd.Context(), http.MethodGet, "/api/v1/devices/"+url.PathEscape(args[0])+"/recordings", nil, &res); err != nil {
				return fmt.Errorf("list recordings: %w", err)
			}
			out := cmd.OutOrStdout()
			if len(res.Recordings) == 0 {
				_, _ = fmt.Fprintln(out, "No recordings.")
				return nil
			}
			for _, r := range res.Recordings {
				state := "recording"
				if r.Ended != nil {
					state = "ended, kept until " + r.Expires.Local().Format(time.DateTime)
				}
				full := ""
				if r.Full {
					full = ", full"
				}
				_, _ = fmt.Fprintf(out, "%s  started %s  %d bytes%s  %s\n", r.ID, r.Started.Local().Format(time.DateTime), r.Bytes, full, state)
			}
			return nil
		},
	}
}

func newAIRunbookCmd(client aiClientFunc) *cobra.Command {
	var (
		notes   string
		preview bool
	)
	cmd := &cobra.Command{
		Use:   "runbook <device> <recording>",
		Short: "Draft a runbook from a recorded terminal session; prints the YAML and saves nothing",
		Long: "Sends what the recorded session showed, redacted, with the names of the hub's devices,\n" +
			"clusters and plugins, to the model, validates the answer as the runbook editor's save does, and asks\n" +
			"once more with the problems if it does not validate. Only the YAML goes to stdout; notes and\n" +
			"problems go to stderr. Once a draft is returned, the recording is deleted. Nothing is saved: review\n" +
			"the file, then save it in the web editor or with `hearth config import`. --preview prints what\n" +
			"would be sent, sends nothing and keeps the recording. The draft is ai.runbook.draft, audited.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client(cmd)
			if err != nil {
				return err
			}
			req := hub.RunbookDraftRequestJSON{Notes: notes, Preview: preview}
			return c.draftRunbook(cmd.Context(), args[0], args[1], req, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&notes, "notes", "", "what the session did, in your words")
	cmd.Flags().BoolVar(&preview, "preview", false, "print what would be sent, and send nothing")
	return cmd
}

func (c *runbookClient) draftRunbook(ctx context.Context, device, recording string, req hub.RunbookDraftRequestJSON, out, notes io.Writer) error {
	var res hub.RunbookDraftJSON
	path := "/api/v1/devices/" + url.PathEscape(device) + "/recordings/" + url.PathEscape(recording) + "/runbook"
	if err := c.do(ctx, http.MethodPost, path, req, &res); err != nil {
		return fmt.Errorf("draft a runbook: %w", err)
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
	_, _ = fmt.Fprintf(notes, "Drafted by %s: %d answer(s), sent %d bytes, %d values redacted. The recording was deleted. Nothing was saved.\n",
		where, res.Attempts, res.SentBytes, res.Redactions)
	if res.Valid {
		_, _ = fmt.Fprintf(notes, "Save it as %s.\n", res.File)
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
