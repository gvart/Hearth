// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/hub"
)

// runbookClientTimeout bounds one request to the hub's API.
const runbookClientTimeout = 30 * time.Second

func newRunbookCmd() *cobra.Command {
	var hubURL string
	cmd := &cobra.Command{
		Use:   "runbook",
		Short: "List, plan, start and follow runbooks",
		Long: "Runbooks are YAML files in the hub's runbooks dir (--runbooks-dir of `hearth hub`, default\n" +
			"<data-dir>/runbooks). These commands use the hub's API with a signed-in session: the admin\n" +
			"password comes from HEARTH_ADMIN_PASSWORD or is asked for. See docs/runbooks.md.",
	}
	cmd.PersistentFlags().StringVar(&hubURL, "hub-url", envOr("HEARTH_HUB_URL", "http://127.0.0.1:"+defaultHTTPPort),
		"the hub's web address (env HEARTH_HUB_URL)")
	// One reader for the command: piped input may hold the password and then
	// an answer, and a buffered reader of its own would swallow the second.
	var lines *lineReader
	client := func(cmd *cobra.Command) (*runbookClient, error) {
		lines = &lineReader{in: cmd.InOrStdin(), buf: bufio.NewReader(cmd.InOrStdin()), prompt: cmd.ErrOrStderr()}
		return loginRunbookClient(cmd.Context(), hubURL, lines)
	}
	cmd.AddCommand(
		&cobra.Command{
			Use: "list", Short: "List the runbooks on the hub", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				c, err := client(cmd)
				if err != nil {
					return err
				}
				return c.list(cmd.Context(), cmd.OutOrStdout())
			},
		},
		&cobra.Command{
			Use: "plan <runbook>", Short: "Show what a run would do and what policy would decide, running nothing",
			Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := client(cmd)
				if err != nil {
					return err
				}
				return c.plan(cmd.Context(), args[0], cmd.OutOrStdout())
			},
		},
		&cobra.Command{
			Use: "start <runbook>", Short: "Start a run", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := client(cmd)
				if err != nil {
					return err
				}
				return c.act(cmd.Context(), "/api/v1/runbooks/"+url.PathEscape(args[0])+"/runs", nil, cmd.OutOrStdout())
			},
		},
		&cobra.Command{
			Use: "runs [runbook]", Short: "List recent runs, newest first", Args: cobra.MaximumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := client(cmd)
				if err != nil {
					return err
				}
				id := ""
				if len(args) == 1 {
					id = args[0]
				}
				return c.runs(cmd.Context(), id, cmd.OutOrStdout())
			},
		},
		&cobra.Command{
			Use: "show <run>", Short: "Show a run's steps and log", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := client(cmd)
				if err != nil {
					return err
				}
				var run automation.RunbookRunJSON
				if err := c.do(cmd.Context(), http.MethodGet, runbookRunPath(args[0], ""), nil, &run); err != nil {
					return err
				}
				return printRunbookRun(cmd.OutOrStdout(), run)
			},
		},
		&cobra.Command{
			Use:   "answer <run> <step> [value]",
			Short: "Answer a prompt; without a value it is asked for, unechoed on a terminal",
			Args:  cobra.RangeArgs(2, 3),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := client(cmd)
				if err != nil {
					return err
				}
				var value string
				if len(args) == 3 {
					value = args[2]
				} else if value, err = lines.read("Answer: "); err != nil {
					return err
				}
				body := map[string]string{"step": args[1], "value": value}
				return c.act(cmd.Context(), runbookRunPath(args[0], "/answer"), body, cmd.OutOrStdout())
			},
		},
		&cobra.Command{
			Use: "retry <run>", Short: "Run the step a run stopped at again", Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := client(cmd)
				if err != nil {
					return err
				}
				return c.act(cmd.Context(), runbookRunPath(args[0], "/retry"), nil, cmd.OutOrStdout())
			},
		},
		&cobra.Command{
			Use:   "rollback <run>",
			Short: "Roll a stopped run back; during a rollback, pass over the step it stopped at",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				c, err := client(cmd)
				if err != nil {
					return err
				}
				return c.act(cmd.Context(), runbookRunPath(args[0], "/rollback"), nil, cmd.OutOrStdout())
			},
		},
	)
	return cmd
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func runbookRunPath(id, suffix string) string {
	return "/api/v1/runbook-runs/" + url.PathEscape(id) + suffix
}

// runbookClient talks to the hub's API with a signed-in session.
type runbookClient struct {
	base    string
	http    *http.Client
	cookies []*http.Cookie
}

// loginRunbookClient signs in with the admin password.
func loginRunbookClient(ctx context.Context, base string, lines *lineReader) (*runbookClient, error) {
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("--hub-url %q must be an http:// or https:// address", base)
	}
	password := os.Getenv("HEARTH_ADMIN_PASSWORD")
	if password == "" {
		if password, err = lines.read("Admin password: "); err != nil {
			return nil, err
		}
	}
	c := &runbookClient{base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: runbookClientTimeout}}
	resp, err := c.send(ctx, http.MethodPost, "/api/v1/login", map[string]string{"password": password})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := apiError(resp); err != nil {
		return nil, fmt.Errorf("sign in: %w", err)
	}
	c.cookies = resp.Cookies()
	return c, nil
}

// lineReader reads the lines a command asks for: unechoed from a terminal, and
// otherwise one after the other from piped input.
type lineReader struct {
	in     io.Reader
	buf    *bufio.Reader
	prompt io.Writer
}

func (l *lineReader) read(label string) (string, error) {
	if f, ok := l.in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		_, _ = fmt.Fprint(l.prompt, label)
		b, err := term.ReadPassword(int(f.Fd()))
		_, _ = fmt.Fprintln(l.prompt)
		if err != nil {
			return "", fmt.Errorf("read input: %w", err)
		}
		return string(b), nil
	}
	line, err := l.buf.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read input: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (c *runbookClient) send(ctx context.Context, method, path string, body any) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encode request: %w", err)
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, r)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach the hub: %w", err)
	}
	return resp, nil
}

// do sends a request and decodes its answer into out.
func (c *runbookClient) do(ctx context.Context, method, path string, body, out any) error {
	resp, err := c.send(ctx, method, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := apiError(resp); err != nil {
		return err
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("read the hub's answer: %w", err)
	}
	return nil
}

// apiError is the error a failed API response carries, or nil.
func apiError(resp *http.Response) error {
	if resp.StatusCode < 300 {
		return nil
	}
	var e hub.ErrorJSON
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&e); err != nil || e.Error == "" {
		return fmt.Errorf("the hub answered %s", resp.Status)
	}
	return errors.New(e.Error)
}

// act posts to path and prints the run the hub answers with.
func (c *runbookClient) act(ctx context.Context, path string, body any, out io.Writer) error {
	var run automation.RunbookRunJSON
	if err := c.do(ctx, http.MethodPost, path, body, &run); err != nil {
		return err
	}
	return printRunbookRun(out, run)
}

func (c *runbookClient) list(ctx context.Context, out io.Writer) error {
	var res struct {
		Runbooks []hub.RunbookJSON `json:"runbooks"`
		Errors   []string          `json:"errors"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/runbooks", nil, &res); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSTEPS\tDESCRIPTION")
	for _, r := range res.Runbooks {
		fmt.Fprintf(tw, "%s\t%d\t%s\n", r.ID, r.Steps, r.Description)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write runbooks: %w", err)
	}
	for _, e := range res.Errors {
		if _, err := fmt.Fprintln(out, "invalid:", e); err != nil {
			return fmt.Errorf("write runbooks: %w", err)
		}
	}
	return nil
}

func (c *runbookClient) plan(ctx context.Context, id string, out io.Writer) error {
	var plan automation.RunbookPlan
	if err := c.do(ctx, http.MethodGet, "/api/v1/runbooks/"+url.PathEscape(id)+"/plan", nil, &plan); err != nil {
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Runbook %s\n", plan.ID)
	if plan.Description != "" {
		fmt.Fprintf(&b, "  %s\n", plan.Description)
	}
	for i, s := range plan.Steps {
		fmt.Fprintf(&b, "%d. %s (%s): %s\n", i+1, s.ID, s.Type, s.What)
		writePlanDecision(&b, "   ", s)
		if s.Rollback != nil {
			fmt.Fprintf(&b, "   rollback: %s\n", s.Rollback.What)
			writePlanDecision(&b, "   ", *s.Rollback)
		}
	}
	b.WriteString("\nPlan only: nothing was executed.\n")
	if _, err := io.WriteString(out, b.String()); err != nil {
		return fmt.Errorf("write plan: %w", err)
	}
	return nil
}

func writePlanDecision(b *strings.Builder, indent string, s automation.RunbookPlanStep) {
	if s.Decision == "" {
		return
	}
	fmt.Fprintf(b, "%spolicy: %s (%s) would be %s", indent, s.Action, s.Class, s.Decision)
	if s.Reason != "" {
		fmt.Fprintf(b, ": %s", s.Reason)
	}
	b.WriteByte('\n')
}

func (c *runbookClient) runs(ctx context.Context, id string, out io.Writer) error {
	var res struct {
		Runs []automation.RunbookRunJSON `json:"runs"`
	}
	path := "/api/v1/runbook-runs"
	if id != "" {
		path += "?runbook=" + url.QueryEscape(id)
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &res); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RUN\tRUNBOOK\tSTATUS\tSTARTED\tBY")
	for _, r := range res.Runs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.ID, r.RunbookID, r.Status,
			r.StartedAt.Local().Format(time.DateTime), r.StartedBy)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write runs: %w", err)
	}
	return nil
}

// printRunbookRun writes a run's steps and log.
func printRunbookRun(out io.Writer, run automation.RunbookRunJSON) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Run %s of %s: %s\n\n", run.ID, run.RunbookID, run.Status)
	for i, s := range run.Steps {
		fmt.Fprintf(&b, "%d. %-8s %s (%s): %s\n", i+1, s.Status, s.ID, s.Type, s.What)
		if s.Error != "" {
			fmt.Fprintf(&b, "   error: %s\n", s.Error)
		}
		if s.Rollback != nil && s.Rollback.Status != "pending" {
			fmt.Fprintf(&b, "   rollback %s: %s\n", s.Rollback.Status, s.Rollback.What)
			if s.Rollback.Error != "" {
				fmt.Fprintf(&b, "   error: %s\n", s.Rollback.Error)
			}
		}
	}
	if run.Awaiting != "" {
		fmt.Fprintf(&b, "\nWaiting for an answer: hearth runbook answer %s %s\n", run.ID, run.Awaiting)
	}
	if run.CanRetry {
		fmt.Fprintf(&b, "\nStopped: hearth runbook retry %s, or hearth runbook rollback %s\n", run.ID, run.ID)
	}
	b.WriteString("\nLog:\n")
	for _, l := range run.Log {
		fmt.Fprintf(&b, "  %s", l.At.Local().Format(time.TimeOnly))
		if l.Step != "" {
			fmt.Fprintf(&b, " [%s]", l.Step)
		}
		if l.Actor != "" {
			fmt.Fprintf(&b, " %s:", l.Actor)
		}
		fmt.Fprintf(&b, " %s\n", l.Message)
	}
	if _, err := io.WriteString(out, b.String()); err != nil {
		return fmt.Errorf("write run: %w", err)
	}
	return nil
}
