// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/mcpserver"
	"github.com/gvart/hearth/internal/policy"
	"github.com/gvart/hearth/internal/store"
)

func newMCPCmd() *cobra.Command {
	var hubURL, caFile string
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve the hub's MCP tools to an AI assistant over stdio",
		Long: "Bridges an MCP client (Claude Code, Claude Desktop, ...) on stdin/stdout to the hub's MCP endpoint\n" +
			"(" + mcpserver.Path + "), as the MCP token in HEARTH_MCP_TOKEN. Create one with `hearth mcp token create` on the\n" +
			"hub host. Every tool call goes through the hub's policy and audit log as mcp/<token name>.\n\n" +
			"  claude mcp add hearth --env HEARTH_MCP_TOKEN=... -- hearth mcp --hub http://hub.lan:7080\n\n" +
			"Clients that speak streamable HTTP can use the endpoint directly, with the token as a bearer token.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			token := os.Getenv("HEARTH_MCP_TOKEN")
			if token == "" {
				return errors.New("HEARTH_MCP_TOKEN is not set: create a token with `hearth mcp token create <name>` on the hub host")
			}
			hc, err := mcpHTTPClient(caFile)
			if err != nil {
				return err
			}
			endpoint, err := mcpEndpoint(hubURL)
			if err != nil {
				return err
			}
			// stdout carries the protocol: logs go to stderr.
			log := newLogger(cmd.ErrOrStderr())
			return mcpserver.Bridge(cmd.Context(), endpoint, token, hc, cmd.InOrStdin(), cmd.OutOrStdout(), log)
		},
	}
	hubDefault := os.Getenv("HEARTH_HUB_URL")
	if hubDefault == "" {
		hubDefault = "http://localhost:" + defaultHTTPPort
	}
	cmd.Flags().StringVar(&hubURL, "hub", hubDefault, "the hub's web URL, http or https (env HEARTH_HUB_URL)")
	cmd.Flags().StringVar(&caFile, "ca-file", "",
		"CA certificate to trust for an https hub, e.g. the hub's own CA from http://<hub>:7080/ca.crt")
	cmd.AddCommand(newMCPTokenCmd())
	return cmd
}

// mcpEndpoint is the MCP endpoint of the hub at raw.
func mcpEndpoint(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("--hub %q must be an http or https URL, e.g. http://hub.lan:7080", raw)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + mcpserver.Path
	return u.String(), nil
}

// mcpHTTPClient trusts caFile, if set, on top of the system roots.
func mcpHTTPClient(caFile string) (*http.Client, error) {
	if caFile == "" {
		return &http.Client{}, nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("--ca-file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("--ca-file %s: no PEM certificate", caFile)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool}
	return &http.Client{Transport: tr}, nil
}

func newMCPTokenCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "token",
		Short: "Create, list and revoke the tokens of MCP clients",
		Long: "An MCP token identifies one MCP client (mcp/<name> in policy and the audit log) and caps what it may\n" +
			"do: its scope is the highest class of action it may request (read, safe or dangerous). Run these on\n" +
			"a hub host.",
	}
	cmd.AddCommand(newMCPTokenCreateCmd(), newMCPTokenListCmd(), newMCPTokenRevokeCmd())
	return cmd
}

// mcpTokenName is what a token name looks like: it names the actor in the
// audit log.
var mcpTokenName = sync.OnceValue(func() *regexp.Regexp { return regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`) })

func newMCPTokenCreateCmd() *cobra.Command {
	var (
		dataDir, scope string
		dryRun         bool
	)
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an MCP token; it is printed once",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMCPTokenCreate(cmd.Context(), dataDir, args[0], scope, dryRun, cmd.OutOrStdout())
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().StringVar(&scope, "scope", string(policy.Safe),
		"highest class of action the token may request: read, safe or dangerous (dangerous actions are still held for approval by default)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "decide and audit the creation without creating the token")
	return cmd
}

func runMCPTokenCreate(ctx context.Context, dataDir, name, scope string, dryRun bool, out io.Writer) error {
	if !mcpTokenName().MatchString(name) {
		return fmt.Errorf("name %q must be 1 to 64 lowercase letters, digits, ., - or _, starting with a letter or digit", name)
	}
	switch policy.Class(scope) {
	case policy.Read, policy.Safe, policy.Dangerous:
	default:
		return fmt.Errorf("--scope %q must be read, safe or dangerous", scope)
	}
	st, err := openExistingHubStore(ctx, dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	secret := mcpserver.TokenPrefix + strings.ToLower(rand.Text())
	done, err := adminDo(ctx, dataDir, st, out, dryRun, policy.Request{
		Action: policy.MCPTokenCreate, Target: name, Detail: map[string]any{"scope": scope},
	}, func(ctx context.Context) error {
		return st.MCPTokens().Create(ctx, name, secret, scope, time.Now())
	})
	if errors.Is(err, store.ErrSchemaTooOld) {
		return errors.New("the hub cluster's database predates MCP tokens: run `hearth cluster migrate` first")
	}
	if err != nil {
		if store.IsDomainError(err) {
			return fmt.Errorf("create mcp token %s: the name is taken (names are never reused, even revoked): %w", name, err)
		}
		return err
	}
	if !done {
		return nil
	}
	_, err = fmt.Fprintf(out, "Created MCP token %s (scope %s). It is shown once; keep it secret:\n\n  %s\n\n"+
		"Claude Code, over stdio:\n  claude mcp add hearth --env HEARTH_MCP_TOKEN=%s -- hearth mcp --hub http://<hub>:%s\n"+
		"or over HTTP:\n  claude mcp add --transport http hearth http://<hub>:%s%s --header \"Authorization: Bearer %s\"\n",
		name, scope, secret, secret, defaultHTTPPort, defaultHTTPPort, mcpserver.Path, secret)
	if err != nil {
		return fmt.Errorf("write token: %w", err)
	}
	return nil
}

func newMCPTokenListCmd() *cobra.Command {
	var dataDir string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List MCP tokens, revoked ones included",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			st, err := openExistingHubStore(cmd.Context(), dataDir)
			if err != nil {
				return err
			}
			defer st.Close()
			toks, err := st.MCPTokens().List(cmd.Context())
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tSCOPE\tCREATED\tREVOKED")
			for _, t := range toks {
				revoked := "-"
				if !t.RevokedAt.IsZero() {
					revoked = t.RevokedAt.Local().Format(time.DateTime)
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.Name, t.Scope, t.CreatedAt.Local().Format(time.DateTime), revoked)
			}
			if err := tw.Flush(); err != nil {
				return fmt.Errorf("write tokens: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	return cmd
}

func newMCPTokenRevokeCmd() *cobra.Command {
	var (
		dataDir string
		dryRun  bool
	)
	cmd := &cobra.Command{
		Use:   "revoke <name>",
		Short: "Revoke an MCP token: the hub refuses it from its next request",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, out, name := cmd.Context(), cmd.OutOrStdout(), args[0]
			st, err := openExistingHubStore(ctx, dataDir)
			if err != nil {
				return err
			}
			defer st.Close()
			done, err := adminDo(ctx, dataDir, st, out, dryRun, policy.Request{
				Action: policy.MCPTokenRevoke, Target: name,
			}, func(ctx context.Context) error { return st.MCPTokens().Revoke(ctx, name, time.Now()) })
			if errors.Is(err, store.ErrNotFound) {
				return fmt.Errorf("no MCP token %s in use", name)
			}
			if err != nil || !done {
				return err
			}
			if _, err := fmt.Fprintf(out, "Revoked MCP token %s.\n", name); err != nil {
				return fmt.Errorf("write result: %w", err)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("hub"), "hub data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "decide and audit the revocation without revoking the token")
	return cmd
}
