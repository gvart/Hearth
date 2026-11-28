// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/hub"
)

// errAuditNotOK is what `hearth audit verify` exits with when the log has
// entries missing, out of their chain or failing their seal.
var errAuditNotOK = errors.New("the audit log does not verify")

func newAuditCmd() *cobra.Command {
	var hubURL string
	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Check the audit log (see docs/security.md)",
		Long: "These commands use the hub's API with a signed-in session: the admin password comes from\n" +
			"HEARTH_ADMIN_PASSWORD or is asked for.",
	}
	cmd.PersistentFlags().StringVar(&hubURL, "hub-url", envOr("HEARTH_HUB_URL", "http://127.0.0.1:"+defaultHTTPPort),
		"the hub's web address (env HEARTH_HUB_URL)")
	verify := &cobra.Command{
		Use:   "verify",
		Short: "Check every audit entry's seal and every master's chain of entries",
		Long: "A master seals each audit entry it writes with a key derived from the hub CA key, and numbers it\n" +
			"in a chain of its own. verify reads the whole log on the hub and reports, per master, the entries\n" +
			"missing (deleted), out of their chain (moved or replaced) or failing their seal (forged or changed),\n" +
			"and the entries without a seal: legacy ones, written before sealing started, and the others. It\n" +
			"exits non-zero when anything is wrong. The web UI's Audit page shows the same.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			lines := &lineReader{in: cmd.InOrStdin(), buf: bufio.NewReader(cmd.InOrStdin()), prompt: cmd.ErrOrStderr()}
			c, err := loginRunbookClient(cmd.Context(), hubURL, lines)
			if err != nil {
				return err
			}
			var rep hub.AuditVerifyJSON
			if err := c.do(cmd.Context(), http.MethodGet, "/api/v1/audit/verify", nil, &rep); err != nil {
				return err
			}
			printAuditReport(cmd.OutOrStdout(), rep)
			if !rep.OK {
				return errAuditNotOK
			}
			return nil
		},
	}
	cmd.AddCommand(verify)
	return cmd
}

func printAuditReport(out io.Writer, rep hub.AuditVerifyJSON) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(out, format, a...) }
	if !rep.CanVerify {
		p("This hub holds no hub CA key (a storage-only member): it cannot check seals, only the sequence numbers.\n")
	}
	p("%d entries: %d legacy (written before sealing started), %d without a seal since\n", rep.Entries, rep.Legacy, rep.Unsealed)
	verified := 0
	for _, c := range rep.Chains {
		verified += c.Verified
	}
	// Each hub, and each admin command run on a master's host, seals in a
	// chain of its own: only the chains with a problem are listed.
	p("%d chains, %d entries verified\n", len(rep.Chains), verified)
	for _, c := range rep.Chains {
		if c.OK() {
			continue
		}
		p("%s: entries 1-%d, %d verified: NOT OK\n", c.Origin, c.Last, c.Verified)
		for _, m := range c.Missing {
			if m.From == m.To {
				p("  entry %d from %s missing\n", m.From, c.Origin)
			} else {
				p("  entries %d-%d from %s missing\n", m.From, m.To, c.Origin)
			}
		}
		for _, s := range c.Unverified {
			p("  entry %d: its seal does not check (forged or changed)\n", s)
		}
		for _, s := range c.Broken {
			p("  entry %d: does not follow the entry before it (moved or replaced)\n", s)
		}
		for _, s := range c.Duplicates {
			p("  entry %d: two different entries have this number (a hub restored from an older backup?)\n", s)
		}
	}
	if rep.Unsealed > 0 {
		p("%d entries written since sealing started have no seal: forged, or written by a member without the hub CA key\n", rep.Unsealed)
	}
	if rep.OK {
		p("The audit log verifies.\n")
	}
}
