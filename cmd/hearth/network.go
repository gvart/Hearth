// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/hub"
)

// networkScanWait bounds how long `hearth network scan` waits for the scan
// to end.
const networkScanWait = 10 * time.Minute

func newNetworkCmd() *cobra.Command {
	var hubURL string
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Scan the hub's network for hosts without an agent",
		Long: "These commands use the hub's API with a signed-in session: the admin password comes from\n" +
			"HEARTH_ADMIN_PASSWORD or is asked for. See docs/discovery.md.",
	}
	cmd.PersistentFlags().StringVar(&hubURL, "hub-url", envOr("HEARTH_HUB_URL", "http://127.0.0.1:"+defaultHTTPPort),
		"the hub's web address (env HEARTH_HUB_URL)")
	cmd.AddCommand(&cobra.Command{
		Use:   "scan",
		Short: "Scan the network now and wait for the result",
		Long: "Scans the subnets of --discover-subnet or, when the hub has none, its own LANs, once, from\n" +
			"the hub that answers. The hosts it finds are listed on the Devices page under On your network.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			lines := &lineReader{in: cmd.InOrStdin(), buf: bufio.NewReader(cmd.InOrStdin()), prompt: cmd.ErrOrStderr()}
			c, err := loginRunbookClient(cmd.Context(), hubURL, lines)
			if err != nil {
				return err
			}
			return c.scanNetwork(cmd.Context(), cmd.OutOrStdout())
		},
	})
	return cmd
}

// scanNetwork starts a scan and prints how it ended, from the done event
// with the scan's id. It listens to the hub's events before starting it, so
// that the end cannot be missed.
func (c *runbookClient) scanNetwork(ctx context.Context, out io.Writer) error {
	ctx, cancel := context.WithTimeout(ctx, networkScanWait)
	defer cancel()
	events, err := c.events(ctx)
	if err != nil {
		return err
	}
	defer events.Close()
	sc := bufio.NewScanner(events)
	if !sc.Scan() || sc.Text() != ": subscribed" {
		return errors.New("the hub's event stream did not start")
	}

	resp, err := c.send(ctx, http.MethodPost, "/api/v1/network/scan", nil)
	if err != nil {
		return err
	}
	var started hub.NetworkScanStartedJSON
	err = apiError(resp)
	if err == nil {
		if err = json.NewDecoder(resp.Body).Decode(&started); err != nil {
			err = fmt.Errorf("read the hub's answer: %w", err)
		}
	}
	_ = resp.Body.Close()
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(out, "Scanning the network…")

	var name string
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "event: "); ok {
			name = v
			continue
		}
		v, ok := strings.CutPrefix(line, "data: ")
		if !ok || name != hub.EventNetworkScanDone {
			continue
		}
		var done hub.NetworkScanJSON
		if err := json.Unmarshal([]byte(v), &done); err != nil {
			return fmt.Errorf("read the hub's answer: %w", err)
		}
		if done.ID != started.ID {
			continue // another admin's scan
		}
		if done.Error != "" {
			return fmt.Errorf("the scan failed: %s", done.Error)
		}
		_, err := fmt.Fprintf(out, "Found %d hosts: %d new, %d back (%s)\n", done.Hosts, done.New, done.Returned,
			(time.Duration(done.DurationMS) * time.Millisecond).Round(100*time.Millisecond))
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("the scan did not end within %s", networkScanWait)
	}
	return errors.New("the hub's event stream ended before the scan did")
}

// events opens the hub's event stream, with no timeout but ctx's.
func (c *runbookClient) events(ctx context.Context) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+"/api/v1/events", nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	stream := &http.Client{Transport: c.http.Transport}
	resp, err := stream.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach the hub: %w", err)
	}
	if err := apiError(resp); err != nil {
		_ = resp.Body.Close()
		return nil, err
	}
	return resp.Body, nil
}
