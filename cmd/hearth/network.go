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
	"net/url"
	"strings"
	"text/tabwriter"
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
		Short: "Scan the hub's network for hosts without an agent, and adopt them as devices",
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
	login := func(cmd *cobra.Command) (*runbookClient, error) {
		lines := &lineReader{in: cmd.InOrStdin(), buf: bufio.NewReader(cmd.InOrStdin()), prompt: cmd.ErrOrStderr()}
		return loginRunbookClient(cmd.Context(), hubURL, lines)
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "hosts",
		Short: "List the hosts network discovery found",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := login(cmd)
			if err != nil {
				return err
			}
			return c.listNetworkHosts(cmd.Context(), cmd.OutOrStdout())
		},
	})
	var name string
	adopt := &cobra.Command{
		Use:   "adopt <mac>",
		Short: "Adopt a host without an agent (a printer, a TV, a router) as a device",
		Long: "Lists the host on the Devices page under Network devices, by --name, online while scans find\n" +
			"it. Adopting an adopted host renames it. It fires no new-device alerts.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := login(cmd)
			if err != nil {
				return err
			}
			return c.postNetworkHost(cmd.Context(), args[0], "adopt", map[string]string{"name": name})
		},
	}
	adopt.Flags().StringVar(&name, "name", "", "the device's name, 1 to 63 characters (required)")
	_ = adopt.MarkFlagRequired("name")
	cmd.AddCommand(adopt, &cobra.Command{
		Use:   "unadopt <mac>",
		Short: "Stop listing an adopted host as a device",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := login(cmd)
			if err != nil {
				return err
			}
			return c.postNetworkHost(cmd.Context(), args[0], "unadopt", nil)
		},
	})
	return cmd
}

// listNetworkHosts prints the hosts the hub's discovery found, one per line.
func (c *runbookClient) listNetworkHosts(ctx context.Context, out io.Writer) error {
	resp, err := c.send(ctx, http.MethodGet, "/api/v1/network/hosts", nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := apiError(resp); err != nil {
		return err
	}
	var body struct {
		Hosts []hub.NetworkHostJSON `json:"hosts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("read the hub's answer: %w", err)
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "MAC\tIP\tNAME\tKIND\tSTATE\tONLINE")
	for _, h := range body.Hosts {
		name, state := h.Name, h.State
		if name == "" {
			name = h.Hostname
		}
		if h.DeviceID != "" {
			state = "device " + h.DeviceID
		}
		online := "no"
		if h.Online {
			online = "yes"
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", h.MAC, h.IP, orDash(name), h.Kind, orDash(state), online)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("write hosts: %w", err)
	}
	return nil
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// postNetworkHost posts body to /api/v1/network/hosts/{mac}/{verb}.
func (c *runbookClient) postNetworkHost(ctx context.Context, mac, verb string, body any) error {
	resp, err := c.send(ctx, http.MethodPost, "/api/v1/network/hosts/"+url.PathEscape(mac)+"/"+verb, body)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return apiError(resp)
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
