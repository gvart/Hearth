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

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/deviceproto"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/store"
)

// Commands for Device Protocol devices (docs/spec/device-protocol-v1.md),
// through the hub's API, as the web UI does.

func newDeviceCommandCmd() *cobra.Command {
	var (
		hubURL string
		params []string
	)
	cmd := &cobra.Command{
		Use:   "command <device> <command>",
		Short: "Send a Device Protocol device one of the commands it announced",
		Long: "Sends the command through the hub's API: it is the policy action device.command, dangerous and\n" +
			"audited, and the hub waits up to 10 seconds for the device's result. <device> is the device's ID\n" +
			"or its Device Protocol id (its MQTT username). Each --param key=value goes into the command's\n" +
			"params: a value that is JSON (true, 3, \"x\", {...}) is taken as such, anything else as a string.\n" +
			"This uses the hub's API with a signed-in session: the admin password comes from\n" +
			"HEARTH_ADMIN_PASSWORD or is asked for.",
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			body, err := commandParams(params)
			if err != nil {
				return err
			}
			c, err := deviceAPIClient(cmd, hubURL)
			if err != nil {
				return err
			}
			return c.protocolCommand(cmd.Context(), args[0], hub.CommandRequest{Command: args[1], Params: body}, cmd.OutOrStdout())
		},
	}
	addHubURLFlag(cmd, &hubURL)
	cmd.Flags().StringArrayVar(&params, "param", nil, "a param of the command, key=value (repeatable)")
	return cmd
}

func newDeviceRemoveCmd() *cobra.Command {
	var hubURL string
	cmd := &cobra.Command{
		Use:   "remove <device>",
		Short: "Remove a Device Protocol device and its MQTT user",
		Long: "Removes the device's MQTT user from the hub's clients file and broker, which disconnects it\n" +
			"and refuses its next login, then the device itself. It is the policy action device.remove,\n" +
			"dangerous and audited. Only this hub's clients file is changed: in a cluster, the device's user\n" +
			"may be in the file of the hub it connects to. An enrolled device is revoked instead\n" +
			"(`hearth device revoke`). <device> is the device's ID or its Device Protocol id.\n" +
			"This uses the hub's API with a signed-in session: the admin password comes from\n" +
			"HEARTH_ADMIN_PASSWORD or is asked for.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := deviceAPIClient(cmd, hubURL)
			if err != nil {
				return err
			}
			return c.removeProtocolDevice(cmd.Context(), args[0], cmd.OutOrStdout())
		},
	}
	addHubURLFlag(cmd, &hubURL)
	return cmd
}

func addHubURLFlag(cmd *cobra.Command, hubURL *string) {
	cmd.Flags().StringVar(hubURL, "hub-url", envOr("HEARTH_HUB_URL", "http://127.0.0.1:"+defaultHTTPPort),
		"the hub's web address (env HEARTH_HUB_URL)")
}

// deviceAPIClient signs in to the hub. Signing in enters the password: it
// counts as entering it again, for the dangerous actions.
func deviceAPIClient(cmd *cobra.Command, hubURL string) (*runbookClient, error) {
	lines := &lineReader{in: cmd.InOrStdin(), buf: bufio.NewReader(cmd.InOrStdin()), prompt: cmd.ErrOrStderr()}
	return loginRunbookClient(cmd.Context(), hubURL, lines)
}

// commandParams makes the params object of --param key=value flags, or nil
// for none.
func commandParams(params []string) (json.RawMessage, error) {
	if len(params) == 0 {
		return nil, nil
	}
	obj := map[string]json.RawMessage{}
	for _, p := range params {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--param %q: want key=value", p)
		}
		if _, dup := obj[k]; dup {
			return nil, fmt.Errorf("--param %s is given twice", k)
		}
		if json.Valid([]byte(v)) {
			obj[k] = json.RawMessage(v)
		} else {
			s, _ := json.Marshal(v)
			obj[k] = s
		}
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("encode params: %w", err)
	}
	return b, nil
}

// protocolIDs are the registry IDs device may name: itself, then, if it is a
// valid Device Protocol id, the device that id registers.
func protocolIDs(device string) []string {
	ids := []string{device}
	if deviceproto.ValidID(device) {
		if id := store.ProtocolDeviceID(device); id != device {
			ids = append(ids, id)
		}
	}
	return ids
}

// errNotFound is the hub's 404 for a device that is not one.
type errNotFound struct{ err error }

func (e errNotFound) Error() string { return e.err.Error() }

// protocolDo sends method to path(id) for each ID device may name, until
// the hub finds one, and decodes its answer into out. A 404 changes nothing
// on the hub.
func (c *runbookClient) protocolDo(ctx context.Context, method, device string, path func(id string) string, body, out any) error {
	var err error
	for _, id := range protocolIDs(device) {
		var resp *http.Response
		if resp, err = c.send(ctx, method, path(id), body); err != nil {
			return err
		}
		err = func() error {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusNotFound {
				return errNotFound{apiError(resp)}
			}
			if err := apiError(resp); err != nil {
				return err
			}
			if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
				return fmt.Errorf("read the hub's answer: %w", err)
			}
			return nil
		}()
		if !errors.As(err, new(errNotFound)) {
			return err
		}
	}
	return err
}

func (c *runbookClient) protocolCommand(ctx context.Context, device string, req hub.CommandRequest, out io.Writer) error {
	var res hub.CommandResult
	err := c.protocolDo(ctx, http.MethodPost, device, func(id string) string {
		return "/api/v1/devices/" + url.PathEscape(id) + "/commands"
	}, req, &res)
	if err != nil {
		return fmt.Errorf("%s on %s: %w", req.Command, device, err)
	}
	_, err = fmt.Fprintf(out, "%s on %s: ok", req.Command, device)
	if err == nil && res.Message != "" {
		_, err = fmt.Fprintf(out, ": %s", res.Message)
	}
	if err == nil {
		_, err = fmt.Fprintln(out)
	}
	return err
}

func (c *runbookClient) removeProtocolDevice(ctx context.Context, device string, out io.Writer) error {
	var res hub.RemoveResult
	err := c.protocolDo(ctx, http.MethodDelete, device, func(id string) string {
		return "/api/v1/devices/" + url.PathEscape(id)
	}, nil, &res)
	if err != nil {
		return fmt.Errorf("remove %s: %w", device, err)
	}
	if _, err := fmt.Fprintf(out, "Removed device %s.\n", res.ID); err != nil {
		return err
	}
	msg := "Its MQTT user is gone from this hub's clients file: it cannot log in again.\n"
	if !res.MQTTUserRemoved {
		msg = "This hub's clients file had no MQTT user for it: remove its user from the clients file of the hub it connects to, or it announces itself again.\n"
	}
	_, err = io.WriteString(out, msg)
	return err
}
