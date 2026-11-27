// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/agent"
	"github.com/gvart/hearth/internal/cluster"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/release"
)

func newAgentCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "agent", Short: "Run or manage the Hearth agent on this device"}
	cmd.AddCommand(newAgentJoinCmd(), newAgentRunCmd(), newAgentMakeHubCmd())
	return cmd
}

func newAgentRunCmd() *cobra.Command {
	var (
		dataDir      string
		ceiling      agent.Ceiling
		dockerSocket string
		localCeiling bool
		allowPlugins []string
		mirror       string
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Connect to the hub and keep reporting this device",
		Long: "Connect to the hub this device joined and keep the connection up: report host facts,\n" +
			"send heartbeats and reconnect with backoff when the hub is unreachable. Stops on SIGINT/SIGTERM.\n\n" +
			"What the hub may do here, its capability ceiling, is managed from the hub: an admin turns each\n" +
			"capability on or off on the device's page in the web UI (Capabilities) or with `hearth device\n" +
			"capabilities`, and the agent applies it at once and saves it in its data dir. The --allow-* flags\n" +
			"add to that, and the hub cannot take away what they grant. --local-ceiling makes the flags the\n" +
			"whole ceiling: the agent then ignores what the hub sets.\n\n" +
			"--allow-exec and --allow-restart name commands and services the hub (its automations) may run\n" +
			"or restart here.\n" +
			"--allow-probe lets the hub's http, tcp and dns checks run from here (from: <device>).\n" +
			"--allow-logs names the logs the hub's UI may stream from here; logs can hold secrets, so none\n" +
			"are readable without it.\n" +
			"--allow-shell lets an admin open a shell here from the web UI's terminal, as this agent's user\n" +
			"(Linux and macOS).\n" +
			"--allow-scan lets the hub's network discovery sweep a subnet from here (--discover-subnet\n" +
			"CIDR@device on the hub), for a subnet the hub is not on; none may be swept without it.\n" +
			"--allow-net-edges reports this device's neighbours and established TCP connections to the hub\n" +
			"every minute (Linux); connections say who talks to whom, so nothing is reported without it.\n" +
			"--allow-docker lets the hub list this device's Docker or Podman containers and images, read the last\n" +
			"lines of a container's log, and start, stop and restart containers; nothing else of the engine.\n" +
			"--allow-plugin NAME[:CLASS][@DIGEST] lets the hub install the exec plugin NAME uploaded to it for\n" +
			"this device's platform, and run its commands of class CLASS (read, the default, safe or dangerous)\n" +
			"or lower. The hub supplies the plugin's program, which runs as this agent's user: whatever the\n" +
			"class, allowing a plugin lets whoever uploads it run code here. DIGEST pins one release, program and\n" +
			"manifest (`hearth plugin list` shows it); without it, the agent pins the first release it installs\n" +
			"(trusting the hub for that one) and refuses any other while the flag stays, whatever its class.\n" +
			"--local-ceiling ignores the capabilities the hub sets for this device, and any it saved before.\n\n" +
			"--release-mirror URL makes the agent upgrade itself from a local release mirror, laid out as the\n" +
			"project's GitHub releases (<URL>/<tag>/<asset>; `hearth release mirror` fills one), instead of\n" +
			"GitHub. It still checks the release's signature with the key compiled in.",
		Example: "  hearth agent run --allow-restart systemd:pihole-FTL.service --allow-restart docker:jellyfin \\\n" +
			"    --allow-exec /usr/bin/df --allow-logs 'systemd:pihole-FTL.service' --allow-logs 'docker:*'",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			for _, e := range ceiling.Logs {
				if err := agent.ParseLogs(e); err != nil {
					return fmt.Errorf("--allow-logs: %w", err)
				}
			}
			for _, e := range ceiling.Scan {
				if err := agent.ParseScan(e); err != nil {
					return fmt.Errorf("--allow-scan: %w", err)
				}
			}
			for _, e := range ceiling.Restart {
				if err := agent.ParseRestart(e); err != nil {
					return fmt.Errorf("--allow-restart: %w", err)
				}
			}
			for _, e := range allowPlugins {
				g, err := agent.ParsePluginGrant(e)
				if err != nil {
					return fmt.Errorf("--allow-plugin: %w", err)
				}
				if slices.ContainsFunc(ceiling.Plugins, func(o agent.PluginGrant) bool { return o.Name == g.Name }) {
					return fmt.Errorf("--allow-plugin: %s given twice", g.Name)
				}
				ceiling.Plugins = append(ceiling.Plugins, g)
			}
			if ceiling.NetEdges && !agent.NetEdgesSupported {
				return errors.New("--allow-net-edges: network edges are only reported on Linux")
			}
			if ceiling.Shell && !agent.ShellSupported {
				return errors.New("--allow-shell: interactive shells are not supported on this platform")
			}
			if mirror != "" {
				m, err := release.MirrorBase(mirror)
				if err != nil {
					return fmt.Errorf("--release-mirror: %w", err)
				}
				mirror = m
			}
			connected, failed, stop := agent.TuneRuntime()
			defer stop()
			return agent.Run(cmd.Context(), agent.Config{
				DataDir:       dataDir,
				Version:       cmd.Root().Version,
				Log:           newLogger(cmd.ErrOrStderr()),
				Ceiling:       ceiling,
				LocalCeiling:  localCeiling,
				ReleaseMirror: mirror,
				DockerSocket:  dockerSocket,
				Connected:     connected,
				Failed:        failed,
			})
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("agent"), "agent data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().StringArrayVar(&ceiling.Exec, "allow-exec", nil,
		"program the hub may run here, matched exactly against the command's first word; repeatable")
	cmd.Flags().StringArrayVar(&ceiling.Restart, "allow-restart", nil,
		"service the hub may restart here, as systemd:UNIT, systemd-user:UNIT or docker:CONTAINER; repeatable")
	cmd.Flags().BoolVar(&ceiling.Probe, "allow-probe", false,
		"let the hub run HTTP, TCP and DNS checks from this device, against anything it can reach")
	cmd.Flags().StringArrayVar(&ceiling.Logs, "allow-logs", nil,
		"log the hub may stream from here, as systemd:UNIT, systemd-user:UNIT or docker:CONTAINER, where the\n"+
			"name may be a glob (systemd:*, docker:*); repeatable")
	cmd.Flags().BoolVar(&ceiling.Shell, "allow-shell", false,
		"let an admin open an interactive shell on this device from the web UI, as this agent's user")
	cmd.Flags().StringArrayVar(&ceiling.Scan, "allow-scan", nil,
		"IPv4 subnet the hub's network discovery may sweep from this device, e.g. 10.0.5.0/24 (or a part of it);\n"+
			"repeatable (default: none)")
	cmd.Flags().BoolVar(&ceiling.NetEdges, "allow-net-edges", false,
		"report this device's neighbour table and a summary of its established TCP connections to the hub (Linux)")
	cmd.Flags().BoolVar(&ceiling.Docker, "allow-docker", false,
		"let the hub list Docker or Podman containers and images here, read a container's last log lines, and\n"+
			"start, stop and restart containers")
	cmd.Flags().StringArrayVar(&allowPlugins, "allow-plugin", nil,
		"exec plugin the hub may install and run here, as NAME[:CLASS][@DIGEST], where CLASS (read, safe or\n"+
			"dangerous; default read) is the highest class of its commands the hub may run and DIGEST pins a\n"+
			"release; repeatable")
	cmd.Flags().BoolVar(&localCeiling, "local-ceiling", false,
		"make the --allow-* flags this device's whole capability ceiling: ignore the capabilities the hub sets")
	cmd.Flags().StringVar(&mirror, "release-mirror", os.Getenv(releaseMirrorEnv),
		"base URL of a local release mirror to upgrade from, as <URL>/<tag>/<asset>, instead of GitHub\n(env "+
			releaseMirrorEnv+")")
	cmd.Flags().StringVar(&dockerSocket, "docker-socket", "",
		"the container engine's unix socket, for Docker (default "+agent.DefaultDockerSocket+
			", then Podman's\n$XDG_RUNTIME_DIR/podman/podman.sock and /run/podman/podman.sock)")
	return cmd
}

func newAgentJoinCmd() *cobra.Command {
	var (
		dataDir, tokenFile, hubDataDir string
		ifNotEnrolled                  bool
	)
	cmd := &cobra.Command{
		Use:   "join [<hub-url>] [<token> | -]",
		Short: "Enroll this device with a hub",
		Long: "Enroll this device with a hub using a token from `hearth token create` or the web UI.\n" +
			"The token names the hub, so the hub URL is optional; given, it is where the agent connects\n" +
			"and the way back if this device cannot reach the hub the token names. The hub is verified\n" +
			"against the CA fingerprint in the token before the token is sent.\n" +
			"The token comes from the " + tokenEnv + " environment variable, or from the first line of\n" +
			"stdin when the token argument is -. Both keep it out of argv, which any local user can read\n" +
			"with ps; a token argument still works but warns for that reason. --token-file reads it from\n" +
			"the first line of a file instead, such as a Kubernetes Secret mounted in the agent's pod.\n\n" +
			"--if-not-enrolled makes a join of a device that is already enrolled a success that does\n" +
			"nothing, so a container can run it before every start (see docs/talos.md).\n\n" +
			"--hub-data-dir offers this device as a hub (the installer passes it): a capable Linux device\n" +
			"(64-bit, 1.5 GiB of memory, 2 GiB free there) enrolled with a token that allows it gets a\n" +
			"cluster join token, written to <dir>/join for `hearth hub --join-file` (docs/cluster.md).",
		Example: "  " + tokenEnv + "=<token> hearth agent join\n" +
			"  " + tokenEnv + "=<token> hearth agent join https://hub.lan:7443",
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			if ifNotEnrolled {
				if _, err := os.Stat(filepath.Join(dataDir, agent.CertFile)); err == nil {
					if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Already enrolled; identity in %s.\n", dataDir); err != nil {
						return fmt.Errorf("write result: %w", err)
					}
					return nil
				}
			}
			// A hub URL has a scheme; a token (base64url and dots) or - never
			// contains "://".
			var hubURL string
			if len(args) > 0 && strings.Contains(args[0], "://") {
				hubURL, args = args[0], args[1:]
			}
			if len(args) > 1 {
				return errors.New("want [<hub-url>] [<token> | -]: the first of two arguments must be the hub URL (https://<hub>:7443)")
			}
			var token string
			var err error
			if tokenFile != "" {
				if len(args) > 0 {
					return errors.New("--token-file and a token argument are mutually exclusive")
				}
				token, err = readTokenFile(tokenFile)
			} else {
				token, err = joinToken(cmd, args)
			}
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			offer := hubOffer(cmd.Context(), hubDataDir, out)
			res, err := agent.JoinWith(cmd.Context(), agent.JoinOptions{
				HubURL: hubURL, Token: token, DataDir: dataDir, Hostname: hostnameOr(""), HubOffer: offer,
			})
			if err != nil {
				return err
			}
			if _, err := fmt.Fprintf(out, "Enrolled as device %s; identity stored in %s.\n", res.DeviceID, dataDir); err != nil {
				return fmt.Errorf("write result: %w", err)
			}
			if offer != nil {
				return writeHubJoin(hubDataDir, res.HubJoin, out)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir("agent"), "agent data directory (env HEARTH_DATA_DIR)")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "file whose first line is the enrollment token")
	cmd.Flags().BoolVar(&ifNotEnrolled, "if-not-enrolled", false,
		"do nothing, successfully, if this device is already enrolled")
	cmd.Flags().StringVar(&hubDataDir, "hub-data-dir", "",
		"offer this device as a hub whose data dir this is, if capable and the token allows it (the installer sets it)")
	return cmd
}

// hubOffer is the hub offer of this device for a hub at hubDataDir: nil
// without one, or when the device is not capable, which it says.
func hubOffer(ctx context.Context, hubDataDir string, out io.Writer) *agentv1.HubOffer {
	if hubDataDir == "" {
		return nil
	}
	o, err := cluster.LocalHubOffer(ctx, hubDataDir)
	if err == nil {
		err = cluster.HubCapable(o)
	}
	if err != nil {
		_, _ = fmt.Fprintf(out, "This device stays an agent, not a hub: %v.\n", err)
		return nil
	}
	return &agentv1.HubOffer{Os: o.OS, Arch: o.Arch, MemTotal: o.MemTotal, DiskFree: o.DiskFree}
}

// writeHubJoin writes the join the hub minted for this device into
// hubDataDir, for `hearth hub --join-file`, or says why there is none.
func writeHubJoin(hubDataDir string, hj *agentv1.HubJoin, out io.Writer) error {
	if hj.GetToken() == "" {
		reason := hj.GetRefused()
		if reason == "" {
			reason = "the hub made no offer (an older hub)"
		}
		_, err := fmt.Fprintf(out, "This device stays an agent, not a hub: %s.\n", reason)
		return err
	}
	if err := cluster.WriteJoinFile(filepath.Join(hubDataDir, cluster.JoinFileName),
		cluster.JoinFile{URL: hj.GetUrl(), Token: hj.GetToken()}); err != nil {
		return err
	}
	_, err := fmt.Fprintf(out, "This device becomes a hub (%s): `hearth hub --join-file %s` joins the cluster.\n",
		strings.Join(hj.GetRoles(), ", "), filepath.Join(hubDataDir, cluster.JoinFileName))
	return err
}

// readTokenFile reads an enrollment token from the first line of a file.
func readTokenFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("--token-file: %w", err)
	}
	defer func() { _ = f.Close() }()
	line, err := bufio.NewReader(io.LimitReader(f, maxTokenLine)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("--token-file: %w", err)
	}
	token := strings.TrimSpace(line)
	if token == "" {
		return "", fmt.Errorf("--token-file: no token in %s", path)
	}
	return token, nil
}

// tokenEnv names the environment variable `hearth agent join` reads the
// enrollment token from.
const tokenEnv = "HEARTH_TOKEN"

// joinToken returns the enrollment token from the optional token argument
// (- reads stdin) or else from $HEARTH_TOKEN. It always unsets HEARTH_TOKEN,
// so no process started later inherits the token.
func joinToken(cmd *cobra.Command, args []string) (string, error) {
	env := strings.TrimSpace(os.Getenv(tokenEnv))
	if err := os.Unsetenv(tokenEnv); err != nil {
		return "", fmt.Errorf("unset %s: %w", tokenEnv, err)
	}
	switch {
	case len(args) == 0:
		if env == "" {
			return "", errors.New("no enrollment token: set " + tokenEnv + "=<token>, or pass - and the token on stdin")
		}
		return env, nil
	case args[0] == "-":
		return readToken(cmd.InOrStdin())
	default:
		// Best effort: a warning that cannot be written must not fail the join.
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "warning: a token argument is visible to other local users (ps); pass it as "+
			tokenEnv+"=<token> instead")
		return args[0], nil
	}
}

// maxTokenLine bounds the stdin read; real tokens are about 100 bytes.
const maxTokenLine = 4 << 10

// readToken reads an enrollment token from the first line of in.
func readToken(in io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(in, maxTokenLine)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read token from stdin: %w", err)
	}
	token := strings.TrimSpace(line)
	if token == "" {
		return "", errors.New("no token on stdin (token argument was -)")
	}
	return token, nil
}
