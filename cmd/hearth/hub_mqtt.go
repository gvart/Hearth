// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/mqtt"
	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// mqttOptions configure the embedded MQTT broker, off unless listen is set.
type mqttOptions struct {
	listen string
	// clients is the MQTT clients file; default <data-dir>/mqtt.yaml.
	clients string
	// bridge is the bridge file, connecting the broker to a remote one.
	bridge string
}

func addMQTTFlags(cmd *cobra.Command, o *mqttOptions) {
	cmd.Flags().StringVar(&o.listen, "mqtt-listen", os.Getenv("HEARTH_MQTT_LISTEN"),
		"address to serve the embedded MQTT broker on, over TLS, e.g. :8883 (env HEARTH_MQTT_LISTEN; "+
			"default: off; see docs/mqtt.md)")
	cmd.Flags().StringVar(&o.clients, "mqtt-clients", os.Getenv("HEARTH_MQTT_CLIENTS"),
		"file of the MQTT users and devices allowed to connect and their topics "+
			"(env HEARTH_MQTT_CLIENTS; default <data-dir>/mqtt.yaml)")
	cmd.Flags().StringVar(&o.bridge, "mqtt-bridge", os.Getenv("HEARTH_MQTT_BRIDGE"),
		"file of a remote MQTT broker to bridge topics with; its password comes from "+
			"HEARTH_MQTT_BRIDGE_PASSWORD or the file's password_file (env HEARTH_MQTT_BRIDGE; default: off)")
}

// newMQTTBroker returns the embedded MQTT broker, listening, or nil if
// --mqtt-listen is not set. The caller must Run it, which closes the listener.
// protocol, if not nil, takes the Device Protocol messages of its devices.
func newMQTTBroker(ctx context.Context, opts hubOptions, ca *pki.CA, serverCert func() *tls.Certificate,
	st *store.Store, protocol *hub.DeviceProtocol, log *slog.Logger,
) (*mqtt.Broker, error) {
	if opts.mqtt.listen == "" {
		if opts.mqtt.bridge != "" {
			return nil, errors.New("--mqtt-bridge needs --mqtt-listen: it bridges the embedded broker")
		}
		return nil, nil
	}
	path := opts.mqtt.clients
	if path == "" {
		path = filepath.Join(opts.dataDir, "mqtt.yaml")
	}
	clients, err := mqtt.LoadClients(path)
	if err != nil {
		return nil, fmt.Errorf("--mqtt-clients: %w", err)
	}
	if mqtt.Exposed(path) {
		log.Warn("MQTT clients file is readable by other users, and holds password hashes: chmod 600 it", "path", path)
	}
	var bridge *mqtt.BridgeConfig
	if opts.mqtt.bridge != "" {
		if bridge, err = mqtt.LoadBridge(opts.mqtt.bridge, os.Getenv("HEARTH_MQTT_BRIDGE_PASSWORD")); err != nil {
			return nil, fmt.Errorf("--mqtt-bridge: %w", err)
		}
	}
	ln, err := (&net.ListenConfig{}).Listen(ctx, "tcp", opts.mqtt.listen)
	if err != nil {
		return nil, fmt.Errorf("--mqtt-listen %s: %w", opts.mqtt.listen, err)
	}
	var sink mqtt.ProtocolSink
	if protocol != nil {
		sink = protocol
	}
	b, err := mqtt.New(mqtt.Config{
		Listener: ln, CA: ca, ServerCert: serverCert, Clients: clients, Certs: st.Certs(), Bridge: bridge,
		Protocol: sink, Log: log.With("component", "mqtt"),
	})
	if err != nil {
		_ = ln.Close()
		return nil, err
	}
	log.Info("MQTT broker listening", "addr", b.Addr().String(), "clients_file", path,
		"users", len(clients.Users), "devices", len(clients.Devices))
	if bridge != nil {
		log.Info("MQTT bridge configured", "remote", bridge.Address, "bridge_file", opts.mqtt.bridge, "topics", len(bridge.Topics))
	}
	return b, nil
}
