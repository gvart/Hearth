// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"errors"

	mochi "github.com/mochi-mqtt/server/v2"
	"github.com/mochi-mqtt/server/v2/packets"

	"github.com/gvart/hearth/internal/deviceproto"
)

// The Device Protocol (docs/spec/device-protocol-v1.md) on the broker. A
// device is a password user of the clients file whose name is a valid
// protocol id, granted its own topics, hearth/v1/<name>/#. Whatever the
// clients file grants, under hearth/v1/ a client may write only its own
// device topics, and no client writes a command topic: only the hub does,
// through its inline client, once policy has decided.

// ProtocolSink receives the checked Device Protocol messages of the devices
// connected to the broker (hub.DeviceProtocol). Its methods run on the
// broker's packet path, so they must not block.
type ProtocolSink interface {
	// DeviceMessage is a valid message a device published on its own topic.
	DeviceMessage(m deviceproto.Message)
	// DeviceGone is called when the last connection of the password user
	// named id ends: a device that announced itself under id is offline.
	DeviceGone(id string)
}

// ErrNoProtocol is the error of PublishCommand on a broker without a
// ProtocolSink.
var ErrNoProtocol = errors.New("mqtt: the device protocol is not enabled")

// permits is allowed, with the Device Protocol's rules on top: a write under
// hearth/v1/ is allowed only to the identity's own device topics, and never
// to a command topic.
func permits(identity string, rules []Rule, topic string, write bool) bool {
	if write && deviceproto.InNamespace(topic) {
		id, kind, ok := deviceproto.SplitTopic(topic)
		if !ok || id != identity || !deviceproto.DeviceWrites(kind) {
			return false
		}
	}
	return allowed(rules, topic, write)
}

// protocolWill reports whether a will may go on topic: the broker sends a
// will without OnPublish, so under hearth/v1/ it is checked at CONNECT, and
// must be an offline availability message.
func protocolWill(topic string, payload []byte) bool {
	if !deviceproto.InNamespace(topic) {
		return true
	}
	id, kind, ok := deviceproto.SplitTopic(topic)
	if !ok || kind != deviceproto.KindAvailability {
		return false
	}
	m, err := deviceproto.Parse(id, kind, payload)
	return err == nil && !m.Online
}

// OnPublish checks every message a client publishes on a Device Protocol
// topic before the broker delivers or retains it. A message that is too large
// or malformed is acknowledged and dropped, never delivered; a valid one goes
// to the protocol sink. The hub's own publishes (its commands, and what the
// bridge brings in) are not checked here.
func (h *authHook) OnPublish(cl *mochi.Client, pk packets.Packet) (packets.Packet, error) {
	if cl.Net.Inline || !deviceproto.InNamespace(pk.TopicName) {
		return pk, nil
	}
	identity := string(cl.Properties.Username)
	id, kind, ok := deviceproto.SplitTopic(pk.TopicName)
	// The ACL let only the device itself publish here: check again.
	if !ok || id != identity || !deviceproto.DeviceWrites(kind) {
		h.log.Warn("mqtt device message refused", "reason", "not the publisher's own device topic",
			"identity", identity, "topic", pk.TopicName)
		return pk, packets.CodeSuccessIgnore
	}
	m, err := deviceproto.Parse(id, kind, pk.Payload)
	if err != nil {
		// The reason, never the payload.
		h.log.Warn("mqtt device message refused", "reason", err.Error(), "identity", identity,
			"topic", pk.TopicName, "bytes", len(pk.Payload))
		return pk, packets.CodeSuccessIgnore
	}
	if h.protocol != nil {
		h.protocol.DeviceMessage(m)
	}
	return pk, nil
}

// deviceGone tells the protocol sink that cl, a password user, was the last
// connection of its identity.
func (h *authHook) deviceGone(cl *mochi.Client) {
	identity := string(cl.Properties.Username)
	if h.protocol == nil || !deviceproto.ValidID(identity) || h.user(identity) == nil {
		return
	}
	for _, other := range h.srv.Clients.GetAll() {
		if other != cl && !other.Closed() && string(other.Properties.Username) == identity {
			return
		}
	}
	h.protocol.DeviceGone(identity)
}

// PublishCommand publishes payload, a command the hub decided to send, on
// device id's command topic at QoS 1, not retained: a device that is not
// connected never gets it later.
func (b *Broker) PublishCommand(id string, payload []byte) error {
	if b.auth.protocol == nil {
		return ErrNoProtocol
	}
	if !deviceproto.ValidID(id) {
		return errors.New("mqtt: invalid device id")
	}
	if err := b.srv.Publish(deviceproto.Topic(id, deviceproto.KindCommand), payload, false, 1); err != nil {
		return err
	}
	return nil
}

// RemoveUser removes the password user named name: from the clients file
// first, if the broker was given one, so a restart does not bring it back,
// then from the broker. Its connections are ended, and the retained messages
// of its Device Protocol topics cleared. It reports whether this broker had
// the user, in its file or in memory.
func (b *Broker) RemoveUser(name string) (bool, error) {
	inFile := false
	if b.clientsFile != "" {
		b.fileMu.Lock()
		var err error
		inFile, err = RemoveUserFromFile(b.clientsFile, name)
		b.fileMu.Unlock()
		if err != nil {
			return false, err
		}
	}
	inMemory := b.auth.dropUser(name)
	for _, cl := range b.srv.Clients.GetAll() {
		if !cl.Net.Inline && string(cl.Properties.Username) == name {
			_ = b.srv.DisconnectClient(cl, packets.ErrNotAuthorized)
		}
	}
	if b.auth.protocol != nil && deviceproto.ValidID(name) {
		for _, kind := range []string{
			deviceproto.KindAnnounce, deviceproto.KindState, deviceproto.KindTelemetry,
			deviceproto.KindAvailability, deviceproto.KindResult,
		} {
			// An empty retained message clears the one retained.
			_ = b.srv.Publish(deviceproto.Topic(name, kind), nil, true, 0)
		}
	}
	return inFile || inMemory, nil
}

// Connected reports whether the password user named id has a connection.
func (b *Broker) Connected(id string) bool {
	for _, cl := range b.srv.Clients.GetAll() {
		if !cl.Closed() && !cl.Net.Inline && string(cl.Properties.Username) == id {
			return true
		}
	}
	return false
}
