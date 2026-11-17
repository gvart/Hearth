// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/pki"
	agentv1 "github.com/gvart/hearth/internal/proto/hearth/agent/v1"
	"github.com/gvart/hearth/internal/proto/hearth/agent/v1/agentv1connect"
	"github.com/gvart/hearth/internal/store"
)

// connectOnce opens one agent stream to url with cert and returns how the hub
// answered the Hello (nil: Welcome).
func connectOnce(t *testing.T, ca *pki.CA, url string, cert tls.Certificate) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream := agentv1connect.NewAgentServiceClient(tlsClient(ca, cert), url).Connect(ctx)
	defer func() { _ = stream.CloseRequest() }()
	_ = stream.Send(&agentv1.AgentMessage{Payload: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
		ProtocolVersion: &agentv1.ProtocolVersion{Major: hub.ProtocolMajor}, Hostname: "dev",
	}}})
	msg, err := stream.Receive()
	if err == nil && msg.GetWelcome() == nil {
		return errors.New("no welcome")
	}
	return err
}

// ghostCert is a client certificate the cluster CA signed but no store
// recorded: what a device enrolled on the leader looks like to a hub whose
// store has not caught up yet.
func ghostCert(t *testing.T, ca *pki.CA, id string) tls.Certificate {
	t.Helper()
	key, err := pki.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.NewCSR(key, id)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := ca.SignClientCSR(csr, id, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: key, Leaf: cert}
}

// A clustered hub judges agent certificates only while it leads within a
// term: a follower's store may lag the cluster, so a certificate it does not
// know (or a revocation it holds) yields NotLeader, never Unauthenticated. A
// healthy agent then moves to the leader instead of being turned away.
func TestOnlyTheLeaderRejectsAgentCerts(t *testing.T) {
	hubs := startHubs(t, hubOpts{offlineAfter: 5 * time.Second, flushEvery: time.Minute})
	leader := leaderHub(t, hubs)
	follower := followers(hubs, leader)[0]
	eventually(t, "the leader's term", func() bool {
		return connect.CodeOf(connectOnce(t, leader.ca, leader.url, ghostCert(t, leader.ca, "probe"))) == connect.CodeUnauthenticated
	})

	unknown := ghostCert(t, leader.ca, "ghost")
	revoked := enrollTestDevice(t, leader, "gone")
	if _, err := leader.st.Certs().RevokeDevice(t.Context(), "gone", time.Now()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the revocation on the follower", func() bool {
		return errors.Is(follower.st.Certs().Check(t.Context(), pki.SerialString(revoked.Leaf), "gone"), store.ErrCertRevoked)
	})

	for _, tt := range []struct {
		name string
		cert tls.Certificate
	}{{"unknown", unknown}, {"revoked", revoked}} {
		t.Run(tt.name, func(t *testing.T) {
			err := connectOnce(t, leader.ca, follower.url, tt.cert)
			nl := notLeaderDetail(err)
			if nl == nil {
				t.Fatalf("follower answered %v, want FailedPrecondition with a NotLeader detail", err)
			}
			if nl.GetLeaderUrl() != leader.url {
				t.Errorf("NotLeader names %s, want the leader %s", nl.GetLeaderUrl(), leader.url)
			}
			if got := connect.CodeOf(connectOnce(t, leader.ca, leader.url, tt.cert)); got != connect.CodeUnauthenticated {
				t.Errorf("leader answered %v, want Unauthenticated", got)
			}
		})
	}
}
