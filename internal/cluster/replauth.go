// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"net"

	"github.com/gvart/hearth/internal/pki"
	"github.com/gvart/hearth/internal/store"
)

// Who may write the global rows (#382).
//
// The global rows (the admin password, the configuration documents, the
// device plugins and ceilings, the hub certificates, ...) are written by
// masters only. What a member says of its roles on the gossip is its own
// word, so a member proves it is a master by holding the hub CA key, which
// only masters have: on each replication connection, each end that holds it
// signs the connection's TLS exporter with it (MasterKey). A member takes
// global rows, and commands to coordinate (opApply), only from a peer that
// proved it, and drops the global rows it fetches from one that did not. A
// storage-only member still relays the sharded rows: it is one of their
// replicas.

// MasterKey proves and checks that a member holds the hub CA key.
type MasterKey interface {
	// Holds reports whether this member holds a hub CA key.
	Holds() bool
	// Prove signs msg with a hub CA key this member holds; ok is false
	// when it holds none.
	Prove(msg []byte) (sig []byte, ok bool)
	// Verify reports whether sig is a signature of msg by the key of a hub
	// CA this member trusts.
	Verify(msg, sig []byte) bool
}

// CAMasterKey is the MasterKey of a hub CA.
func CAMasterKey(ca *pki.CA) MasterKey { return caMasterKey{ca} }

type caMasterKey struct{ ca *pki.CA }

func (k caMasterKey) Holds() bool { return k.ca.HasKey() || k.ca.HasNextKey() }

func (k caMasterKey) Prove(msg []byte) ([]byte, bool) {
	for _, c := range k.ca.TrustedCerts() {
		if sig, err := k.ca.ProveKey(pki.FingerprintHex(c), msg); err == nil {
			return sig, true
		}
	}
	return nil, false
}

func (k caMasterKey) Verify(msg, sig []byte) bool {
	for _, c := range k.ca.TrustedCerts() {
		if pki.VerifyKeyProof(c, msg, sig) == nil {
			return true
		}
	}
	return false
}

// binder is a connection with a value both ends share and no one else
// knows: a TLS connection's exporter.
type binder interface{ Binding() []byte }

// replicaBindingLabel is the TLS exporter label of a replication connection.
const replicaBindingLabel = "EXPORTER-hearth-ap-replica-master"

// Binding is the TLS exporter of the connection, nil if it has none.
func (c *trackedConn) Binding() []byte {
	cs := c.ConnectionState()
	b, err := cs.ExportKeyingMaterial(replicaBindingLabel, nil, 32)
	if err != nil {
		return nil
	}
	return b
}

// bindingOf is c's binding, nil if it has none.
func bindingOf(c net.Conn) []byte {
	if b, ok := c.(binder); ok {
		return b.Binding()
	}
	return nil
}

// The two ends sign different messages, so one end cannot hand back the
// other's proof as its own.
const (
	proofDialer = "hearth ap replica: the dialer holds the hub CA key\x00"
	proofServer = "hearth ap replica: the server holds the hub CA key\x00"
)

// proveMaster signs the binding for side; nil if this member holds no hub CA
// key or the connection has no binding.
func (r *Replicator) proveMaster(side string, binding []byte) []byte {
	if len(binding) == 0 {
		return nil
	}
	sig, ok := r.cfg.Master.Prove(append([]byte(side), binding...))
	if !ok {
		return nil
	}
	return sig
}

// verifyMaster checks a proof of side over the binding.
func (r *Replicator) verifyMaster(side string, binding, sig []byte) bool {
	return len(binding) > 0 && len(sig) > 0 && r.cfg.Master.Verify(append([]byte(side), binding...), sig)
}

// holdsKey reports whether this member holds the hub CA key: only then does
// it send global rows.
func (r *Replicator) holdsKey() bool { return r.cfg.Master.Holds() }

// hasGlobal reports whether ms holds a row of a global table.
func hasGlobal(ms []store.Mutation) bool {
	for _, m := range ms {
		if store.GlobalTable(m.Table) {
			return true
		}
	}
	return false
}

// withoutGlobal returns ms without its global rows.
func withoutGlobal(ms []store.Mutation) []store.Mutation {
	if !hasGlobal(ms) {
		return ms
	}
	out := make([]store.Mutation, 0, len(ms))
	for _, m := range ms {
		if !store.GlobalTable(m.Table) {
			out = append(out, m)
		}
	}
	return out
}
