// SPDX-License-Identifier: AGPL-3.0-only

package cluster

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
)

// HostFlagsSource reports the digest of this hub's host flags that grant
// what the replicated policy does not: the --allow-dangerous-automation ids,
// in any order. The policy, notify, automation and runbook documents are in
// the store, the same on every hub, so they are not compared.
func HostFlagsSource(dangerousAutomations []string) ConfigSource {
	h := sha256.New()
	_, _ = h.Write([]byte("allow-dangerous-automation\x00"))
	for _, s := range slices.Compact(slices.Sorted(slices.Values(dangerousAutomations))) {
		_, _ = h.Write(append([]byte(s), 0))
	}
	digest := hex.EncodeToString(h.Sum(nil))
	return func() map[string]string { return map[string]string{ConfigHostFlags: digest} }
}
