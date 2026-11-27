// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import "testing"

// The kernel's IPv6 neighbour table is readable without privileges, and
// every entry read back is a usable one.
func TestReadNeighbors6(t *testing.T) {
	got, err := ReadNeighbors6()
	if err != nil {
		t.Skipf("no IPv6 neighbour table here: %v", err)
	}
	for _, n := range got {
		if !n.IP.Is6() || n.IP.IsMulticast() || !usableMAC(n.MAC) {
			t.Errorf("neighbour %v %v is not a resolved unicast entry", n.IP, n.MAC)
		}
	}
	t.Logf("%d IPv6 neighbours", len(got))
}
