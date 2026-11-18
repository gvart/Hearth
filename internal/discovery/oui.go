// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
)

// ouiTable is the IEEE MA-L registry in ouigen's compact format.
//
//go:embed oui.bin.gz
var ouiTable []byte

type vendorTable struct {
	ouis  []uint32 // ascending
	index []uint16 // name of each OUI
	names []string
}

var loadVendors = sync.OnceValues(func() (*vendorTable, error) { return parseVendors(ouiTable) })

// Vendor returns the short name of the company the IEEE assigned mac's OUI
// to, or "" when it is unknown, or when mac is locally administered (a
// randomized "private" address, as phones use), which names no vendor.
func Vendor(mac net.HardwareAddr) string {
	if len(mac) < 3 || mac[0]&0x02 != 0 {
		return ""
	}
	t, err := loadVendors()
	if err != nil {
		return ""
	}
	oui := uint32(mac[0])<<16 | uint32(mac[1])<<8 | uint32(mac[2])
	i, ok := slices.BinarySearch(t.ouis, oui)
	if !ok {
		return ""
	}
	return t.names[t.index[i]]
}

func parseVendors(gz []byte) (*vendorTable, error) {
	zr, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, fmt.Errorf("oui table: %w", err)
	}
	r := bufio.NewReader(zr)
	n, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, fmt.Errorf("oui table: %w", err)
	}
	m, err := binary.ReadUvarint(r)
	if err != nil {
		return nil, fmt.Errorf("oui table: %w", err)
	}
	if n > 1<<24 || m > 1<<16 {
		return nil, errors.New("oui table: corrupt header")
	}
	t := &vendorTable{ouis: make([]uint32, n), index: make([]uint16, n), names: make([]string, m)}
	for i := range t.names {
		s, err := r.ReadString('\n')
		if err != nil {
			return nil, fmt.Errorf("oui table: %w", err)
		}
		t.names[i] = s[:len(s)-1]
	}
	var oui uint64
	for i := range t.ouis {
		d, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, fmt.Errorf("oui table: %w", err)
		}
		oui += d
		t.ouis[i] = uint32(oui) //nolint:gosec // OUIs are 24-bit
	}
	for i := range t.index {
		x, err := binary.ReadUvarint(r)
		if err != nil {
			return nil, fmt.Errorf("oui table: %w", err)
		}
		if x >= m {
			return nil, errors.New("oui table: corrupt index")
		}
		t.index[i] = uint16(x) //nolint:gosec // x < m <= 1<<16
	}
	return t, nil
}
