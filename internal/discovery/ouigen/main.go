// SPDX-License-Identifier: AGPL-3.0-only

// Command ouigen turns the IEEE MA-L registry (oui.csv) into the compact
// vendor table embedded in internal/discovery (oui.bin.gz). Names are
// shortened (no company suffixes, no text after a comma) and stored once, to
// keep the binary small. The format, gzip-compressed, is:
//
//	uvarint n (entries), uvarint m (names)
//	m names, each followed by '\n', sorted
//	n uvarints: each OUI minus the previous one, OUIs ascending
//	n uvarints: each OUI's index into the names
//
// To refresh the table:
//
//	curl -A curl/8 -o /tmp/oui.csv https://standards-oui.ieee.org/oui/oui.csv
//	go run ./internal/discovery/ouigen /tmp/oui.csv internal/discovery/oui.bin.gz
package main

import (
	"compress/gzip"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// maxName caps a vendor name; the UI shows it in a table column.
const maxName = 24

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: ouigen oui.csv out.bin.gz")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, "ouigen:", err)
		os.Exit(1)
	}
}

func run(in, out string) error {
	f, err := os.Open(in) //nolint:gosec // a path the developer passes
	if err != nil {
		return err
	}
	defer f.Close()
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	vendors := map[uint32]string{}
	for {
		rec, err := r.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if len(rec) < 3 || rec[0] != "MA-L" || len(rec[1]) != 6 {
			continue
		}
		oui, err := strconv.ParseUint(rec[1], 16, 24)
		if err != nil {
			continue
		}
		name := shorten(rec[2])
		if name == "" || strings.EqualFold(name, "Private") {
			continue
		}
		if _, dup := vendors[uint32(oui)]; !dup {
			vendors[uint32(oui)] = name
		}
	}
	ouis := slices.Sorted(maps.Keys(vendors))
	names := slices.Compact(slices.Sorted(maps.Values(vendors)))
	index := make(map[string]uint64, len(names))
	for i, n := range names {
		index[n] = uint64(i)
	}

	var b []byte
	b = binary.AppendUvarint(b, uint64(len(ouis)))
	b = binary.AppendUvarint(b, uint64(len(names)))
	for _, n := range names {
		b = append(b, n...)
		b = append(b, '\n')
	}
	var prev uint32
	for _, o := range ouis {
		b = binary.AppendUvarint(b, uint64(o-prev))
		prev = o
	}
	for _, o := range ouis {
		b = binary.AppendUvarint(b, index[vendors[o]])
	}

	o, err := os.Create(out) //nolint:gosec // a path the developer passes
	if err != nil {
		return err
	}
	zw, err := gzip.NewWriterLevel(o, gzip.BestCompression)
	if err != nil {
		return err
	}
	if _, err := zw.Write(b); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return o.Close()
}

var (
	parens = regexp.MustCompile(`\([^)]*\)`)
	spaces = regexp.MustCompile(`\s+`)
	// suffixes are dropped from the end of a name, repeatedly.
	suffixes = map[string]bool{
		"inc": true, "incorporated": true, "ltd": true, "limited": true, "llc": true, "co": true,
		"corp": true, "corporation": true, "company": true, "gmbh": true, "ag": true, "sa": true,
		"s.a": true, "bv": true, "b.v": true, "nv": true, "n.v": true, "oy": true, "ab": true, "as": true,
		"a/s": true, "spa": true, "s.p.a": true, "srl": true, "s.r.l": true, "pty": true, "plc": true,
		"kg": true, "sas": true, "sarl": true, "kk": true, "k.k": true, "pte": true, "sdn": true,
		"bhd": true, "jsc": true, "ltda": true, "trading": true, "foundation": true, "&": true,
		"technology": true, "technologies": true, "tech": true, "electronics": true, "electronic": true,
		"communications": true, "communication": true, "international": true, "group": true,
		"holdings": true, "industrial": true, "systems": true, "networks": true, "co.,ltd": true,
		"mfg": true, "manufacturing": true, "enterprises": true, "products": true, "solutions": true,
	}
)

// shorten turns "Raspberry Pi (Trading) Ltd" into "Raspberry Pi" and
// "Shenzhen Foo Technology Co., Ltd." into "Shenzhen Foo".
func shorten(name string) string {
	name = parens.ReplaceAllString(name, " ")
	if i := strings.IndexByte(name, ','); i > 0 {
		name = name[:i]
	}
	words := strings.Fields(spaces.ReplaceAllString(name, " "))
	for len(words) > 1 && suffixes[strings.ToLower(strings.Trim(words[len(words)-1], ".,"))] {
		words = words[:len(words)-1]
	}
	name = strings.Join(words, " ")
	if r := []rune(name); len(r) > maxName {
		name = strings.TrimSpace(string(r[:maxName]))
	}
	return name
}
