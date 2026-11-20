// SPDX-License-Identifier: AGPL-3.0-only

package talos

import (
	"errors"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

// Field numbers of the Talos API messages (api/machine/machine.proto,
// api/common/common.proto) the client decodes. Every response is
// `repeated <Reply> messages = 1`, and every reply starts with
// `common.Metadata metadata = 1`.
const (
	fMessages = 1
	fMetadata = 1

	// common.Metadata
	fMetaHostname = 1
	fMetaError    = 2

	// machine.Version
	fVersionInfo  = 2
	fPlatformInfo = 3
	// machine.VersionInfo
	fVersionTag  = 1
	fVersionArch = 6
	// machine.PlatformInfo
	fPlatformName = 1

	// machine.Hostname
	fHostname = 2

	// machine.ServiceList
	fServices = 2
	// machine.ServiceInfo
	fServiceID     = 1
	fServiceState  = 2
	fServiceHealth = 4
	// machine.ServiceHealth
	fHealthUnknown = 1
	fHealthHealthy = 2
	fHealthMessage = 3

	// machine.Memory
	fMemInfo = 2
	// machine.MemInfo
	fMemTotal     = 1
	fMemAvailable = 3

	// machine.LoadAvg
	fLoad1  = 2
	fLoad5  = 3
	fLoad15 = 4

	// machine.SystemStat
	fBootTime = 2
)

// maxField caps a string the API reports.
const maxField = 255

var errMalformed = errors.New("malformed Talos API response")

// field is one decoded field: bytes for a length-delimited field, num for a
// varint or fixed64 one.
type field struct {
	num   protowire.Number
	typ   protowire.Type
	bytes []byte
	num64 uint64
}

// walk calls fn for each field of the message b, skipping groups and
// fixed32 fields, which no message the client reads uses.
func walk(b []byte, fn func(field) error) error {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return errMalformed
		}
		b = b[n:]
		f := field{num: num, typ: typ}
		switch typ {
		case protowire.VarintType:
			f.num64, n = protowire.ConsumeVarint(b)
		case protowire.Fixed64Type:
			f.num64, n = protowire.ConsumeFixed64(b)
		case protowire.BytesType:
			f.bytes, n = protowire.ConsumeBytes(b)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
		}
		if n < 0 {
			return errMalformed
		}
		b = b[n:]
		if typ == protowire.VarintType || typ == protowire.Fixed64Type || typ == protowire.BytesType {
			if err := fn(f); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f field) str() string {
	if f.typ != protowire.BytesType {
		return ""
	}
	s := f.bytes
	if len(s) > maxField {
		s = s[:maxField]
	}
	return string(s)
}

func (f field) double() float64 {
	if f.typ != protowire.Fixed64Type {
		return 0
	}
	return math.Float64frombits(f.num64)
}

func (f field) uint() uint64 {
	if f.typ != protowire.VarintType {
		return 0
	}
	return f.num64
}

// meta is a reply's common.Metadata.
type meta struct{ hostname, err string }

// replies decodes a response into its replies: the metadata of each and
// its fields after the metadata, handed to fn.
func replies(b []byte, fn func(m meta, f field) error) ([]meta, error) {
	var out []meta
	err := walk(b, func(top field) error {
		if top.num != fMessages || top.typ != protowire.BytesType {
			return nil
		}
		var m meta
		var rest []field
		if err := walk(top.bytes, func(f field) error {
			if f.num == fMetadata && f.typ == protowire.BytesType {
				return walk(f.bytes, func(mf field) error {
					switch mf.num {
					case fMetaHostname:
						m.hostname = mf.str()
					case fMetaError:
						m.err = mf.str()
					}
					return nil
				})
			}
			rest = append(rest, f)
			return nil
		}); err != nil {
			return err
		}
		out = append(out, m)
		for _, f := range rest {
			if err := fn(m, f); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}
