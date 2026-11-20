// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"

	"github.com/gvart/hearth/internal/hlc"
)

// Wire encoding of row values between cluster members. A row value is
// int64, float64, string, []byte or nil; plain JSON would turn an int64
// into a float64 and a []byte into a string, and the replicas of a row
// would differ in type. Each value is encoded with a one-letter tag:
// {"i":"42"}, {"f":1.5}, {"s":"text"}, {"b":"<base64>"}, or null.

// wireValue is one row value on the wire.
type wireValue struct{ v any }

// MarshalJSON implements json.Marshaler.
func (w wireValue) MarshalJSON() ([]byte, error) {
	switch v := w.v.(type) {
	case nil:
		return []byte("null"), nil
	case int64:
		return json.Marshal(map[string]string{"i": strconv.FormatInt(v, 10)})
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return nil, fmt.Errorf("wire value: %v is not a finite number", v)
		}
		return json.Marshal(map[string]float64{"f": v})
	case string:
		return json.Marshal(map[string]string{"s": v})
	case []byte:
		return json.Marshal(map[string]string{"b": base64.StdEncoding.EncodeToString(v)})
	default:
		return nil, fmt.Errorf("wire value: unsupported type %T", v)
	}
}

// UnmarshalJSON implements json.Unmarshaler.
func (w *wireValue) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		w.v = nil
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return fmt.Errorf("wire value: %w", err)
	}
	if len(m) != 1 {
		return errors.New("wire value: want exactly one tag")
	}
	for tag, raw := range m {
		switch tag {
		case "i":
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf("wire value: %w", err)
			}
			n, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return fmt.Errorf("wire value: %w", err)
			}
			w.v = n
		case "f":
			var f float64
			if err := json.Unmarshal(raw, &f); err != nil {
				return fmt.Errorf("wire value: %w", err)
			}
			w.v = f
		case "s":
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf("wire value: %w", err)
			}
			w.v = s
		case "b":
			var s string
			if err := json.Unmarshal(raw, &s); err != nil {
				return fmt.Errorf("wire value: %w", err)
			}
			bs, err := base64.StdEncoding.DecodeString(s)
			if err != nil {
				return fmt.Errorf("wire value: %w", err)
			}
			if bs == nil {
				bs = []byte{}
			}
			w.v = bs
		default:
			return fmt.Errorf("wire value: unknown tag %q", tag)
		}
	}
	return nil
}

// WireArg converts a query argument to a row value: ints and bools as
// SQLite stores them.
func WireArg(a any) (any, error) {
	switch a := a.(type) {
	case nil, int64, float64, string, []byte:
		return a, nil
	case int:
		return int64(a), nil
	case int32:
		return int64(a), nil
	case uint32:
		return int64(a), nil
	case bool:
		if a {
			return int64(1), nil
		}
		return int64(0), nil
	default:
		return nil, fmt.Errorf("query argument of unsupported type %T", a)
	}
}

// Values is a list of row values that keeps their types on the wire.
type Values []any

// MarshalJSON implements json.Marshaler.
func (vs Values) MarshalJSON() ([]byte, error) {
	out := make([]wireValue, len(vs))
	for i, v := range vs {
		out[i] = wireValue{v}
	}
	return json.Marshal(out)
}

// UnmarshalJSON implements json.Unmarshaler.
func (vs *Values) UnmarshalJSON(b []byte) error {
	var in []wireValue
	if err := json.Unmarshal(b, &in); err != nil {
		return err
	}
	out := make(Values, len(in))
	for i, w := range in {
		out[i] = w.v
	}
	*vs = out
	return nil
}

// wireMutation is a Mutation on the wire.
type wireMutation struct {
	Table   string               `json:"table"`
	Row     map[string]wireValue `json:"row"`
	HLC     hlc.Timestamp        `json:"hlc"`
	Origin  string               `json:"origin"`
	Deleted bool                 `json:"deleted,omitempty"`
	Seq     int64                `json:"seq,omitempty"`
}

// MarshalJSON implements json.Marshaler, keeping the row's value types.
func (m Mutation) MarshalJSON() ([]byte, error) {
	w := wireMutation{
		Table: m.Table, HLC: m.HLC, Origin: m.Origin, Deleted: m.Deleted, Seq: m.Seq,
		Row: make(map[string]wireValue, len(m.Row)),
	}
	for k, v := range m.Row {
		w.Row[k] = wireValue{v}
	}
	return json.Marshal(w)
}

// UnmarshalJSON implements json.Unmarshaler.
func (m *Mutation) UnmarshalJSON(b []byte) error {
	var w wireMutation
	if err := json.Unmarshal(b, &w); err != nil {
		return err
	}
	*m = Mutation{
		Table: w.Table, HLC: w.HLC, Origin: w.Origin, Deleted: w.Deleted, Seq: w.Seq,
		Row: make(map[string]any, len(w.Row)),
	}
	for k, v := range w.Row {
		m.Row[k] = v.v
	}
	return nil
}
