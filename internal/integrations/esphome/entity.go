// SPDX-License-Identifier: AGPL-3.0-only

package esphome

import (
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"

	esphomev1 "github.com/gvart/hearth/internal/proto/hearth/esphome/v1"
)

// listedEntity decodes a ListEntities*Response the hub shows; ok is false
// for the other kinds, and for an entity the device keeps disabled or whose
// text does not fit the hub's limits.
func listedEntity(p packet) (Entity, bool, error) {
	var (
		e        Entity
		disabled bool
	)
	unmarshal := func(m proto.Message) error {
		if err := proto.Unmarshal(p.data, m); err != nil {
			return fmt.Errorf("%w: entity: %w", ErrProtocol, err)
		}
		return nil
	}
	switch p.typ {
	case msgListSensor:
		var v esphomev1.ListEntitiesSensorResponse
		if err := unmarshal(&v); err != nil {
			return Entity{}, false, err
		}
		e = Entity{
			Key: v.GetKey(), ObjectID: v.GetObjectId(), Name: v.GetName(), Kind: KindSensor,
			Unit: v.GetUnitOfMeasurement(), DeviceClass: v.GetDeviceClass(), Decimals: int(v.GetAccuracyDecimals()),
		}
		disabled = v.GetDisabledByDefault()
	case msgListBinarySensor:
		var v esphomev1.ListEntitiesBinarySensorResponse
		if err := unmarshal(&v); err != nil {
			return Entity{}, false, err
		}
		e = Entity{
			Key: v.GetKey(), ObjectID: v.GetObjectId(), Name: v.GetName(), Kind: KindBinarySensor,
			DeviceClass: v.GetDeviceClass(),
		}
		disabled = v.GetDisabledByDefault()
	case msgListSwitch:
		var v esphomev1.ListEntitiesSwitchResponse
		if err := unmarshal(&v); err != nil {
			return Entity{}, false, err
		}
		e = Entity{
			Key: v.GetKey(), ObjectID: v.GetObjectId(), Name: v.GetName(), Kind: KindSwitch,
			DeviceClass: v.GetDeviceClass(),
		}
		disabled = v.GetDisabledByDefault()
	case msgListButton:
		var v esphomev1.ListEntitiesButtonResponse
		if err := unmarshal(&v); err != nil {
			return Entity{}, false, err
		}
		e = Entity{
			Key: v.GetKey(), ObjectID: v.GetObjectId(), Name: v.GetName(), Kind: KindButton,
			DeviceClass: v.GetDeviceClass(),
		}
		disabled = v.GetDisabledByDefault()
	case msgListTextSensor:
		var v esphomev1.ListEntitiesTextSensorResponse
		if err := unmarshal(&v); err != nil {
			return Entity{}, false, err
		}
		e = Entity{
			Key: v.GetKey(), ObjectID: v.GetObjectId(), Name: v.GetName(), Kind: KindTextSensor,
			DeviceClass: v.GetDeviceClass(),
		}
		disabled = v.GetDisabledByDefault()
	default:
		return Entity{}, false, nil
	}
	if disabled || e.ObjectID == "" || !fits(e.ObjectID, e.Name, e.Unit, e.DeviceClass) {
		return Entity{}, false, nil
	}
	if e.Decimals < 0 || e.Decimals > 10 {
		e.Decimals = 0
	}
	return e, true, nil
}

// stateUpdate is one entity's new state.
type stateUpdate struct {
	key   uint32
	state any
}

// decodeState decodes a *StateResponse; ok is false for any other message.
func decodeState(p packet) (stateUpdate, bool, error) {
	unmarshal := func(m proto.Message) error {
		if err := proto.Unmarshal(p.data, m); err != nil {
			return fmt.Errorf("%w: state: %w", ErrProtocol, err)
		}
		return nil
	}
	switch p.typ {
	case msgSensorState:
		var v esphomev1.SensorStateResponse
		if err := unmarshal(&v); err != nil {
			return stateUpdate{}, false, err
		}
		return stateUpdate{key: v.GetKey(), state: sensorValue(v.GetState(), v.GetMissingState())}, true, nil
	case msgBinarySensorState:
		var v esphomev1.BinarySensorStateResponse
		if err := unmarshal(&v); err != nil {
			return stateUpdate{}, false, err
		}
		return boolState(v.GetKey(), v.GetState(), v.GetMissingState()), true, nil
	case msgSwitchState:
		var v esphomev1.SwitchStateResponse
		if err := unmarshal(&v); err != nil {
			return stateUpdate{}, false, err
		}
		return boolState(v.GetKey(), v.GetState(), v.GetMissingState()), true, nil
	case msgTextSensorState:
		var v esphomev1.TextSensorStateResponse
		if err := unmarshal(&v); err != nil {
			return stateUpdate{}, false, err
		}
		if v.GetMissingState() {
			return stateUpdate{key: v.GetKey()}, true, nil
		}
		return stateUpdate{key: v.GetKey(), state: clip(v.GetState())}, true, nil
	}
	return stateUpdate{}, false, nil
}

func boolState(key uint32, on, missing bool) stateUpdate {
	if missing {
		return stateUpdate{key: key}
	}
	return stateUpdate{key: key, state: on}
}

// sensorValue is a sensor's state as JSON can carry it: ESPHome sends NaN
// for "unknown", and JSON has no NaN or infinity.
func sensorValue(v float32, missing bool) any {
	f := float64(v)
	if missing || math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	// The shortest decimal that reads back as the float32: 21.3, not
	// 21.299999237060547.
	out, err := strconv.ParseFloat(strconv.FormatFloat(f, 'g', -1, 32), 64)
	if err != nil {
		return nil
	}
	return out
}

// fits reports whether every text is valid UTF-8 within maxText bytes.
func fits(texts ...string) bool {
	for _, t := range texts {
		if len(t) > maxText || !utf8.ValidString(t) {
			return false
		}
	}
	return true
}

// clip cuts what a device says to maxText bytes of valid UTF-8.
func clip(s string) string {
	if !utf8.ValidString(s) {
		s = string([]rune(s))
	}
	if len(s) <= maxText {
		return s
	}
	s = s[:maxText]
	for !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}
