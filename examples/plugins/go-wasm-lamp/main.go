// SPDX-License-Identifier: AGPL-3.0-only

// Command go-wasm-lamp is an example Hearth plugin written with the plugin
// SDK (pkg/sdk): a lamp that can be turned on and off. Given a URL as its
// argument, it also calls it on each change, with ?turn=on or ?turn=off
// (as a Shelly relay takes), through the SDK's HTTP: in a WASM plugin, the
// hub's http host function, which the manifest must grant.
//
// The same source builds as a WASM plugin, which the hub runs in a sandbox:
//
//	GOOS=wasip1 GOARCH=wasm go build -o lamp.wasm . && hearth hub --plugin ./plugin.yaml
//
// and as an exec plugin: go build -o lamp . (with runtime and command set
// to match in the manifest).
package main

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/gvart/hearth/pkg/sdk"
)

func main() {
	l := &lamp{}
	if len(os.Args) > 1 {
		l.url = os.Args[1]
	}
	l.p = &sdk.Plugin{Name: "go-wasm-lamp", Version: "0.1.0", Discover: l.discover, Command: l.command}
	if err := l.p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

type lamp struct {
	p   *sdk.Plugin
	url string

	mu sync.Mutex
	on bool
}

func (l *lamp) discover() ([]sdk.Device, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return []sdk.Device{{
		ID: "lamp", Name: "Lamp", Kind: "light",
		Entities: []sdk.Entity{{ID: "on", Name: "On", Kind: "switch", State: l.on}},
	}}, nil
}

func (l *lamp) command(c sdk.Command) (string, error) {
	var on bool
	switch c.Name {
	case "turn_on":
		on = true
	case "turn_off":
	default:
		return "", fmt.Errorf("unknown command %q", c.Name)
	}
	if l.url != "" {
		turn := map[bool]string{true: "on", false: "off"}[on]
		resp, err := sdk.HTTP(sdk.HTTPRequest{URL: l.url + "?turn=" + turn})
		if err != nil {
			return "", err
		}
		if resp.Status != 200 {
			return "", errors.New("the lamp answered " + fmt.Sprint(resp.Status))
		}
	}
	l.mu.Lock()
	l.on = on
	l.mu.Unlock()
	if err := l.p.SetState("lamp", "on", on); err != nil {
		return "", err
	}
	if on {
		return "lamp is on", nil
	}
	return "lamp is off", nil
}
