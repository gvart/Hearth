// SPDX-License-Identifier: AGPL-3.0-only

//go:build wasip1

// Command wasmguest is a WASM plugin for the tests, built with
// GOOS=wasip1 GOARCH=wasm: each of its commands misbehaves in its own way.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"
	"unsafe"

	"github.com/gvart/hearth/pkg/sdk"
)

//go:wasmimport hearth call
func hostCall(name unsafe.Pointer, nameLen uint32, req unsafe.Pointer, reqLen uint32) int32

//go:wasmimport hearth reply
func hostReply(buf unsafe.Pointer, capacity uint32) int32

// rawCall calls host function name as the SDK does, and returns its reply.
func rawCall(name, req string) string {
	n := hostCall(unsafe.Pointer(unsafe.StringData(name)), uint32(len(name)),
		unsafe.Pointer(unsafe.StringData(req)), uint32(len(req)))
	if n < 0 {
		return "refused"
	}
	buf := make([]byte, n)
	hostReply(unsafe.Pointer(unsafe.SliceData(buf)), uint32(n))
	return string(buf)
}

var keep [][]byte

func main() {
	var p *sdk.Plugin
	p = &sdk.Plugin{
		Version: "1",
		Discover: func(context.Context) ([]sdk.Device, error) {
			return []sdk.Device{{ID: "d", Name: "D", Entities: []sdk.Entity{{ID: "e", Name: "E", State: 0}}}}, nil
		},
		Command: func(ctx context.Context, c sdk.Command) (string, error) {
			var args struct {
				URL  string `json:"url"`
				Name string `json:"name"`
				MiB  int    `json:"mib"`
			}
			_ = json.Unmarshal(c.Args, &args)
			switch c.Name {
			case "echo":
				_ = p.SetState("d", "e", 42)
				return fmt.Sprintf("%s %s %v env=%q", c.Device, c.Args, os.Args[1:], os.Environ()), nil
			case "files":
				_, err := os.ReadDir("/")
				return fmt.Sprint(err), nil
			case "http":
				r, err := sdk.HTTP(ctx, sdk.HTTPRequest{URL: args.URL})
				if err != nil {
					return "", err
				}
				return fmt.Sprintf("%d %s", r.Status, r.Body), nil
			case "raw":
				return rawCall(args.Name, "{}"), nil
			case "flood":
				for range 20 {
					rawCall("nothing", "{}")
				}
				return "flooded", nil
			case "spin":
				for {
				}
			case "alloc":
				// args.mib MiB, or until it dies.
				for i := 0; args.MiB == 0 || i < args.MiB; i++ {
					keep = append(keep, make([]byte, 1<<20))
				}
				keep = nil
				return "allocated", nil
			case "sleep":
				time.Sleep(time.Hour)
				return "slept", nil
			case "tick":
				go func() {
					for i := 1; ; i++ {
						time.Sleep(20 * time.Millisecond)
						_ = p.SetState("d", "e", i)
					}
				}()
				return "ticking", nil
			}
			return "", fmt.Errorf("no command %s", c.Name)
		},
	}
	if err := p.Run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
