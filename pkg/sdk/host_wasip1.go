// SPDX-License-Identifier: Apache-2.0

//go:build wasip1

package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"syscall"
	"unsafe"
)

// stdin is the hub's end of the plugin's stdin. Go's runtime runs one
// goroutine at a time in WASM, and a blocking read would stop every other
// one, timers too: nonblocking, the runtime polls stdin with its timers.
func stdin() io.Reader {
	if err := syscall.SetNonblock(0, true); err != nil {
		return os.Stdin
	}
	return os.NewFile(0, "stdin")
}

// The "hearth" host module's ABI (docs/plugins.md): call runs the host
// function named at name with the JSON request at req, and returns the
// length of its JSON reply, or -1; reply copies that reply into buf if it
// fits, and returns its length, or -1.
//
//go:wasmimport hearth call
func hostCall(name unsafe.Pointer, nameLen uint32, req unsafe.Pointer, reqLen uint32) int32

//go:wasmimport hearth reply
func hostReply(buf unsafe.Pointer, capacity uint32) int32

// call calls host function name with req as JSON and decodes its result
// into result.
func call(name string, req, result any) error {
	b, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("sdk: %s: %w", name, err)
	}
	nb := []byte(name)
	n := hostCall(unsafe.Pointer(unsafe.SliceData(nb)), uint32(len(nb)), //nolint:gosec // a short name
		unsafe.Pointer(unsafe.SliceData(b)), uint32(len(b))) //nolint:gosec // bounded by the hub
	if n < 0 {
		return ErrHostCall
	}
	buf := make([]byte, n)
	if n > 0 && hostReply(unsafe.Pointer(unsafe.SliceData(buf)), uint32(n)) != n {
		return ErrHostCall
	}
	var r struct {
		OK     bool            `json:"ok"`
		Result json.RawMessage `json:"result"`
		Error  string          `json:"error"`
	}
	if err := json.Unmarshal(buf, &r); err != nil {
		return fmt.Errorf("sdk: %s: %w", name, err)
	}
	if !r.OK {
		return fmt.Errorf("sdk: %s: %s", name, r.Error)
	}
	if result == nil || len(r.Result) == 0 {
		return nil
	}
	return json.Unmarshal(r.Result, result)
}

func doHTTP(ctx context.Context, req HTTPRequest) (HTTPResponse, error) {
	if err := ctx.Err(); err != nil {
		return HTTPResponse{}, fmt.Errorf("sdk: http: %w", err)
	}
	var r HTTPResponse
	err := call("http", req, &r)
	return r, err
}
