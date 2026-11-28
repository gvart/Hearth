// SPDX-License-Identifier: Apache-2.0

// Package sdk is the public SDK for building Hearth agents and plugins.
//
// Unlike the rest of Hearth, this package is licensed under Apache-2.0 so it can
// be embedded in third-party code.
//
// A plugin speaks Hearth's plugin protocol (version 1, docs/plugins.md) on
// its stdin and stdout. Fill in a Plugin and call Run:
//
//	p := &sdk.Plugin{
//		Name:    "lamp",
//		Version: "0.1.0",
//		Discover: func() ([]sdk.Device, error) { ... },
//		Command:  func(c sdk.Command) (string, error) { ... },
//	}
//	if err := p.Run(); err != nil { ... }
//
// The same source builds as an exec plugin (go build) and as a WASM plugin
// (GOOS=wasip1 GOARCH=wasm go build -o plugin.wasm), which the hub runs in a
// sandbox. A WASM plugin reaches the outside only through the host
// functions its manifest grants, such as HTTP.
package sdk
