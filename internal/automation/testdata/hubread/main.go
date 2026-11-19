// SPDX-License-Identifier: AGPL-3.0-only

// Command hubread prints what the hub's YAML parser reads from stdin, as JSON.
// The web editor's round-trip test compares it before and after an edit: a
// JavaScript reader cannot see the difference between 010 and 10.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"
)

type node struct {
	Kind    yaml.Kind `json:"kind"`
	Tag     string    `json:"tag"`
	Value   string    `json:"value"`
	Content []node    `json:"content,omitempty"`
}

func convert(n *yaml.Node) node {
	out := node{Kind: n.Kind, Tag: n.ShortTag(), Value: n.Value}
	for _, c := range n.Content {
		out.Content = append(out.Content, convert(c))
	}
	return out
}

func run() error {
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return fmt.Errorf("read stdin: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(convert(&doc)); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
