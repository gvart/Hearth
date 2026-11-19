// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/hub"
	"github.com/gvart/hearth/internal/integrations/beszel"
	"github.com/gvart/hearth/internal/integrations/netalertx"
	"github.com/gvart/hearth/internal/integrations/pihole"
)

// leaseSources returns the Pi-hole, NetAlertX and lease files the hub
// imports hosts from; none if none of --pihole-url, --netalertx-url and
// --dhcp-leases is set.
func leaseSources(opts hubOptions) ([]discovery.Source, error) {
	var out []discovery.Source
	if opts.piholeURL != "" {
		password := opts.piholePassword
		if opts.piholePasswordFile != "" {
			if password != "" {
				return nil, errors.New("set HEARTH_PIHOLE_PASSWORD or --pihole-password-file, not both")
			}
			var err error
			if password, err = readSecretFile(opts.piholePasswordFile); err != nil {
				return nil, fmt.Errorf("--pihole-password-file: %w", err)
			}
		}
		c, err := pihole.New(opts.piholeURL, password, nil)
		if err != nil {
			return nil, fmt.Errorf("--pihole-url: %w", err)
		}
		out = append(out, c)
	} else if opts.piholePasswordFile != "" {
		return nil, errors.New("--pihole-password-file needs --pihole-url")
	}
	if opts.netalertxURL != "" {
		token, err := secretFrom(opts.netalertxToken, opts.netalertxTokenFile,
			"HEARTH_NETALERTX_TOKEN", "--netalertx-token-file")
		if err != nil {
			return nil, err
		}
		c, err := netalertx.New(opts.netalertxURL, token, nil)
		if err != nil {
			return nil, fmt.Errorf("--netalertx-url: %w", err)
		}
		out = append(out, c)
	} else if opts.netalertxTokenFile != "" {
		return nil, errors.New("--netalertx-token-file needs --netalertx-url")
	}
	for _, p := range opts.dhcpLeases {
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("--dhcp-leases: %w", err)
		}
		out = append(out, discovery.LeaseFile{Path: p})
	}
	return out, nil
}

// beszelSource returns the client for --beszel-url; nil if it is not set.
func beszelSource(opts hubOptions) (*beszel.Client, error) {
	if opts.beszelURL == "" {
		if opts.beszelEmail != "" || opts.beszelPasswordFile != "" {
			return nil, errors.New("--beszel-email and --beszel-password-file need --beszel-url")
		}
		return nil, nil
	}
	if opts.beszelEmail == "" {
		return nil, errors.New("--beszel-url needs --beszel-email")
	}
	password, err := secretFrom(opts.beszelPassword, opts.beszelPasswordFile,
		"HEARTH_BESZEL_PASSWORD", "--beszel-password-file")
	if err != nil {
		return nil, err
	}
	c, err := beszel.New(opts.beszelURL, opts.beszelEmail, password, nil)
	if err != nil {
		return nil, fmt.Errorf("--beszel-url: %w", err)
	}
	return c, nil
}

// beszelSnapshotter returns r as a hub.BeszelSnapshotter, nil if r is: a
// nil *beszel.Reader in the interface would not be nil.
func beszelSnapshotter(r *beszel.Reader) hub.BeszelSnapshotter {
	if r == nil {
		return nil
	}
	return r
}

// secretFrom returns the secret given in the environment variable env
// (value) or in the file named by flag (path), and fails if both or neither
// is set.
func secretFrom(value, path, env, flag string) (string, error) {
	switch {
	case value != "" && path != "":
		return "", fmt.Errorf("set %s or %s, not both", env, flag)
	case path != "":
		s, err := readSecretFile(path)
		if err != nil {
			return "", fmt.Errorf("%s: %w", flag, err)
		}
		return s, nil
	case value == "":
		return "", fmt.Errorf("set %s or %s", env, flag)
	}
	return value, nil
}

// readSecretFile reads a one-line secret from a file only its owner can
// read (on Windows, any file).
func readSecretFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s is readable by others (mode %04o); chmod 600 it", path, info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return s, nil
}
