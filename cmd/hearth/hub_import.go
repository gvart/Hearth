// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/gvart/hearth/internal/discovery"
	"github.com/gvart/hearth/internal/integrations/pihole"
)

// leaseSources returns the Pi-hole and lease files the hub imports hosts
// from; none if neither --pihole-url nor --dhcp-leases is set.
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
	for _, p := range opts.dhcpLeases {
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("--dhcp-leases: %w", err)
		}
		out = append(out, discovery.LeaseFile{Path: p})
	}
	return out, nil
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
