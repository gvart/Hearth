// SPDX-License-Identifier: AGPL-3.0-only

package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// platform is what the Linux readers keep between collections.
type platform struct {
	// buf is the read buffer, and proc where they find /proc.
	buf  []byte
	proc string
	// thermalGlob lists the thermal zone temperature files, and zones are
	// the files it matched, listed once.
	thermalGlob string
	zones       []string
}

// newPlatform finds /proc and /sys where HOST_PROC and HOST_SYS say, as
// gopsutil does for the facts: an agent in a container (the Kubernetes
// DaemonSet) reads the host's, mounted read-only.
func newPlatform() platform {
	return platform{
		proc:        envOr("HOST_PROC", "/proc"),
		thermalGlob: envOr("HOST_SYS", "/sys") + "/class/thermal/thermal_zone*/temp",
	}
}

// envOr returns the environment variable key, or def if it is unset or empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// cpuTimes reads the aggregate "cpu" line of /proc/stat: user nice system
// idle iowait irq softirq steal (guest time is already counted in user).
func (c *collector) cpuTimes(context.Context) (cpuTimes, error) {
	b, err := c.readFile(c.proc + "/stat")
	if err != nil {
		return cpuTimes{}, err
	}
	line, _, _ := bytes.Cut(b, []byte("\n"))
	f, line := nextField(line)
	if string(f) != "cpu" {
		return cpuTimes{}, errors.New("/proc/stat: no cpu line")
	}
	var t cpuTimes
	for i := range 8 {
		f, line = nextField(line)
		v, ok := parseUint(f)
		if !ok {
			if i >= 4 { // old kernels lack the later fields
				break
			}
			return cpuTimes{}, errors.New("/proc/stat: bad cpu line")
		}
		t.total += float64(v)
		if i == 3 || i == 4 { // idle, iowait
			t.idle += float64(v)
		}
	}
	return t, nil
}

// memoryPercent is the share of memory not available, from /proc/meminfo.
func (c *collector) memoryPercent(context.Context) (float64, error) {
	b, err := c.readFile(c.proc + "/meminfo")
	if err != nil {
		return 0, err
	}
	var (
		total, avail uint64
		hasAvail     bool
	)
	for len(b) > 0 {
		var line []byte
		line, b, _ = bytes.Cut(b, []byte("\n"))
		key, rest, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			continue
		}
		switch string(key) {
		case "MemTotal":
			f, _ := nextField(rest)
			total, _ = parseUint(f)
		case "MemAvailable":
			f, _ := nextField(rest)
			avail, hasAvail = parseUint(f)
		}
	}
	if total == 0 || !hasAvail || avail > total {
		return 0, errors.New("/proc/meminfo: no MemTotal or MemAvailable")
	}
	return 100 * (1 - float64(avail)/float64(total)), nil
}

// netBytes sums the received and sent bytes of the non-loopback interfaces
// in /proc/net/dev.
func (c *collector) netBytes(context.Context) (rx, tx uint64, err error) {
	b, err := c.readFile(c.proc + "/net/dev")
	if err != nil {
		return 0, 0, err
	}
	for len(b) > 0 {
		var line []byte
		line, b, _ = bytes.Cut(b, []byte("\n"))
		name, rest, ok := bytes.Cut(line, []byte(":"))
		if !ok || bytes.HasPrefix(bytes.TrimSpace(name), []byte("lo")) {
			continue // a header line, or loopback
		}
		// rest is 8 receive fields, bytes first, then 8 transmit fields.
		for i := range 9 {
			var f []byte
			f, rest = nextField(rest)
			v, _ := parseUint(f)
			switch i {
			case 0:
				rx += v
			case 8:
				tx += v
			}
		}
	}
	return rx, tx, nil
}

// temperature is the hottest thermal zone in °C, read from sysfs. The zones
// are listed once.
func (c *collector) temperature() (float64, bool) {
	if c.zones == nil {
		zones, _ := filepath.Glob(c.thermalGlob) // the pattern is valid
		c.zones = append(make([]string, 0, len(zones)), zones...)
	}
	var (
		hottest float64
		found   bool
	)
	for _, z := range c.zones {
		b, err := c.readFile(z)
		if err != nil {
			continue
		}
		f, _ := nextField(b)
		neg := len(f) > 0 && f[0] == '-'
		if neg {
			f = f[1:]
		}
		milli, ok := parseUint(f)
		if !ok {
			continue
		}
		t := float64(milli) / 1000
		if neg {
			t = -t
		}
		if !found || t > hottest {
			hottest, found = t, true
		}
	}
	return hottest, found
}

// readFile reads a small /proc or /sys file into c.buf, growing it if the
// file does not fit, and returns its contents; they are valid until the next
// read.
func (c *collector) readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if c.buf == nil {
		c.buf = make([]byte, 8<<10)
	}
	n := 0
	for {
		if n == len(c.buf) {
			c.buf = append(c.buf, make([]byte, len(c.buf))...)
		}
		m, err := f.Read(c.buf[n:])
		n += m
		if errors.Is(err, io.EOF) {
			return c.buf[:n], nil
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
	}
}

// nextField returns the first space-separated field of b and what follows.
func nextField(b []byte) (field, rest []byte) {
	b = bytes.TrimLeft(b, " \t")
	i := bytes.IndexAny(b, " \t\n")
	if i < 0 {
		return b, nil
	}
	return b[:i], b[i:]
}

// parseUint parses a decimal without allocating.
func parseUint(b []byte) (uint64, bool) {
	if len(b) == 0 {
		return 0, false
	}
	var v uint64
	for _, ch := range b {
		if ch < '0' || ch > '9' {
			return 0, false
		}
		v = v*10 + uint64(ch-'0')
	}
	return v, true
}
