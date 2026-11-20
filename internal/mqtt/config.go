// SPDX-License-Identifier: AGPL-3.0-only

// Package mqtt is the hub's embedded MQTT broker (mochi-mqtt). It is off
// unless the hub is started with --mqtt-listen. Clients connect over TLS with
// the hub's server certificate and authenticate with an enrolled device's
// client certificate or with a username and password from the clients file.
// There is no anonymous access, and every topic a client publishes or
// subscribes to must be granted to it in that file: anything else is denied.
package mqtt

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
	"golang.org/x/crypto/bcrypt"
)

// Access is what a rule grants on its topics.
type Access string

// Accesses.
const (
	Read      Access = "read"
	Write     Access = "write"
	ReadWrite Access = "readwrite"
)

// Rule grants access to the topics an MQTT topic filter matches, such as
// sensors/# or home/+/temperature.
type Rule struct {
	Topic  string `yaml:"topic"`
	Access Access `yaml:"access"`
}

// User is a client that logs in with a username and password. Only the
// password's bcrypt hash is kept (see `hearth mqtt hash-password`).
type User struct {
	Name         string `yaml:"name"`
	PasswordHash string `yaml:"password_hash"`
	Allow        []Rule `yaml:"allow"`
}

// Device is an enrolled device that connects with its agent's client
// certificate, named by its device ID.
type Device struct {
	ID    string `yaml:"id"`
	Allow []Rule `yaml:"allow"`
}

// Clients is the clients file: who may connect, and to which topics.
//
//	users:
//	  - name: sensors
//	    password_hash: $2a$10$...
//	    allow:
//	      - topic: sensors/#
//	        access: readwrite
//	devices:
//	  - id: 3f2a9c...
//	    allow:
//	      - topic: hearth/3f2a9c/#
//	        access: write
type Clients struct {
	Users   []User   `yaml:"users"`
	Devices []Device `yaml:"devices"`
}

// LoadClients reads and checks the clients file at path.
func LoadClients(path string) (*Clients, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read MQTT clients file: %w", err)
	}
	c, err := ParseClients(b)
	if err != nil {
		return nil, fmt.Errorf("MQTT clients file %s: %w", path, err)
	}
	return c, nil
}

// Exposed reports whether the file at path is readable by group or others.
// It holds password hashes, which an attacker could brute-force offline.
func Exposed(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().Perm()&fs.FileMode(0o044) != 0
}

// ParseClients parses and checks a clients file.
func ParseClients(b []byte) (*Clients, error) {
	var c Clients
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	// An empty file has no clients.
	if err := dec.Decode(&c); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse: %w", err)
	}
	users := map[string]bool{}
	for i, u := range c.Users {
		switch {
		case u.Name == "":
			return nil, fmt.Errorf("users[%d]: name is required", i)
		case strings.ContainsAny(u.Name, ":/"):
			// A device identity is "device:<id>"; no user may look like one.
			return nil, fmt.Errorf("user %q: name may not contain ':' or '/'", u.Name)
		case users[u.Name]:
			return nil, fmt.Errorf("user %q is listed twice", u.Name)
		}
		users[u.Name] = true
		if _, err := bcrypt.Cost([]byte(u.PasswordHash)); err != nil {
			return nil, fmt.Errorf("user %q: password_hash is not a bcrypt hash (make one with `hearth mqtt hash-password`)", u.Name)
		}
		if err := checkRules(u.Allow); err != nil {
			return nil, fmt.Errorf("user %q: %w", u.Name, err)
		}
	}
	devices := map[string]bool{}
	for i, d := range c.Devices {
		switch {
		case d.ID == "":
			return nil, fmt.Errorf("devices[%d]: id is required", i)
		case devices[d.ID]:
			return nil, fmt.Errorf("device %q is listed twice", d.ID)
		}
		devices[d.ID] = true
		if err := checkRules(d.Allow); err != nil {
			return nil, fmt.Errorf("device %q: %w", d.ID, err)
		}
	}
	return &c, nil
}

func checkRules(rules []Rule) error {
	for _, r := range rules {
		if !validFilter(r.Topic) {
			return fmt.Errorf("allow: %q is not a valid MQTT topic filter", r.Topic)
		}
		switch r.Access {
		case Read, Write, ReadWrite:
		default:
			return fmt.Errorf("allow %q: access must be read, write or readwrite, not %q", r.Topic, r.Access)
		}
	}
	return nil
}

// HashPassword returns the bcrypt hash of password for a user's
// password_hash.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", errors.New("password is empty")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(h), nil
}
