// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.yaml.in/yaml/v3"
)

// RemoveUserFromFile removes the user named name from the clients file at
// path, keeping the rest of it, comments included, and its mode. The new file
// replaces the old one at once (a rename), and only if the hub would load it.
// It reports whether the file had the user.
func RemoveUserFromFile(path, name string) (bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Errorf("read MQTT clients file: %w", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("read MQTT clients file: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return false, fmt.Errorf("MQTT clients file %s: parse: %w", path, err)
	}
	if !dropUserNode(&doc, name) {
		return false, nil
	}
	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return false, fmt.Errorf("MQTT clients file %s: encode: %w", path, err)
	}
	if err := enc.Close(); err != nil {
		return false, fmt.Errorf("MQTT clients file %s: encode: %w", path, err)
	}
	if _, err := ParseClients(out.Bytes()); err != nil {
		return false, fmt.Errorf("MQTT clients file %s without user %s: %w", path, name, err)
	}
	if err := replaceFile(path, out.Bytes(), info.Mode().Perm()); err != nil {
		return false, fmt.Errorf("write MQTT clients file: %w", err)
	}
	return true, nil
}

// dropUserNode removes the users entry named name from doc, a parsed clients
// file, and reports whether there was one.
func dropUserNode(doc *yaml.Node, name string) bool {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return false
	}
	root := doc.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		users := root.Content[i+1]
		if root.Content[i].Value != "users" || users.Kind != yaml.SequenceNode {
			continue
		}
		for j, u := range users.Content {
			if userNodeName(u) == name {
				users.Content = append(users.Content[:j], users.Content[j+1:]...)
				return true
			}
		}
	}
	return false
}

func userNodeName(u *yaml.Node) string {
	if u.Kind != yaml.MappingNode {
		return ""
	}
	for i := 0; i+1 < len(u.Content); i += 2 {
		if u.Content[i].Value == "name" {
			return u.Content[i+1].Value
		}
	}
	return ""
}

// replaceFile writes b to a new file next to path, with mode perm, and
// renames it over path.
func replaceFile(path string, b []byte, perm fs.FileMode) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
		}
	}()
	if err := f.Chmod(perm); err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
