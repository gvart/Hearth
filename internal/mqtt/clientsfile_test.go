// SPDX-License-Identifier: AGPL-3.0-only

package mqtt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestRemoveUserFromFile(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte(testPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	file := strings.ReplaceAll(`# Hearth's MQTT clients.
users:
  - name: kitchen # the kitchen sensor
    password_hash: "HASH"
    allow:
      - topic: hearth/v1/kitchen/#
        access: readwrite
  # Scripts.
  - name: sensors
    password_hash: "HASH"
    allow:
      - topic: sensors/#
        access: readwrite
bridge:
  allow:
    - topic: sensors/#
      access: readwrite
`, "HASH", string(hash))
	tests := []struct {
		name, file, user string
		removed          bool
		wantErr          string
		wantUsers        string
	}{
		{name: "a user", file: file, user: "kitchen", removed: true, wantUsers: "sensors"},
		{name: "no such user", file: file, user: "garage", wantUsers: "kitchen,sensors"},
		{name: "an empty file", file: "", user: "kitchen"},
		{name: "not YAML", file: "users: [", user: "kitchen", wantErr: "parse"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "mqtt.yaml")
			if err := os.WriteFile(path, []byte(tt.file), 0o600); err != nil {
				t.Fatal(err)
			}
			removed, err := RemoveUserFromFile(path, tt.user)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil || removed != tt.removed {
				t.Fatalf("RemoveUserFromFile = %v, %v, want %v", removed, err, tt.removed)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !tt.removed && string(b) != tt.file {
				t.Fatalf("file changed without a user removed:\n%s", b)
			}
			c, err := ParseClients(b)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, u := range c.Users {
				names = append(names, u.Name)
			}
			if strings.Join(names, ",") != tt.wantUsers {
				t.Fatalf("users = %v, want %s", names, tt.wantUsers)
			}
			if !tt.removed {
				return
			}
			if c.Bridge == nil || len(c.Bridge.Allow) != 1 {
				t.Errorf("bridge section lost: %+v", c.Bridge)
			}
			if !strings.Contains(string(b), "# Hearth's MQTT clients.") || !strings.Contains(string(b), "# Scripts.") {
				t.Errorf("comments lost:\n%s", b)
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o600 {
				t.Errorf("mode = %v, %v, want 0600", info.Mode().Perm(), err)
			}
			if left, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".mqtt.yaml.*")); len(left) != 0 {
				t.Errorf("temporary files left: %v", left)
			}
		})
	}
}
