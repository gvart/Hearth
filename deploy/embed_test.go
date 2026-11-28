// SPDX-License-Identifier: AGPL-3.0-only

package deploy

import (
	"os"
	"strings"
	"testing"
)

// The installer embeds the service files as heredocs so `curl | sh` works
// without a checkout; they must stay identical to the files in deploy/.
func TestInstallScriptHeredocsMatchServiceFiles(t *testing.T) {
	tests := []struct {
		file, marker string
	}{
		{"systemd/hearth-agent.service", "HEARTH_SYSTEMD_UNIT"},
		{"launchd/dev.hearth.agent.plist", "HEARTH_LAUNCHD_PLIST"},
		{"systemd/hearth-hub.service", "HEARTH_HUB_UNIT"},
		{"launchd/dev.hearth.hub.plist", "HEARTH_LAUNCHD_HUB_PLIST"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			want, err := os.ReadFile(tt.file)
			if err != nil {
				t.Fatal(err)
			}
			got := heredoc(t, string(InstallScript), tt.marker)
			if got != string(want) {
				t.Errorf("heredoc %s in install.sh differs from %s:\n--- install.sh\n%s\n--- %s\n%s",
					tt.marker, tt.file, got, tt.file, want)
			}
		})
	}
}

// heredoc returns the body of the single <<'marker' heredoc in script,
// including the trailing newline.
func heredoc(t *testing.T, script, marker string) string {
	t.Helper()
	open := "<<'" + marker + "'\n"
	i := strings.Index(script, open)
	if i < 0 || strings.Count(script, open) != 1 {
		t.Fatalf("install.sh must contain exactly one <<'%s' heredoc", marker)
	}
	body := script[i+len(open):]
	end := strings.Index(body, "\n"+marker+"\n")
	if end < 0 {
		t.Fatalf("heredoc %s is not terminated", marker)
	}
	return body[:end+1]
}

func TestInstallScriptIsEmbedded(t *testing.T) {
	if !strings.HasPrefix(string(InstallScript), "#!/bin/sh\n") {
		t.Fatal("InstallScript does not start with #!/bin/sh")
	}
}

func TestInstallPowerShellIsEmbedded(t *testing.T) {
	if !strings.HasPrefix(string(InstallPowerShell), "# SPDX-License-Identifier: AGPL-3.0-only\n") {
		t.Fatal("InstallPowerShell is not deploy/install.ps1")
	}
}
