// SPDX-License-Identifier: AGPL-3.0-only

package hub

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/gvart/hearth/internal/automation"
	"github.com/gvart/hearth/internal/policy"
)

// Files that the hub loads from disk, and that a web save must refuse.
const (
	namedTemplatesYAML = `id: named
triggers:
  - type: manual
actions:
  - type: log
    message: '{{define "who"}}the pi{{end}}hello {{template "who"}}'
`
	overBudgetYAML = `id: over
triggers:
  - type: manual
actions:
  - type: log
    message: '{{range 2000000}}xxxxxxxxxx{{end}}'
`
)

// TestWebRefusesWhatDiskMayLoad: the limits on new files must not reach the
// files a lab already runs, and those files must not get in the way of others.
func TestWebRefusesWhatDiskMayLoad(t *testing.T) {
	for name, tc := range map[string]struct{ id, yaml, problem string }{
		"named templates": {"named", namedTemplatesYAML, "define"},
		"over budget":     {"over", overBudgetYAML, "render limit"},
	} {
		t.Run(name, func(t *testing.T) {
			path := "/api/v1/automations/" + tc.id
			refused := func(t *testing.T, resp apiResp) {
				t.Helper()
				if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(string(resp.body), tc.problem) {
					t.Errorf("status %d: %s; want 422 naming %q", resp.StatusCode, resp.body, tc.problem)
				}
			}

			t.Run("create", func(t *testing.T) {
				f := newAutomationFixture(t, policy.Config{})
				refused(t, f.send(t, http.MethodPost, "/api/v1/automations", "application/json", saveBody(t, tc.yaml, ""), f.cookie))
				if got := f.files(t); len(got) != 0 {
					t.Errorf("written: %v", got)
				}
			})

			t.Run("update of a file on disk", func(t *testing.T) {
				f := newAutomationFixture(t, policy.Config{})
				f.write(t, tc.id+".yaml", tc.yaml)
				body := saveBody(t, tc.yaml+"# edited\n", automation.Revision([]byte(tc.yaml)))
				refused(t, f.send(t, http.MethodPut, path, "application/json", body, f.cookie))
				if got := f.read(t, tc.id+".yaml"); got != tc.yaml {
					t.Errorf("file changed:\n%s", got)
				}
			})

			t.Run("dry run", func(t *testing.T) {
				f := newAutomationFixture(t, policy.Config{})
				resp := f.send(t, http.MethodPost, "/api/v1/automations/dry-run", "application/json", saveBody(t, tc.yaml, ""), f.cookie)
				var out AutomationDryRunJSON
				if err := json.Unmarshal(resp.body, &out); err != nil {
					t.Fatal(err)
				}
				if out.Valid || len(out.Problems) == 0 {
					t.Errorf("dry run = %s", resp.body)
				}
			})

			t.Run("on disk it is valid and blocks no other save", func(t *testing.T) {
				f := newAutomationFixture(t, policy.Config{})
				f.write(t, tc.id+".yaml", tc.yaml)
				resp := f.do(t, http.MethodGet, path, "", f.cookie)
				var src AutomationSourceJSON
				if err := json.Unmarshal(resp.body, &src); err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != http.StatusOK || len(src.Problems) != 0 {
					t.Errorf("read: status %d, problems %+v", resp.StatusCode, src.Problems)
				}
				save := f.send(t, http.MethodPost, "/api/v1/automations", "application/json", saveBody(t, nightlyLogYAML, ""), f.cookie)
				if save.StatusCode != http.StatusCreated {
					t.Errorf("saving another file: status %d: %s", save.StatusCode, save.body)
				}
			})
		})
	}
}
