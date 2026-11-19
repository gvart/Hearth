// SPDX-License-Identifier: AGPL-3.0-only

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// auditOpSchemaForTest is the schema version whose migration (00018) added
// the indexed operation id columns of audit_log.
const auditOpSchemaForTest = 18

// auditCorpus is a mix of details the folding has to treat alike on the
// columns and on the detail JSON: plain rows, started and outcome pairs,
// reserved keys of other types, an over-deep placeholder, and details SQLite
// cannot parse.
func auditCorpus() []string {
	corpus := []string{
		`{}`,
		`{"old":true}`,
		`{"audit_op":"a","n":1}`,
		`{"audit_outcome_of":"a","n":2}`,
		`{"audit_op":"never"}`,
		`{"audit_op":""}`,
		`{"audit_outcome_of":""}`,
		`{"audit_op":5}`,
		`{"audit_outcome_of":5,"x":1}`,
		`{"audit_op":"5"}`,
		`{"audit_outcome_of":"5","x":2}`,
		`{"audit_op":true}`,
		`{"audit_outcome_of":true}`,
		`{"audit_op":null}`,
		`{"audit_outcome_of":null}`,
		`{"audit_op":{"k":1}}`,
		`{"audit_outcome_of":["z"]}`,
		`{"audit_op":1.5}`,
		`{"audit_outcome_of":1.5}`,
		`{"detail_omitted":true,"audit_op":"deep"}`,
		`{"detail_omitted":true,"audit_outcome_of":"deep","result":"x"}`,
		`{"nested":{"audit_op":"n","audit_outcome_of":"n"}}`,
		`{"hostname":"audit_outcome_of"}`,
		`{"audit_op":"dup","audit_op":"dup2"}`,
		`{"audit_outcome_of":"dup2"}`,
		`[]`,
		`5`,
		`"audit_op"`,
		`null`,
		`{"audit_op":"a","audit_outcome_of":"b"}`,
		`{"audit_outcome_of":"b"}`,
		string(nestedJSON(1001)),
		`{not json`,
		``,
	}
	// Many pairs so a page holds a mix of folded, open and outcome rows.
	for i := range 40 {
		id := fmt.Sprintf("op%d", i)
		corpus = append(corpus, `{"audit_op":"`+id+`","i":`+fmt.Sprint(i)+`}`)
		if i%3 != 0 {
			corpus = append(corpus, `{"audit_outcome_of":"`+id+`","o":`+fmt.Sprint(i)+`}`)
		}
		corpus = append(corpus, `{"plain":`+fmt.Sprint(i)+`}`)
	}
	return corpus
}

func seedAuditCorpus(ctx context.Context, t *testing.T, s *Store) {
	t.Helper()
	base := time.UnixMilli(1_700_000_000_000).UTC()
	for i, d := range auditCorpus() {
		kind := "web"
		if i%2 == 0 {
			kind = "admin"
		}
		if _, err := s.apply(ctx, AppendAudit{
			TS: toMillis(base.Add(time.Duration(i) * time.Second)), ActorKind: kind, ActorID: "root",
			Action: fmt.Sprintf("act.%d", i%4), Target: fmt.Sprintf("t%d", i%3), Decision: "allow",
			Result: fmt.Sprintf("r%d", i), Detail: d,
		}); err != nil {
			t.Fatalf("append %q: %v", d, err)
		}
	}
}

// TestAuditQueryColumnsMatchDetailFolding: folding on the indexed columns
// returns exactly what folding on the detail JSON returns, for every page and
// filter, over a corpus of odd rows.
func TestAuditQueryColumnsMatchDetailFolding(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	seedAuditCorpus(ctx, t, s)
	base := time.UnixMilli(1_700_000_000_000).UTC()

	filters := []AuditFilter{
		{},
		{ActorKind: "admin"},
		{ActorID: "roo"},
		{Actions: []string{"act.1", "act.2"}},
		{Targets: []string{"t0"}},
		{Decision: "deny"},
		{Since: base.Add(20 * time.Second), Until: base.Add(90 * time.Second)},
		{ActorKind: "web", Actions: []string{"act.3"}},
	}
	for fi, f := range filters {
		for _, limit := range []int{1, 2, 5, 17, 1000} {
			f := f
			for page := range 400 {
				want, err := s.Audit().query(ctx, f, limit, false)
				if err != nil {
					t.Fatal(err)
				}
				got, err := s.Audit().query(ctx, f, limit, true)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("filter %d limit %d page %d:\n got  %+v\n want %+v", fi, limit, page, got, want)
				}
				if len(want) < limit {
					break
				}
				f.Before = want[len(want)-1].ID
			}
		}
	}
	got, err := s.Audit().List(ctx, 1000)
	if err != nil {
		t.Fatal(err)
	}
	want, err := s.Audit().query(ctx, AuditFilter{}, 1000, false)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) || len(got) == 0 {
		t.Errorf("List differs from the detail folding: %d rows against %d", len(got), len(want))
	}
}

func auditOpColumns(ctx context.Context, t *testing.T, db *sql.DB) map[int64][2]any {
	t.Helper()
	rows, err := db.QueryContext(ctx, `SELECT id, audit_op, audit_outcome_of FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[int64][2]any{}
	for rows.Next() {
		var id int64
		var op, outcomeOf any
		if err := rows.Scan(&id, &op, &outcomeOf); err != nil {
			t.Fatal(err)
		}
		out[id] = [2]any{op, outcomeOf}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// pathBeforeAuditOp returns the path of a closed database one schema before
// the audit op columns.
func pathBeforeAuditOp(ctx context.Context, t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hearth.db")
	s, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.newMigrator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.DownTo(ctx, auditOpSchemaForTest-1); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestAuditOpMigrationBackfills: rows written before the migration get their
// columns from the detail, and a row SQLite cannot parse is left alone.
func TestAuditOpMigrationBackfills(t *testing.T) {
	ctx := t.Context()
	s, err := Open(ctx, pathBeforeAuditOp(ctx, t), WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ids := map[string]int64{}
	for _, d := range auditCorpus() {
		res, err := s.db.ExecContext(ctx, `INSERT INTO audit_log (ts, actor_kind, actor_id, action, decision, detail)
			VALUES (1, 'admin', 'root', 'x', 'allow', ?)`, d)
		if err != nil {
			t.Fatal(err)
		}
		if ids[d], err = res.LastInsertId(); err != nil {
			t.Fatal(err)
		}
	}
	// What the detail folding says before the migration.
	before, err := s.Audit().query(ctx, AuditFilter{}, 10000, false)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.ApplyLocal(ctx, MigrateSchema{To: auditOpSchemaForTest}); err != nil {
		t.Fatal(err)
	}
	cols := auditOpColumns(ctx, t, s.db)
	for _, tt := range []struct {
		detail     string
		op, outcom any
	}{
		{`{"audit_op":"a","n":1}`, "a", nil},
		{`{"audit_outcome_of":"a","n":2}`, nil, "a"},
		{`{"audit_op":5}`, int64(5), nil},
		{`{"audit_outcome_of":5,"x":1}`, nil, int64(5)},
		{`{"audit_op":null}`, nil, nil},
		{`{"old":true}`, nil, nil},
		{`[]`, nil, nil},
		{string(nestedJSON(1001)), nil, nil},
		{`{not json`, nil, nil},
		{``, nil, nil},
	} {
		if got := cols[ids[tt.detail]]; got[0] != tt.op || got[1] != tt.outcom {
			t.Errorf("detail %.40q: op, outcome_of = %v, %v; want %v, %v", tt.detail, got[0], got[1], tt.op, tt.outcom)
		}
	}
	after, err := s.Audit().query(ctx, AuditFilter{}, 10000, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) == 0 || !reflect.DeepEqual(after, before) {
		t.Errorf("rows read differently after the migration:\n got  %+v\n want %+v", after, before)
	}
	// The log stays append-only.
	if _, err := s.db.ExecContext(ctx, `UPDATE audit_log SET result = 'x'`); err == nil {
		t.Error("audit_log accepts an UPDATE after the migration")
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM audit_log`); err == nil {
		t.Error("audit_log accepts a DELETE after the migration")
	}
}

// TestAuditBeforeTheOpColumns: a node still on the schema before the columns
// (a cluster that has not run `hearth cluster migrate`) applies the same
// command and reads the log as before.
func TestAuditBeforeTheOpColumns(t *testing.T) {
	ctx := t.Context()
	s, err := Open(ctx, pathBeforeAuditOp(ctx, t), WithoutUpgrade())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	seedAuditCorpus(ctx, t, s)

	got, err := s.Audit().List(ctx, 10000)
	if err != nil {
		t.Fatal(err)
	}
	want, err := s.Audit().query(ctx, AuditFilter{}, 10000, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || !reflect.DeepEqual(got, want) {
		t.Errorf("List on the old schema = %d rows, want %d from the detail folding", len(got), len(want))
	}

	// Migrating then backfills what was written meanwhile.
	if _, err := s.ApplyLocal(ctx, MigrateSchema{To: auditOpSchemaForTest}); err != nil {
		t.Fatal(err)
	}
	after, err := s.Audit().query(ctx, AuditFilter{}, 10000, true)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(after, want) {
		t.Error("rows read differently once migrated")
	}
}

// TestAuditAppendSetsOpColumns: a write sets the columns from the detail
// without a change to the replicated command.
func TestAuditAppendSetsOpColumns(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	for _, d := range []string{`{"audit_op":"k"}`, `{"audit_outcome_of":"k"}`, `{}`} {
		if _, err := s.Audit().Append(ctx, AuditEntry{
			ActorKind: "admin", ActorID: "root", Action: "x", Decision: "allow", Detail: json.RawMessage(d),
		}); err != nil {
			t.Fatal(err)
		}
	}
	got := auditOpColumns(ctx, t, s.db)
	want := map[int64][2]any{1: {"k", nil}, 2: {nil, "k"}, 3: {nil, nil}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("columns = %v, want %v", got, want)
	}
	b, err := EncodeCommand(AppendAudit{Detail: "{}"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "audit_op") || strings.Contains(string(b), "outcome_of") {
		t.Errorf("the replicated command carries the columns: %s", b)
	}
}

// TestAuditFoldUsesTheIndex: looking up the outcomes of a page's actions does
// not scan the log.
func TestAuditFoldUsesTheIndex(t *testing.T) {
	ctx := t.Context()
	s := openTest(t)
	rows, err := s.db.QueryContext(ctx, `EXPLAIN QUERY PLAN `+auditFoldSQL(true), 0, `["a"]`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan = append(plan, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if p := strings.Join(plan, "\n"); !strings.Contains(p, "INDEX audit_log_outcome_of") {
		t.Errorf("plan does not use audit_log_outcome_of:\n%s", p)
	}
}

// BenchmarkAuditQuery pages a log of 150k rows by folding on the detail JSON
// ("detail") and on the indexed columns ("column").
func BenchmarkAuditQuery(b *testing.B) {
	ctx := b.Context()
	s := openBench(b)
	seedBenchAudit(ctx, b, s, 150_000)
	for _, mode := range []struct {
		name    string
		indexed bool
	}{{"detail", false}, {"column", true}} {
		for _, page := range []struct {
			name string
			f    AuditFilter
		}{
			{"first", AuditFilter{}},
			{"last", AuditFilter{Before: 102}},
			{"filter_nothing", AuditFilter{ActorKind: "nobody"}},
		} {
			b.Run(mode.name+"/"+page.name, func(b *testing.B) {
				for range b.N {
					if _, err := s.Audit().query(ctx, page.f, 101, mode.indexed); err != nil {
						b.Fatal(err)
					}
				}
			})
		}
	}
}

// seedBenchAudit inserts n rows shaped like a real log: started entries with
// their outcomes, and plain reads.
func seedBenchAudit(ctx context.Context, b *testing.B, s *Store, n int) {
	b.Helper()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		b.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	st, err := tx.PrepareContext(ctx, `INSERT INTO audit_log (ts, actor_kind, actor_id, action, target, decision, result, detail, audit_op, audit_outcome_of)
		VALUES (?1, 'admin', 'root', ?2, 't', 'allow', ?3, ?4,
		        CASE WHEN json_valid(?4) THEN json_extract(?4, '$.audit_op') END,
		        CASE WHEN json_valid(?4) THEN json_extract(?4, '$.audit_outcome_of') END)`)
	if err != nil {
		b.Fatal(err)
	}
	for i := range n {
		action, result, detail := "device.read", "read allowed", `{"path":"/x"}`
		switch i % 4 {
		case 0:
			action, result, detail = "device.revoke", "started", fmt.Sprintf(`{"audit_op":"op%d","n":1}`, i)
		case 1:
			action, result, detail = "device.revoke", "ok", fmt.Sprintf(`{"audit_outcome_of":"op%d","n":1}`, i-1)
		}
		if _, err := st.ExecContext(ctx, i, action, result, detail); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
}
