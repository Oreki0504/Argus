package database

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAuditRetentionBackupBoundedBatchesAndRollback(t *testing.T) {
	s := fixture(t)
	if _, err := s.DB.Exec(`WITH RECURSIVE x(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM x WHERE n<3500)
 INSERT INTO audit_events(timestamp,actor,action,node_id,task_id,status) SELECT 1,'operator','test','','','ok' FROM x`); err != nil {
		t.Fatal(err)
	}
	preview, err := s.PreviewAuditRetention(t.Context(), 1000)
	if err != nil || preview.CurrentCapacity != 100000 || preview.Eligible != 2501 || preview.Applied {
		t.Fatal(preview, err)
	}
	if _, err = s.ConfigureAuditRetention(t.Context(), 1000, ""); err == nil {
		t.Fatal("missing backup accepted")
	}
	dir := t.TempDir()
	backup := filepath.Join(dir, "audit-backup.db")
	report, err := s.ConfigureAuditRetention(t.Context(), 1000, backup)
	if err != nil || !report.Applied || report.Deleted != 1000 || report.RemainingEligible != 1501 {
		t.Fatal(report, err)
	}
	if _, err = os.Stat(backup); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ConfigureAuditRetention(t.Context(), 2000, backup); err == nil {
		t.Fatal("existing backup overwritten")
	}
	current, err := s.PreviewAuditRetention(t.Context(), 0)
	if err != nil || current.CurrentCapacity != 1000 {
		t.Fatal(current, err)
	}
	if err = s.Write(t.Context(), func(tx *sql.Tx) error { return Audit(t.Context(), tx, "operator", "next", "", "", "ok") }); err != nil {
		t.Fatal(err)
	}
	current, err = s.PreviewAuditRetention(t.Context(), 0)
	if err != nil || current.Rows != 1502 {
		t.Fatal("prune batch exceeded bound", current, err)
	}
	if _, err = s.DB.Exec("CREATE TRIGGER fail_retention_audit BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL,'audit unavailable'); END"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ConfigureAuditRetention(t.Context(), 2000, filepath.Join(dir, "failure-backup.db")); err == nil {
		t.Fatal("audit failure ignored")
	}
	current, err = s.PreviewAuditRetention(t.Context(), 0)
	if err != nil || current.CurrentCapacity != 1000 || current.Rows != 1502 {
		t.Fatal("failed configuration partially applied", current, err)
	}
}

func TestAuditExportPaginationIntegrityPrivateFilesAndImmutableBoundary(t *testing.T) {
	s := fixture(t)
	for range 5 {
		if err := s.Write(t.Context(), func(tx *sql.Tx) error {
			return auditSubject(t.Context(), tx, "operator", "test", "node", "task", "subject", "ok")
		}); err != nil {
			t.Fatal(err)
		}
	}
	page, err := s.ExportAudit(t.Context(), 0, 0, 2)
	if err != nil || len(page.Data.Events) != 2 || !page.Data.HasMore || page.Data.Through != 5 || page.Data.Events[0].SubjectID != "subject" {
		t.Fatal(page, err)
	}
	if err = s.Write(t.Context(), func(tx *sql.Tx) error { return Audit(t.Context(), tx, "operator", "later", "", "", "ok") }); err != nil {
		t.Fatal(err)
	}
	final, err := s.ExportAudit(t.Context(), page.Data.NextAfter, page.Data.Through, 10)
	if err != nil || len(final.Data.Events) != 3 || final.Data.HasMore || final.Data.NextAfter != 5 {
		t.Fatal("snapshot boundary moved", final, err)
	}
	private := t.TempDir()
	if err = os.Chmod(private, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(private, "audit.json")
	if err = WriteAuditExport(file, page); err != nil {
		t.Fatal(err)
	}
	if err = WriteAuditExport(file, page); err == nil {
		t.Fatal("existing export overwritten")
	}
	st, err := os.Stat(file)
	if err != nil || runtime.GOOS != "windows" && st.Mode().Perm() != 0600 {
		t.Fatal(st, err)
	}
	loaded, err := ReadAuditExport(file)
	if err != nil || loaded.SHA256 != page.SHA256 {
		t.Fatal(loaded, err)
	}
	bytes, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := strings.Replace(string(bytes), `"action": "test"`, `"action": "changed"`, 1)
	if err = os.WriteFile(file, []byte(corrupt), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadAuditExport(file); err == nil {
		t.Fatal("corrupt export verified")
	}
	// Reformatting JSON does not alter the canonical logical content digest.
	compact, _ := json.Marshal(page)
	if err = os.WriteFile(file, compact, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = ReadAuditExport(file); err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{0, MaxAuditExportEvents + 1} {
		if _, err = s.ExportAudit(t.Context(), 0, 0, limit); err == nil {
			t.Fatal("invalid limit accepted", limit)
		}
	}
}
