package database

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/localdb"
)

func TestTelemetryMigrationPreservesIdentityTasksAndAudit(t *testing.T) {
	for _, mode := range []string{"success", "audit-failure", "ddl-failure", "locked", "backup-exists"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Chmod(root, 0700); err != nil {
				t.Fatal(err)
			}
			dir := filepath.Join(root, "state")
			db, err := localdb.Open(dir, "argus.db", true)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = db.Exec(schema + consoleSchema + consoleAccountSchema + `
INSERT INTO nodes(id,hostname,certificate_fingerprint,status,created_at,certificate_expires_at,certificate) VALUES('old-node','host','fp','active',1,9999999999,'cert');
INSERT INTO tasks(id,node_id,task_type,parameters,status,created_at,dispatch_expires_at,execution_timeout_ms,result_due_at) VALUES('old-task','old-node','system.info','{}','PENDING',1,2,1000,3);
INSERT INTO audit_events(timestamp,actor,action,node_id,task_id,status) VALUES(1,'admin','old.event','old-node','old-task','ok');`); err != nil {
				t.Fatal(err)
			}
			if mode == "audit-failure" {
				if _, err = db.Exec("CREATE TRIGGER fail BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL,'injected'); END"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "ddl-failure" {
				if _, err = db.Exec("CREATE TABLE telemetry_samples(preserved TEXT)"); err != nil {
					t.Fatal(err)
				}
			}
			db.Close()
			if s, err := Open(dir, false); err == nil {
				s.Close()
				t.Fatal("startup silently migrated104")
			}
			backup := filepath.Join(root, "backup.db")
			if mode == "backup-exists" {
				if err = os.WriteFile(backup, []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "locked" {
				lock, err := localdb.LockServer(dir)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			}
			err = MigrateTelemetry(t.Context(), dir, backup)
			if (err == nil) != (mode == "success") {
				t.Fatal(mode, err)
			}
			db, err = localdb.Open(dir, "argus.db", false)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			var version, count int
			if err = db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
				t.Fatal(err)
			}
			want := 104
			if mode == "success" {
				want = 105
			}
			if version != want {
				t.Fatal("partial schema migration", version)
			}
			for _, table := range []string{"nodes", "tasks"} {
				if err = db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 1 {
					t.Fatal("existing data lost", table, count, err)
				}
			}
			var action string
			if err = db.QueryRow("SELECT action FROM audit_events WHERE id=1").Scan(&action); err != nil || action != "old.event" {
				t.Fatal(action, err)
			}
			if mode == "success" || mode == "audit-failure" || mode == "ddl-failure" {
				snapshot, err := sql.Open("sqlite", "file:"+filepath.ToSlash(backup)+"?mode=ro")
				if err != nil {
					t.Fatal(err)
				}
				defer snapshot.Close()
				if err = snapshot.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 104 {
					t.Fatal("backup not original104", version, err)
				}
			}
			if mode == "backup-exists" {
				data, err := os.ReadFile(backup)
				if err != nil || string(data) != "keep" {
					t.Fatal("backup overwritten", err)
				}
			}
		})
	}
}
