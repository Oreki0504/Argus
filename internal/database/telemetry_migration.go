package database

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Oreki0504/Argus-C2/internal/localdb"
)

// The typed payload is authoritative for exact uint64 counters. Decimal TEXT
// columns prevent SQLite's signed integer and floating point coercion from
// rounding memory sizes. No diagnostic identity, task or audit row is rewritten.
const telemetrySchema = `
CREATE TABLE telemetry_samples (
 id INTEGER PRIMARY KEY,
 node_id TEXT NOT NULL REFERENCES nodes(id),
 sample_id TEXT NOT NULL, boot_id TEXT NOT NULL,
 observed_at INTEGER NOT NULL CHECK(observed_at>0),
 received_at INTEGER NOT NULL CHECK(received_at>0),
 agent_version TEXT NOT NULL, schema_version INTEGER NOT NULL CHECK(schema_version=1),
 interval_seconds INTEGER NOT NULL CHECK(interval_seconds BETWEEN 30 AND 300),
 clock_skew INTEGER NOT NULL CHECK(clock_skew IN (0,1)),
 cpu_percent REAL, memory_total_bytes TEXT, memory_available_bytes TEXT,
 payload_json TEXT NOT NULL CHECK(json_valid(payload_json)),
 UNIQUE(node_id,sample_id)
);
CREATE INDEX telemetry_node_observed ON telemetry_samples(node_id,observed_at,sample_id);
CREATE INDEX telemetry_observed ON telemetry_samples(observed_at,id);
CREATE INDEX telemetry_received ON telemetry_samples(received_at);
PRAGMA user_version=105;
` + alertsSchema + diagnosticsSchema + auditSettingsSchema + nodeMetadataSchema + capabilitiesSchema + diagnosticMetadataSchema

// MigrateTelemetry requires a stopped Server and a new private backup path.
// Startup does not silently upgrade existing installations.
func MigrateTelemetry(ctx context.Context, dir, backup string) error {
	lock, err := localdb.LockServer(dir)
	if err != nil {
		return err
	}
	defer lock.Close()
	parent, err := os.Lstat(filepath.Dir(backup))
	if err != nil {
		return err
	}
	if backup == "" || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && parent.Mode().Perm()&0077 != 0 {
		return errors.New("backup directory must be private and non-symlink")
	}
	db, err := localdb.Open(dir, "argus.db", false)
	if err != nil {
		return err
	}
	defer db.Close()
	var version, component int
	if err = db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if err = db.QueryRowContext(ctx, "PRAGMA application_id").Scan(&component); err != nil {
		return err
	}
	if version != 104 || component != applicationID {
		return errors.New("telemetry migration requires an ARGS schema 104 database")
	}
	s := &Store{DB: db}
	if err = s.backupVersion(ctx, backup, version); err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version != 104 {
		return errors.New("database changed during migration")
	}
	if _, err = tx.ExecContext(ctx, telemetrySchema); err != nil {
		return err
	}
	if err = Audit(ctx, tx, "local", "telemetry.migrate", "", "", "105"); err != nil {
		return err
	}
	return tx.Commit()
}
