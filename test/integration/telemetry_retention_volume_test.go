//go:build linux

package integration

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"golang.org/x/sys/unix"
)

const retentionVolumeRows = 50 * 60 * 24 * 30
const retentionVolumeExpired = 50 * 60 * 24
const retentionVolumeDiskBudget = int64(6 << 30)

// This opt-in test measures retention on a realistic 30-day SQLite inventory.
// Fixture insertion uses bounded SQL transactions, bypassing authentication and
// ingestion validation. Fixture timings are not ingestion throughput results.
// Use a disk-backed private TMPDIR: the default /tmp may be a small tmpfs.
func TestTelemetryRetentionThirtyDayVolume(t *testing.T) {
	if os.Getenv("ARGUS_TELEMETRY_RETENTION_VOLUME") != "1" {
		t.Skip("set ARGUS_TELEMETRY_RETENTION_VOLUME=1; requires 6 GiB free in a disk-backed TMPDIR")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	available := retentionVolumeFree(t, dir)
	if available < uint64(retentionVolumeDiskBudget) {
		t.Fatalf("requires 6 GiB free before starting; available=%d", available)
	}
	stateDir := filepath.Join(dir, "state")
	store, err := database.Open(stateDir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().Truncate(time.Second)
	retentionVolumeSeedIdentity(t, store, now)
	beforeIdentity := retentionVolumeProtectedDigest(t, store.DB)
	base := protocol.TelemetrySample{
		SampleID: "volume-template", BootID: "volume-runtime", ObservedAt: now.Unix(), AgentVersion: "retention-volume-fixture", IntervalSeconds: 60,
		System: protocol.SystemInformation{Available: true, OS: "linux", Architecture: "amd64", Hostname: "volume-host", Kernel: "6.0.0", BootTime: now.Add(-40 * 24 * time.Hour).Unix()},
		Metrics: protocol.SystemMeasurements{
			CPU:      protocol.CPUStats{Available: true, BusyPercent: 42.5, WindowMS: 1000},
			Memory:   protocol.MemoryStats{Available: true, TotalBytes: 8 << 30, AvailableBytes: 4 << 30},
			Disks:    []protocol.DiskStats{{Path: "/", Available: true, TotalBytes: 100 << 30, AvailableBytes: 50 << 30}},
			Networks: []protocol.NetworkStats{{Interface: "eth0", Available: true, RXBytes: 123456789, TXBytes: 987654321}},
		}, Errors: []protocol.TelemetryCollectionError{},
	}
	payload, err := protocol.CanonicalTelemetrySample(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture_start rows=%d expired=%d free_bytes=%d disk_budget_bytes=%d template_payload_bytes=%d", retentionVolumeRows, retentionVolumeExpired, available, retentionVolumeDiskBudget, len(payload))
	fixtureStart := time.Now()
	const rowsPerNode = retentionVolumeRows / 50
	const fixtureBatch = 10000
	inserted := 0
	for node := range 50 {
		for offset := 0; offset < rowsPerNode; offset += fixtureBatch {
			last := min(offset+fixtureBatch, rowsPerNode) - 1
			tx, err := store.DB.BeginTx(t.Context(), nil)
			if err != nil {
				t.Fatal(err)
			}
			_, err = tx.ExecContext(t.Context(), `WITH RECURSIVE sequence(n) AS (SELECT ? UNION ALL SELECT n+1 FROM sequence WHERE n<?),
 fixture AS (SELECT printf('volume-%02d-%06d',?,n) AS sample_id,
 CASE WHEN n<1440 THEN ?+n*60 ELSE ?+(n-1440)*60 END AS observed_at,n FROM sequence)
 INSERT INTO telemetry_samples(node_id,sample_id,boot_id,observed_at,received_at,agent_version,schema_version,interval_seconds,clock_skew,cpu_percent,memory_total_bytes,memory_available_bytes,payload_json)
 SELECT ?,sample_id,'volume-runtime',observed_at,observed_at+2,'retention-volume-fixture',1,60,0,42.5,'8589934592','4294967296',
 json_set(?,'$.sample_id',sample_id,'$.observed_at',observed_at,'$.metrics.networks[0].rx_bytes',n*6000,'$.metrics.networks[0].tx_bytes',n*12000) FROM fixture`,
				offset, last, node, now.Add(-31*24*time.Hour).Unix(), now.Add(-29*24*time.Hour).Unix(), fmt.Sprintf("volume-node-%02d", node), string(payload))
			if err != nil {
				tx.Rollback()
				t.Fatal(err)
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			inserted += last - offset + 1
			// Keep WAL growth and available-space risk bounded throughout setup.
			if _, err = store.DB.ExecContext(t.Context(), "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
				t.Fatal(err)
			}
			bytes := retentionVolumeFileBytes(t, filepath.Join(stateDir, "argus.db"))
			if bytes*2+(128<<20) > retentionVolumeDiskBudget {
				t.Fatalf("fixture plus one backup would exceed 6 GiB budget: database_bytes=%d", bytes)
			}
			if retentionVolumeFree(t, dir) < uint64(bytes)+(128<<20) {
				t.Fatalf("insufficient remaining free space for verified backup after %d rows", inserted)
			}
		}
		if (node+1)%10 == 0 {
			t.Logf("fixture_progress rows=%d elapsed_seconds=%.3f database_bytes=%d", inserted, time.Since(fixtureStart).Seconds(), retentionVolumeFileBytes(t, filepath.Join(stateDir, "argus.db")))
		}
	}
	fixtureDuration := time.Since(fixtureStart)
	if count := retentionVolumeCount(t, store.DB, "SELECT count(*) FROM telemetry_samples"); count != retentionVolumeRows {
		t.Fatalf("fixture rows=%d", count)
	}
	preview, err := store.PreviewPruneTelemetrySweep(t.Context(), 30, 1000, 72)
	if err != nil || len(preview.Items) != retentionVolumeExpired {
		t.Fatalf("expired candidate mismatch count=%d err=%v", len(preview.Items), err)
	}
	// At least one typed history query ensures the generated payloads are valid
	// observations and correspond to SQL identity/time columns.
	page, err := store.QueryTelemetry(t.Context(), "volume-node-00", database.TelemetryQuery{From: now.Add(-29 * 24 * time.Hour).Unix(), To: now.Unix(), Limit: 2})
	if err != nil || len(page.Items) != 2 || page.Items[0].SampleID != "volume-00-001440" {
		t.Fatalf("invalid generated sample shape: %+v %v", page, err)
	}
	dbBefore := retentionVolumeFileBytes(t, filepath.Join(stateDir, "argus.db"))
	backup := filepath.Join(dir, "before-retention.db")
	t.Logf("sweep_start candidates=%d batches=72 database_bytes=%d", len(preview.Items), dbBefore)
	sweepStart := time.Now()
	report, err := store.PruneTelemetrySweep(t.Context(), 30, 1000, 72, backup)
	sweepDuration := time.Since(sweepStart)
	if err != nil || !report.Applied || report.Deleted != retentionVolumeExpired || report.CompletedBatches != 72 || report.FailedBatch != 0 {
		t.Fatalf("retention sweep failed: deleted=%d completed_batches=%d failed_batch=%d error=%v", report.Deleted, report.CompletedBatches, report.FailedBatch, err)
	}
	t.Logf("sweep_complete deleted=%d batches=%d backup_ms=%d prune_ms=%d total_seconds=%.3f", report.Deleted, report.CompletedBatches, report.BackupDurationMS, report.PruneDurationMS, sweepDuration.Seconds())
	backupBytes := retentionVolumeFileBytes(t, backup)
	dbAfter := retentionVolumeFileBytes(t, filepath.Join(stateDir, "argus.db"))
	walBytes := retentionVolumeOptionalBytes(t, filepath.Join(stateDir, "argus.db-wal"))
	if dbAfter+walBytes+backupBytes > retentionVolumeDiskBudget {
		t.Fatalf("actual footprint exceeded 6 GiB: db=%d wal=%d backup=%d", dbAfter, walBytes, backupBytes)
	}
	retained := retentionVolumeCount(t, store.DB, "SELECT count(*) FROM telemetry_samples")
	if retained != retentionVolumeRows-retentionVolumeExpired || retentionVolumeCount(t, store.DB, "SELECT count(*) FROM telemetry_samples WHERE observed_at<?", report.Cutoff) != 0 {
		t.Fatalf("unexpected remaining observations: %d", retained)
	}
	if digest := retentionVolumeProtectedDigest(t, store.DB); digest != beforeIdentity {
		t.Fatal("retention changed node identity, task/result, or diagnostic metadata")
	}
	auditBatches := retentionVolumeCount(t, store.DB, "SELECT count(*) FROM audit_events WHERE action='telemetry.prune' AND subject_id=?", report.SweepID)
	if auditBatches != 72 {
		t.Fatalf("expected one summary audit per committed batch, got %d", auditBatches)
	}
	if audited := retentionVolumeCount(t, store.DB, "SELECT coalesce(sum(json_extract(status,'$.count')),0) FROM audit_events WHERE action='telemetry.prune' AND subject_id=?", report.SweepID); audited != retentionVolumeExpired {
		t.Fatalf("audit deletion count=%d", audited)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	backups := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			backups++
			if entry.Name() != "before-retention.db" {
				t.Fatalf("unexpected additional backup %s", entry.Name())
			}
		}
	}
	if backups != 1 {
		t.Fatalf("expected exactly one backup, got %d", backups)
	}
	// Restore by moving the sole snapshot into an isolated state directory.
	// This exercises the real Open path without a third multi-GiB copy.
	restoreStart := time.Now()
	t.Logf("restore_verification_start backup_bytes=%d", backupBytes)
	restoreDir := filepath.Join(dir, "restored")
	if err = os.Mkdir(restoreDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(backup, filepath.Join(restoreDir, "argus.db")); err != nil {
		t.Fatal(err)
	}
	restored, err := database.Open(restoreDir, false)
	if err != nil {
		t.Fatal("backup cannot be opened as restored state", err)
	}
	defer restored.Close()
	var integrity string
	if err = restored.DB.QueryRowContext(t.Context(), "PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		t.Fatal("restored integrity check", integrity, err)
	}
	if count := retentionVolumeCount(t, restored.DB, "SELECT count(*) FROM telemetry_samples"); count != retentionVolumeRows {
		t.Fatalf("restored rows=%d", count)
	}
	if count := retentionVolumeCount(t, restored.DB, "SELECT count(*) FROM telemetry_samples WHERE observed_at<?", report.Cutoff); count != retentionVolumeExpired {
		t.Fatalf("expired observations not recoverable: %d", count)
	}
	if retentionVolumeProtectedDigest(t, restored.DB) != beforeIdentity {
		t.Fatal("backup did not preserve identity and diagnostic state")
	}
	result := map[string]any{
		"nodes": 50, "inventory_samples": retentionVolumeRows, "expired_samples": retentionVolumeExpired, "retained_samples": retained, "deleted_samples": report.Deleted,
		"sample_interval_seconds": 60, "raw_retention_days": 30, "fixture_batch_rows": fixtureBatch, "fixture_seconds": fixtureDuration.Seconds(),
		"backup_count": backups, "completed_batches": report.CompletedBatches, "batch_limit": 1000, "audit_batch_records": auditBatches,
		"database_before_bytes": dbBefore, "database_after_bytes": dbAfter, "wal_after_bytes": walBytes, "backup_bytes": backupBytes,
		"initial_free_bytes": available, "disk_budget_bytes": retentionVolumeDiskBudget, "peak_measured_state_bytes": dbAfter + walBytes + backupBytes,
		"sweep_total_seconds": sweepDuration.Seconds(), "backup_duration_ms": report.BackupDurationMS, "prune_duration_ms": report.PruneDurationMS,
		"restore_verification_seconds": time.Since(restoreStart).Seconds(), "restored_integrity": integrity, "identity_and_diagnostics_preserved": true,
		"limitations": "single-host disk-backed SQLite retention benchmark; fixture uses direct bounded SQL and is not an ingestion or 72-hour/VPS test; includes one backup and isolated restore without copying a third database",
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(string(raw))
	if output := os.Getenv("ARGUS_TELEMETRY_RETENTION_VOLUME_REPORT"); output != "" {
		if err = os.WriteFile(output, append(raw, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func retentionVolumeSeedIdentity(t *testing.T, s *database.Store, now time.Time) {
	t.Helper()
	tx, err := s.DB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := range 50 {
		id := fmt.Sprintf("volume-node-%02d", i)
		if _, err = tx.ExecContext(t.Context(), "INSERT INTO nodes(id,hostname,certificate_fingerprint,status,created_at,certificate_expires_at,certificate) VALUES(?,?,?,'active',?,?,?)", id, id, "fixture-fingerprint-"+id, now.Add(-40*24*time.Hour).Unix(), now.Add(365*24*time.Hour).Unix(), "fixture-certificate-"+id); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = tx.ExecContext(t.Context(), `INSERT INTO tasks(id,node_id,task_type,parameters,status,created_at,dispatch_expires_at,execution_timeout_ms,result_due_at,execution_authorized_at)
 VALUES('volume-task','volume-node-00','system.info','{}','SUCCEEDED',?,?,1000,?,?)`, now.Add(-time.Hour).Unix(), now.Add(-time.Hour+time.Minute).Unix(), now.Add(-time.Hour+2*time.Minute).Unix(), now.Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(t.Context(), `INSERT INTO results(task_id,node_id,status,payload,error,completed_at,received_at) VALUES('volume-task','volume-node-00','SUCCEEDED',?,'',?,?)`, `{"available":false,"os":"linux","architecture":"amd64","hostname":"","kernel":"","boot_time":0}`, now.Add(-time.Hour).Unix(), now.Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	collection := protocol.DiagnosticCollection{ID: "volume-collection", BootID: "volume-runtime", CollectorVersion: "retention-volume-fixture", StartedAt: now.Add(-time.Hour).Unix(), CompletedAt: now.Add(-time.Hour).Unix(), DurationMS: 1, DiagnosticEvidence: protocol.DiagnosticEvidence{Coverage: "unavailable", ResourcesTotal: 1}}
	raw, err := json.Marshal(collection)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.ExecContext(t.Context(), "INSERT INTO diagnostic_result_metadata(task_id,payload_json) VALUES('volume-task',?)", string(raw)); err != nil {
		t.Fatal(err)
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func retentionVolumeProtectedDigest(t *testing.T, db *sql.DB) string {
	t.Helper()
	digest := sha256.New()
	queries := []string{
		"SELECT json_array(id,hostname,certificate_fingerprint,status,last_seen_at,created_at,certificate_expires_at,certificate,previous_fingerprint,previous_until,protocol_version,agent_version) FROM nodes ORDER BY id",
		"SELECT json_array(node_id,public_id,display_name) FROM console_nodes ORDER BY node_id",
		"SELECT json_array(id,node_id,task_type,parameters,status,created_at,dispatch_expires_at,execution_timeout_ms,result_due_at,execution_authorized_at) FROM tasks ORDER BY id",
		"SELECT json_array(task_id,node_id,status,payload,error,completed_at,received_at) FROM results ORDER BY task_id",
		"SELECT json_array(task_id,payload_json) FROM diagnostic_result_metadata ORDER BY task_id",
	}
	for _, query := range queries {
		rows, err := db.QueryContext(t.Context(), query)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var raw string
			if err = rows.Scan(&raw); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			fmt.Fprintln(digest, raw)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func retentionVolumeCount(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var count int
	if err := db.QueryRowContext(t.Context(), query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func retentionVolumeFileBytes(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func retentionVolumeOptionalBytes(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func retentionVolumeFree(t *testing.T, path string) uint64 {
	t.Helper()
	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		t.Fatal(err)
	}
	return stat.Bavail * uint64(stat.Bsize)
}
