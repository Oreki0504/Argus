package database

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestTelemetryPruneBoundedBackupAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		s := fixture(t)
		c := telemetryCertificate(t, s)
		now := time.Now()
		s.clock = func() time.Time { return now }
		batch := protocol.TelemetryBatch{SchemaVersion: 1, Samples: []protocol.TelemetrySample{telemetrySample("old1", now.Add(-25*time.Hour).Unix()), telemetrySample("old2", now.Add(-25*time.Hour).Unix()), telemetrySample("keep", now.Unix())}}
		if _, err := s.SubmitTelemetry(t.Context(), c, batch); err != nil {
			t.Fatal(err)
		}
		p, err := s.PreviewPruneTelemetry(t.Context(), 1, 1)
		if err != nil || len(p.Items) != 1 || p.Applied || historyCount(t, s, "telemetry_samples") != 3 {
			t.Fatal(p, err)
		}
		if _, err = s.PruneTelemetry(t.Context(), 1, 1, ""); err == nil {
			t.Fatal("pruned without backup")
		}
		if fail {
			if _, err = s.DB.Exec("CREATE TRIGGER fail BEFORE INSERT ON audit_events BEGIN SELECT RAISE(FAIL,'audit failure'); END"); err != nil {
				t.Fatal(err)
			}
		}
		dir := filepath.Join(t.TempDir(), "restore")
		if err = os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		p, err = s.PruneTelemetry(t.Context(), 1, 1, filepath.Join(dir, "argus.db"))
		if fail {
			if err == nil || p.Applied || historyCount(t, s, "telemetry_samples") != 3 {
				t.Fatal("partial deletion", p, err)
			}
		} else if err != nil || !p.Applied || p.Deleted != 1 || historyCount(t, s, "telemetry_samples") != 2 {
			t.Fatal(p, err)
		}
		restored, err := Open(dir, false)
		if err != nil {
			t.Fatal(err)
		}
		if historyCount(t, restored, "telemetry_samples") != 3 {
			t.Fatal("backup missing observations")
		}
		restored.Close()
	}
}

func seedTelemetryRetention(t *testing.T, s *Store, count int, observedAt int64) {
	t.Helper()
	err := s.Write(t.Context(), func(tx *sql.Tx) error {
		for i := range count {
			sample := telemetrySample(fmt.Sprintf("retention-%04d", i), observedAt)
			payload, err := protocol.CanonicalTelemetrySample(sample)
			if err != nil {
				return err
			}
			if _, err = tx.ExecContext(t.Context(), "INSERT INTO telemetry_samples(node_id,sample_id,boot_id,observed_at,received_at,agent_version,schema_version,interval_seconds,clock_skew,payload_json) VALUES('node',?,'boot-1',?,?,'test',1,60,0,?)", sample.SampleID, sample.ObservedAt, observedAt+60, string(payload)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTelemetrySweepUsesOneBackupAndOneAuditPerBatch(t *testing.T) {
	s := fixture(t)
	now := time.Now()
	s.clock = func() time.Time { return now }
	cutoff := now.Add(-30 * 24 * time.Hour).Unix()
	seedTelemetryRetention(t, s, 9, cutoff-1)
	if _, err := s.DB.Exec("UPDATE telemetry_samples SET observed_at=? WHERE sample_id='retention-0007'", cutoff); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec("UPDATE telemetry_samples SET observed_at=? WHERE sample_id='retention-0008'", now.Unix()); err != nil {
		t.Fatal(err)
	}
	p, err := s.PreviewPruneTelemetrySweep(t.Context(), 30, 2, 3)
	if err != nil || len(p.Items) != 6 || p.Batches != 3 || p.Applied || historyCount(t, s, "telemetry_samples") != 9 {
		t.Fatal(p, err)
	}
	dir := filepath.Join(t.TempDir(), "snapshot")
	if err = os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "argus.db")
	p, err = s.PruneTelemetrySweep(t.Context(), 30, 2, 3, backup)
	if err != nil || !p.Applied || p.Deleted != 6 || p.CompletedBatches != 3 || p.FailedBatch != 0 || p.SweepID == "" || p.Backup != backup || historyCount(t, s, "telemetry_samples") != 3 {
		t.Fatal(p, err)
	}
	rows, err := s.DB.Query("SELECT subject_id,status FROM audit_events WHERE action='telemetry.prune' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	audits := 0
	for rows.Next() {
		var subject, raw string
		if err = rows.Scan(&subject, &raw); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		var a struct {
			SweepID string `json:"sweep_id"`
			Batch   int    `json:"batch"`
			Cutoff  int64  `json:"cutoff"`
			Count   int    `json:"count"`
			Backup  string `json:"backup"`
		}
		audits++
		if err = json.Unmarshal([]byte(raw), &a); err != nil || subject != p.SweepID || a.SweepID != p.SweepID || a.Batch != audits || a.Cutoff != cutoff || a.Count != 2 || a.Backup != backup {
			rows.Close()
			t.Fatal(subject, a, err)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil || audits != 3 {
		t.Fatal(audits, err)
	}
	restored, err := Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if historyCount(t, restored, "telemetry_samples") != 9 || historyCount(t, restored, "audit_events") != 0 {
		t.Fatal("backup does not precede the whole sweep")
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	backups := 0
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".db") {
			backups++
		}
	}
	if backups != 1 {
		t.Fatal("created more than one snapshot", backups)
	}
}

func TestTelemetrySweepBackupFailureCannotDelete(t *testing.T) {
	s := fixture(t)
	seedTelemetryRetention(t, s, 5, time.Now().Add(-31*24*time.Hour).Unix())
	backup := filepath.Join(t.TempDir(), "existing.db")
	if err := os.WriteFile(backup, []byte("preserve"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := s.PruneTelemetrySweep(t.Context(), 30, 2, 3, backup)
	if err == nil || p.Applied || p.Deleted != 0 || p.CompletedBatches != 0 || p.Backup != "" || historyCount(t, s, "telemetry_samples") != 5 || historyCount(t, s, "audit_events") != 0 {
		t.Fatal(p, err)
	}
	b, err := os.ReadFile(backup)
	if err != nil || string(b) != "preserve" {
		t.Fatal("backup overwritten", err)
	}
}

func TestTelemetrySweepReportsCommittedProgressAndRollsBackFailedBatch(t *testing.T) {
	for _, mode := range []string{"delete", "audit", "changed-candidate", "reused-id-same-receipt"} {
		t.Run(mode, func(t *testing.T) {
			s := fixture(t)
			seedTelemetryRetention(t, s, 6, time.Now().Add(-31*24*time.Hour).Unix())
			var trigger string
			switch mode {
			case "delete":
				trigger = "CREATE TRIGGER reject_prune BEFORE DELETE ON telemetry_samples WHEN OLD.sample_id='retention-0003' BEGIN SELECT RAISE(FAIL,'delete unavailable'); END"
			case "audit":
				trigger = "CREATE TRIGGER reject_prune BEFORE INSERT ON audit_events WHEN NEW.action='telemetry.prune' AND json_extract(NEW.status,'$.batch')=2 BEGIN SELECT RAISE(FAIL,'audit unavailable'); END"
			case "changed-candidate":
				trigger = "CREATE TRIGGER change_candidate AFTER INSERT ON audit_events WHEN NEW.action='telemetry.prune' AND json_extract(NEW.status,'$.batch')=1 BEGIN UPDATE telemetry_samples SET observed_at=9999999999 WHERE sample_id='retention-0003'; END"
			case "reused-id-same-receipt":
				// Replace the same row ID and logical key with changed payload while
				// preserving received_at too; a timestamp-only guard cannot catch it.
				trigger = `CREATE TRIGGER replace_candidate AFTER INSERT ON audit_events WHEN NEW.action='telemetry.prune' AND json_extract(NEW.status,'$.batch')=1 BEGIN
INSERT OR REPLACE INTO telemetry_samples(id,node_id,sample_id,boot_id,observed_at,received_at,agent_version,schema_version,interval_seconds,clock_skew,payload_json)
SELECT id,node_id,sample_id,boot_id,observed_at,received_at,agent_version,schema_version,interval_seconds,clock_skew,json_set(payload_json,'$.metrics.cpu.busy_percent',77) FROM telemetry_samples WHERE sample_id='retention-0003'; END`
			}
			if _, err := s.DB.Exec(trigger); err != nil {
				t.Fatal(err)
			}
			p, err := s.PruneTelemetrySweep(t.Context(), 30, 2, 3, filepath.Join(t.TempDir(), "before.db"))
			if err == nil || p.Applied || p.Deleted != 2 || p.CompletedBatches != 1 || p.FailedBatch != 2 || p.Backup == "" || len(p.Items) != 6 || historyCount(t, s, "telemetry_samples") != 4 {
				t.Fatal(p, err)
			}
			if !strings.Contains(err.Error(), "2 deleted samples") {
				t.Fatal("failure hid committed progress", err)
			}
			if (mode == "changed-candidate" || mode == "reused-id-same-receipt") && !errors.Is(err, ErrConflict) {
				t.Fatal("candidate mutation not detected", err)
			}
			var count int
			if err = s.DB.QueryRow("SELECT count(*) FROM telemetry_samples WHERE sample_id='retention-0002'").Scan(&count); err != nil || count != 1 {
				t.Fatal("failed batch partially deleted", count, err)
			}
			if err = s.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='telemetry.prune'").Scan(&count); err != nil || count != 1 {
				t.Fatal("failed batch audited as success", count, err)
			}
			if mode == "reused-id-same-receipt" {
				var cpu float64
				if err = s.DB.QueryRow("SELECT json_extract(payload_json,'$.metrics.cpu.busy_percent') FROM telemetry_samples WHERE sample_id='retention-0003'").Scan(&cpu); err != nil || cpu != 77 {
					t.Fatal("replacement observation was lost", cpu, err)
				}
			}
		})
	}
}

func TestTelemetrySweepRejectsUnexportableAuditPathBeforeBackup(t *testing.T) {
	s := fixture(t)
	seedTelemetryRetention(t, s, 1, time.Now().Add(-31*24*time.Hour).Unix())
	// This path need not exist: size validation must precede file creation.
	p, err := s.PruneTelemetrySweep(t.Context(), 30, 1000, 100, filepath.Join(t.TempDir(), strings.Repeat("long/", 250), "backup.db"))
	if err == nil || !strings.Contains(err.Error(), "audit record") || p.Deleted != 0 || p.Backup != "" || historyCount(t, s, "telemetry_samples") != 1 {
		t.Fatal(p, err)
	}
}

func TestTelemetrySweepSnapshotCoverageRejectsDeletedOrChangedCandidates(t *testing.T) {
	for _, mode := range []string{"missing-then-identical-reinsert", "changed", "matching", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			s := fixture(t)
			seedTelemetryRetention(t, s, 1, time.Now().Add(-31*24*time.Hour).Unix())
			p, err := s.PreviewPruneTelemetrySweep(t.Context(), 30, 1, 1)
			if err != nil || len(p.Items) != 1 {
				t.Fatal(p, err)
			}
			var originalPayload string
			if err = s.DB.QueryRow("SELECT payload_json FROM telemetry_samples WHERE id=?", p.Items[0].ID).Scan(&originalPayload); err != nil {
				t.Fatal(err)
			}
			if mode == "missing-then-identical-reinsert" {
				if _, err = s.DB.Exec("DELETE FROM telemetry_samples"); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "changed" {
				if _, err = s.DB.Exec("UPDATE telemetry_samples SET payload_json=json_set(payload_json,'$.metrics.cpu.busy_percent',77)"); err != nil {
					t.Fatal(err)
				}
			}
			backup := filepath.Join(t.TempDir(), "before.db")
			if err = s.Backup(t.Context(), backup); err != nil {
				t.Fatal(err)
			}
			if mode == "missing-then-identical-reinsert" {
				item := p.Items[0]
				if _, err = s.DB.Exec("INSERT INTO telemetry_samples(id,node_id,sample_id,boot_id,observed_at,received_at,agent_version,schema_version,interval_seconds,clock_skew,payload_json) VALUES(?,?,?,'boot-1',?,?,'test',1,60,0,?)", item.ID, item.NodeID, item.SampleID, item.ObservedAt, item.ReceivedAt, originalPayload); err != nil {
					t.Fatal(err)
				}
			}
			ctx := t.Context()
			if mode == "canceled" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err = verifyTelemetryPruneSnapshot(ctx, backup, p.Cutoff, p.Items)
			switch mode {
			case "matching":
				if err != nil {
					t.Fatal(err)
				}
			case "canceled":
				if !errors.Is(err, context.Canceled) {
					t.Fatal(err)
				}
			default:
				if !errors.Is(err, ErrConflict) {
					t.Fatal("uncovered candidate accepted", err)
				}
			}
			if historyCount(t, s, "telemetry_samples") != 1 || historyCount(t, s, "audit_events") != 0 {
				t.Fatal("snapshot validation mutated live state")
			}
		})
	}
}

func TestTelemetrySweepDoesNotDeleteNewEligibleObservations(t *testing.T) {
	s := fixture(t)
	seedTelemetryRetention(t, s, 5, time.Now().Add(-31*24*time.Hour).Unix())
	// This deterministic interleaving inserts an eligible record after freezing
	// and backing up candidates but before the next transaction starts. It models
	// a writer committing between batches without relying on scheduling sleeps.
	if _, err := s.DB.Exec(`CREATE TRIGGER new_observation AFTER INSERT ON audit_events WHEN NEW.action='telemetry.prune' AND json_extract(NEW.status,'$.batch')=1 BEGIN
INSERT INTO telemetry_samples(node_id,sample_id,boot_id,observed_at,received_at,agent_version,schema_version,interval_seconds,clock_skew,payload_json)
SELECT node_id,'new-arrival',boot_id,observed_at,received_at,agent_version,schema_version,interval_seconds,clock_skew,json_set(payload_json,'$.sample_id','new-arrival') FROM telemetry_samples WHERE sample_id='retention-0004'; END`); err != nil {
		t.Fatal(err)
	}
	p, err := s.PruneTelemetrySweep(t.Context(), 30, 2, 3, filepath.Join(t.TempDir(), "before.db"))
	if err != nil || !p.Applied || p.Deleted != 5 || p.CompletedBatches != 3 || len(p.Items) != 5 || historyCount(t, s, "telemetry_samples") != 1 {
		t.Fatal(p, err)
	}
	var sample string
	if err = s.DB.QueryRow("SELECT sample_id FROM telemetry_samples").Scan(&sample); err != nil || sample != "new-arrival" {
		t.Fatal("post-freeze record deleted", sample, err)
	}
}

func TestTelemetrySweepBoundsAndSingleBatchCompatibility(t *testing.T) {
	s := fixture(t)
	seedTelemetryRetention(t, s, 5, time.Now().Add(-31*24*time.Hour).Unix())
	for _, v := range [][3]int{{0, 1, 1}, {36501, 1, 1}, {30, 0, 1}, {30, 1001, 1}, {30, 1, 0}, {30, 1, 101}} {
		if _, err := s.PreviewPruneTelemetrySweep(t.Context(), v[0], v[1], v[2]); err == nil {
			t.Fatal("invalid sweep bounds accepted", v)
		}
	}
	if p, err := s.PreviewPruneTelemetrySweep(t.Context(), 30, 1000, 100); err != nil || len(p.Items) != 5 || p.Batches != 100 {
		t.Fatal(p, err)
	}
	p, err := s.PruneTelemetry(t.Context(), 30, 2, filepath.Join(t.TempDir(), "before.db"))
	if err != nil || !p.Applied || p.Batches != 1 || p.CompletedBatches != 1 || p.Deleted != 2 || len(p.Items) != 2 || historyCount(t, s, "telemetry_samples") != 3 {
		t.Fatal("single-batch API changed", p, err)
	}
}
