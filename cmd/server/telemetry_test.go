package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/config"
	"github.com/Oreki0504/Argus-C2/internal/database"
)

func TestTelemetryMaintenanceWithoutServiceCredentials(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	s, err := database.Open(state, true)
	if err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "unavailable-service-credential")
	c := config.Server{Listen: "127.0.0.1:8443", StateDir: state, Certificate: missing, PrivateKey: missing, CA: missing, IssuerKey: missing, Admins: missing}
	file := filepath.Join(dir, "server.json")
	if err = writeJSON(file, c); err != nil {
		t.Fatal(err)
	}
	// Reconstruct the pre-telemetry schema without touching identity/task tables.
	if _, err = s.DB.Exec("DROP TABLE IF EXISTS diagnostic_result_metadata; DROP TABLE IF EXISTS agent_capabilities; DROP TABLE IF EXISTS node_tags; DROP TABLE IF EXISTS node_revocations; DROP TABLE audit_settings; DROP TABLE diagnostic_batch_tasks; DROP TABLE diagnostic_batches; DROP TABLE alert_events; DROP TABLE alert_states; DROP TABLE alerts; DROP TABLE alert_rules; DROP TABLE telemetry_samples; PRAGMA user_version=104"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	if err = telemetryMigrateCommand([]string{"-config", file}, &bytes.Buffer{}); err == nil {
		t.Fatal("migration without backup accepted")
	}
	before := filepath.Join(dir, "before.db")
	if err = telemetryMigrateCommand([]string{"-config", file, "-backup", before}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(before); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = telemetryPruneCommand([]string{"-config", file}, &out); err != nil {
		t.Fatal(err)
	}
	var report database.TelemetryPruneReport
	if err = json.Unmarshal(out.Bytes(), &report); err != nil || report.RetainDays != 30 || report.Limit != 1000 || report.Batches != 1 || report.Applied || report.Items == nil {
		t.Fatal(report, err)
	}
	backup := filepath.Join(dir, "prune.db")
	for _, args := range [][]string{{"-apply"}, {"-backup", backup}, {"-retain-days", "0"}, {"-limit", "1001"}, {"-batches", "0"}, {"-batches", "101"}, {"-timeout", "0s"}, {"-timeout", "31m"}, {"extra"}} {
		if err = telemetryPruneCommand(append([]string{"-config", file}, args...), &bytes.Buffer{}); err == nil {
			t.Fatal("unsafe arguments accepted", args)
		}
	}
	if _, err = os.Stat(backup); !os.IsNotExist(err) {
		t.Fatal("preview created backup", err)
	}
	out.Reset()
	if err = telemetryPruneCommand([]string{"-config", file, "-apply", "-backup", backup}, &out); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(out.Bytes(), &report); err != nil || !report.Applied || report.Backup != backup {
		t.Fatal(report, err)
	}
	if err = telemetryPruneCommand([]string{"-config", file, "-apply", "-backup", backup}, &bytes.Buffer{}); err == nil {
		t.Fatal("existing backup overwritten")
	}
}

func TestTelemetrySweepCLIEmitsPartialProgressAndPreservesLaterBatches(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	s, err := database.Open(state, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("INSERT INTO nodes(id,hostname,certificate_fingerprint,status,created_at,certificate_expires_at,certificate) VALUES('node','host','fp','active',1,9999999999,'cert')"); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-31 * 24 * time.Hour).Unix()
	for _, id := range []string{"first", "second", "third"} {
		if _, err = s.DB.Exec("INSERT INTO telemetry_samples(node_id,sample_id,boot_id,observed_at,received_at,agent_version,schema_version,interval_seconds,clock_skew,payload_json) VALUES('node',?,'boot',?,?,'test',1,60,0,'{}')", id, old, old+1); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.DB.Exec("CREATE TRIGGER fail_second BEFORE DELETE ON telemetry_samples WHEN OLD.sample_id='second' BEGIN SELECT RAISE(FAIL,'second batch unavailable'); END"); err != nil {
		t.Fatal(err)
	}
	s.Close()
	missing := filepath.Join(dir, "unavailable-credentials")
	file := filepath.Join(dir, "server.json")
	if err = writeJSON(file, config.Server{Listen: "127.0.0.1:8443", StateDir: state, Certificate: missing, PrivateKey: missing, CA: missing, IssuerKey: missing, Admins: missing}); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(dir, "before.db")
	var out bytes.Buffer
	err = telemetryPruneCommand([]string{"-config", file, "-limit", "1", "-batches", "3", "-timeout", "1m", "-apply", "-backup", backup}, &out)
	if err == nil || !strings.Contains(err.Error(), "1 deleted samples") {
		t.Fatal("CLI hid partial failure", err)
	}
	var report database.TelemetryPruneReport
	if err = json.Unmarshal(out.Bytes(), &report); err != nil || report.Applied || report.Deleted != 1 || report.CompletedBatches != 1 || report.FailedBatch != 2 || report.Backup != backup || report.Batches != 3 || len(report.Items) != 3 {
		t.Fatal(report, err)
	}
	s, err = database.Open(state, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var count int
	if err = s.DB.QueryRow("SELECT count(*) FROM telemetry_samples").Scan(&count); err != nil || count != 2 {
		t.Fatal(count, err)
	}
	out.Reset()
	if err = telemetryPruneCommand([]string{"-config", file, "-limit", "1", "-batches", "3"}, &out); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(out.Bytes(), &report); err != nil || report.Applied || len(report.Items) != 2 {
		t.Fatal("preview failed after partial apply", report, err)
	}
}
