package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/config"
	"github.com/Oreki0504/Argus-C2/internal/database"
)

func TestAuditCommandsPreviewExportAndVerification(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	s, err := database.Open(state, true)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()
	missing := filepath.Join(dir, "unavailable-credential")
	c := config.Server{Listen: "127.0.0.1:8443", StateDir: state, Certificate: missing, PrivateKey: missing, CA: missing, IssuerKey: missing, Admins: missing}
	file := filepath.Join(dir, "server.json")
	if err = writeJSON(file, c); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = auditCommand("audit-retention", []string{"-config", file, "-capacity", "2000"}, &out); err != nil {
		t.Fatal(err)
	}
	var report database.AuditRetentionReport
	if err = json.Unmarshal(out.Bytes(), &report); err != nil || report.Applied || report.CurrentCapacity != 100000 || report.Capacity != 2000 {
		t.Fatal(report, err)
	}
	if err = auditCommand("audit-retention", []string{"-config", file, "-apply"}, &bytes.Buffer{}); err == nil {
		t.Fatal("apply without backup accepted")
	}
	export := filepath.Join(dir, "export.json")
	if err = auditCommand("audit-export", []string{"-config", file, "-out", export}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err = auditCommand("audit-verify", []string{"-file", export}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err = auditCommand("audit-export", []string{"-config", file, "-out", export}, &bytes.Buffer{}); err == nil {
		t.Fatal("export overwritten")
	}
}
