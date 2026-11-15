package database

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func telemetryCertificate(t *testing.T, s *Store) *x509.Certificate {
	t.Helper()
	now := time.Now()
	c := &x509.Certificate{Raw: []byte("telemetry-cert"), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, URIs: []*url.URL{identity.URI("node")}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	if _, err := s.DB.Exec("UPDATE nodes SET certificate_fingerprint=? WHERE id='node'", identity.Fingerprint(c)); err != nil {
		t.Fatal(err)
	}
	return c
}

func telemetrySample(id string, at int64) protocol.TelemetrySample {
	return protocol.TelemetrySample{SampleID: id, BootID: "boot-1", ObservedAt: at, AgentVersion: "test", IntervalSeconds: 60,
		Metrics: protocol.SystemMeasurements{CPU: protocol.CPUStats{Available: true, BusyPercent: 20, WindowMS: 1000}, Memory: protocol.MemoryStats{Available: true, TotalBytes: 1<<63 + 1, AvailableBytes: 1<<62 + 1}, Disks: []protocol.DiskStats{{Path: "/", Available: true, TotalBytes: 1000, AvailableBytes: 500}}, Networks: []protocol.NetworkStats{{Interface: "eth0", Available: true, RXBytes: 1<<63 + 1, TXBytes: 1<<63 + 2}}},
		System:  protocol.SystemInformation{Available: true, OS: "linux", Architecture: "amd64", Hostname: "test", Kernel: "test", BootTime: at - 3600}, Errors: []protocol.TelemetryCollectionError{}}
}

func TestTelemetryAtomicIdempotencyAuthorizationAndClocks(t *testing.T) {
	s := fixture(t)
	c := telemetryCertificate(t, s)
	now := time.Now().Unix()
	s.clock = func() time.Time { return time.Unix(now, 0) }
	first := telemetrySample("first", now-60)
	batch := protocol.TelemetryBatch{SchemaVersion: 1, Samples: []protocol.TelemetrySample{first}}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			ack, err := s.SubmitTelemetry(t.Context(), c, batch)
			if err != nil || len(ack.SampleIDs) != 1 {
				t.Error(ack, err)
			}
		})
	}
	wg.Wait()
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM telemetry_samples").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	latest, err := s.LatestTelemetry(t.Context(), "node")
	if err != nil || latest.ReceivedAt != now || latest.Metrics.Memory.TotalBytes != 1<<63+1 {
		t.Fatal(latest, err)
	}
	changed := first
	changed.Metrics.CPU.BusyPercent++
	batch.Samples = []protocol.TelemetrySample{telemetrySample("rolled-back", now), changed}
	if _, err = s.SubmitTelemetry(t.Context(), c, batch); !errors.Is(err, ErrTelemetryConflict) {
		t.Fatal(err)
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM telemetry_samples").Scan(&count); err != nil || count != 1 {
		t.Fatal("partial batch committed", count, err)
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='telemetry.conflict' AND subject_id='first'").Scan(&count); err != nil || count != 1 {
		t.Fatal("conflict not audited", count, err)
	}
	for _, at := range []int64{now + 301, now - protocol.TelemetryRetentionSeconds - 1} {
		batch.Samples = []protocol.TelemetrySample{telemetrySample("bad-time", at)}
		if _, err = s.SubmitTelemetry(t.Context(), c, batch); !errors.Is(err, ErrInvalidTelemetry) {
			t.Fatal("invalid clock accepted", at, err)
		}
	}
	batch.Samples = []protocol.TelemetrySample{telemetrySample("future", now+120)}
	if _, err = s.SubmitTelemetry(t.Context(), c, batch); err != nil {
		t.Fatal(err)
	}
	latest, err = s.LatestTelemetry(t.Context(), "node")
	if err != nil || !latest.ClockSkew || ProjectTelemetryStatus(latest, now).Health != "UNKNOWN" {
		t.Fatal("future sample treated as healthy", latest, err)
	}
	now += protocol.TelemetryRetentionSeconds + 100
	batch.Samples = []protocol.TelemetrySample{first}
	if _, err = s.SubmitTelemetry(t.Context(), c, batch); err != nil {
		t.Fatal("late duplicate lost ACK recovery", err)
	}
	if err = s.Disable(t.Context(), "admin", "node"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SubmitTelemetry(t.Context(), c, batch); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("disabled identity accepted on retry", err)
	}
}

func TestTelemetryHistoricalOrderingPaginationAndRates(t *testing.T) {
	s := fixture(t)
	c := telemetryCertificate(t, s)
	now := time.Now().Unix()
	first := telemetrySample("first", now-120)
	second := telemetrySample("second", now-60)
	second.Metrics.Networks[0].RXBytes += 600
	second.Metrics.Networks[0].TXBytes += 1200
	third := telemetrySample("third", now)
	third.Metrics.Networks[0].RXBytes += 1200
	third.Metrics.Networks[0].TXBytes += 2400
	// Upload order is intentionally different from observation order.
	if _, err := s.SubmitTelemetry(t.Context(), c, protocol.TelemetryBatch{SchemaVersion: 1, Samples: []protocol.TelemetrySample{third, first, second}}); err != nil {
		t.Fatal(err)
	}
	q := TelemetryQuery{From: now - 60, To: now, Limit: 1}
	page, err := s.QueryTelemetry(t.Context(), "node", q)
	if err != nil || len(page.Items) != 1 || page.Items[0].SampleID != "second" || page.NextCursor == "" {
		t.Fatal(page, err)
	}
	rate := page.Items[0].NetworkRates[0]
	if !rate.Available || rate.RXBytesPerSecond != 10 || rate.TXBytesPerSecond != 20 {
		t.Fatal("range baseline missing or rounded", rate)
	}
	q.Cursor = page.NextCursor
	page, err = s.QueryTelemetry(t.Context(), "node", q)
	if err != nil || len(page.Items) != 1 || page.Items[0].SampleID != "third" || page.NextCursor != "" || page.Items[0].NetworkRates[0].RXBytesPerSecond != 10 {
		t.Fatal(page, err)
	}
	q.To++
	if _, err = s.QueryTelemetry(t.Context(), "node", q); err == nil {
		t.Fatal("cursor changed range")
	}
	before := TelemetryObservation{TelemetrySample: first}
	for _, kind := range []string{"boot", "counter", "time", "gap", "interface", "unavailable", "skew"} {
		after := TelemetryObservation{TelemetrySample: telemetrySample("after", now-60)}
		after.Metrics.Networks[0].RXBytes += 600
		switch kind {
		case "boot":
			after.BootID = "other"
		case "counter":
			after.Metrics.Networks[0].RXBytes = 0
		case "time":
			after.ObservedAt = before.ObservedAt
		case "gap":
			after.ObservedAt = before.ObservedAt + 181
		case "interface":
			after.Metrics.Networks[0].Interface = "eth1"
		case "unavailable":
			after.Metrics.Networks[0].Available = false
		case "skew":
			after.ClockSkew = true
		}
		if TelemetryNetworkRates(&before, &after)[0].Available {
			t.Fatal("invalid rate", kind)
		}
	}
}

func TestTelemetryHealthNeedsFreshEvidence(t *testing.T) {
	now := time.Now().Unix()
	if got := ProjectTelemetryStatus(nil, now); got.Telemetry != "MISSING" || got.Health != "UNKNOWN" {
		t.Fatal(got)
	}
	o := TelemetryObservation{TelemetrySample: telemetrySample("sample", now)}
	if got := ProjectTelemetryStatus(&o, now); got.Telemetry != "FRESH" || got.Health != "HEALTHY" {
		t.Fatal(got)
	}
	o.Metrics.CPU.BusyPercent = 99
	if got := ProjectTelemetryStatus(&o, now); got.Health != "CRITICAL" {
		t.Fatal(got)
	}
	if got := ProjectTelemetryStatus(&o, now+181); got.Telemetry != "STALE" || got.Health != "UNKNOWN" {
		t.Fatal(got)
	}
	o.Metrics.CPU = protocol.CPUStats{}
	if got := ProjectTelemetryStatus(&o, now); got.Health != "UNKNOWN" {
		t.Fatal(got)
	}
}

func TestTelemetryRestartAndBackupRestore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.DB.Exec("INSERT INTO nodes(id,hostname,certificate_fingerprint,status,created_at,certificate_expires_at,certificate) VALUES('node','host','fp','active',1,9999999999,'cert')")
	if err != nil {
		t.Fatal(err)
	}
	c := telemetryCertificate(t, s)
	batch := protocol.TelemetryBatch{SchemaVersion: 1, Samples: []protocol.TelemetrySample{telemetrySample("persisted", time.Now().Unix())}}
	if _, err = s.SubmitTelemetry(t.Context(), c, batch); err != nil {
		t.Fatal(err)
	}
	restoreDir := filepath.Join(t.TempDir(), "restored")
	if err = os.Mkdir(restoreDir, 0700); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(restoreDir, "argus.db")
	if err = s.Backup(t.Context(), backup); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.SubmitTelemetry(t.Context(), c, batch); err != nil {
		t.Fatal(err)
	}
	o, err := s.LatestTelemetry(t.Context(), "node")
	if err != nil || o == nil || o.SampleID != "persisted" {
		t.Fatal(o, err)
	}
	var count int
	if err = s.DB.QueryRow("SELECT count(*) FROM telemetry_samples").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	restored, err := Open(restoreDir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	o, err = restored.LatestTelemetry(t.Context(), "node")
	if err != nil || o == nil || o.SampleID != "persisted" {
		t.Fatal("restored observation missing", o, err)
	}
	if _, err = restored.Authorize(t.Context(), c); err != nil {
		t.Fatal("restored identity changed", err)
	}
}

func TestTelemetryQueryBoundsResponseBytesWithoutLosingPagination(t *testing.T) {
	s := fixture(t)
	now := time.Now().Unix()
	sample := telemetrySample("large", now)
	for i := range 32 {
		sample.Errors = append(sample.Errors, protocol.TelemetryCollectionError{ResourceID: fmt.Sprint(i) + strings.Repeat("x", 250), Code: "unavailable"})
	}
	err := s.Write(t.Context(), func(tx *sql.Tx) error {
		stmt, err := tx.PrepareContext(t.Context(), "INSERT INTO telemetry_samples(node_id,sample_id,boot_id,observed_at,received_at,agent_version,schema_version,interval_seconds,clock_skew,payload_json) VALUES('node',?,'boot-1',?,?,'test',1,60,0,?)")
		if err != nil {
			return err
		}
		defer stmt.Close()
		for i := range 1000 {
			sample.SampleID = fmt.Sprintf("large-%04d", i)
			sample.ObservedAt = now - int64(1000-i)
			payload, err := protocol.CanonicalTelemetrySample(sample)
			if err != nil {
				return err
			}
			if _, err = stmt.ExecContext(t.Context(), sample.SampleID, sample.ObservedAt, now, string(payload)); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	q := TelemetryQuery{From: now - 1000, To: now, Limit: 1000}
	page, err := s.QueryTelemetry(t.Context(), "node", q)
	if err != nil || len(page.Items) == 0 || len(page.Items) >= 1000 || page.NextCursor == "" {
		t.Fatal(len(page.Items), err)
	}
	encoded, err := json.Marshal(page)
	if err != nil || len(encoded) > MaxTelemetryPageBytes {
		t.Fatal("oversized telemetry response", len(encoded), err)
	}
	firstCount := len(page.Items)
	last := page.Items[firstCount-1].SampleID
	q.Cursor = page.NextCursor
	page, err = s.QueryTelemetry(t.Context(), "node", q)
	if err != nil || firstCount+len(page.Items) != 1000 || page.NextCursor != "" || page.Items[0].SampleID <= last {
		t.Fatal("byte-limited pagination lost observations", firstCount, len(page.Items), err)
	}
}
