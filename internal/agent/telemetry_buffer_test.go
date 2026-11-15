package agent

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func telemetrySample(id string, observed time.Time) protocol.TelemetrySample {
	return protocol.TelemetrySample{SampleID: id, BootID: "boot", ObservedAt: observed.Unix(), AgentVersion: "test", IntervalSeconds: 60,
		Metrics: protocol.SystemMeasurements{Disks: []protocol.DiskStats{}, Networks: []protocol.NetworkStats{}},
		System:  protocol.SystemInformation{OS: "linux", Architecture: "amd64"}, Errors: []protocol.TelemetryCollectionError{}}
}

func TestTelemetryBufferRestartIdentityAndAcknowledgment(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	b, err := OpenTelemetryBuffer(dir, "node", 1024*1024, true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	sample := telemetrySample("sample", now.Add(-time.Hour))
	if err = b.Add(t.Context(), sample, now); err != nil {
		t.Fatal(err)
	}
	if err = b.Add(t.Context(), sample, now); err != nil {
		t.Fatal("duplicate", err)
	}
	changed := sample
	changed.Agent.UptimeSeconds++
	if err = b.Add(t.Context(), changed, now); err == nil {
		t.Fatal("conflicting identity replaced")
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	if wrong, e := OpenTelemetryBuffer(dir, "other", 1024*1024, false); e == nil {
		wrong.Close()
		t.Fatal("wrong identity accepted")
	}
	b, err = OpenTelemetryBuffer(dir, "node", 1024*1024, false)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	pending, err := b.Pending(t.Context(), now)
	if err != nil || len(pending) != 1 || pending[0].ObservedAt != sample.ObservedAt || pending[0].Agent.UptimeSeconds != 0 {
		t.Fatalf("observations changed across restart: %+v %v", pending, err)
	}
	for _, ids := range [][]string{nil, {"unknown"}, {"sample", "sample"}} {
		if err = b.Acknowledge(t.Context(), pending, protocol.TelemetryAck{SampleIDs: ids}); err == nil {
			t.Fatal("invalid ACK discarded sample", ids)
		}
	}
	if status, err := b.Status(t.Context()); err != nil || status.Samples != 1 {
		t.Fatal(status, err)
	}
	if err = b.Acknowledge(t.Context(), pending, protocol.TelemetryAck{SampleIDs: []string{"sample"}}); err != nil {
		t.Fatal(err)
	}
	if status, err := b.Status(t.Context()); err != nil || status.Samples != 0 {
		t.Fatal(status, err)
	}
}

func TestTelemetryBufferAgeCountBytesAndFailedWrite(t *testing.T) {
	for _, kind := range []string{"count", "bytes"} {
		t.Run(kind, func(t *testing.T) {
			b, err := OpenTelemetryBuffer(filepath.Join(t.TempDir(), "state"), "node", 1024*1024, true)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			now := time.Now()
			sample := telemetrySample("base", now)
			count := TelemetryBufferLimit
			if kind == "bytes" {
				count = 180
				for i := range 32 {
					sample.Errors = append(sample.Errors, protocol.TelemetryCollectionError{ResourceID: fmt.Sprintf("%02d", i) + strings.Repeat("x", 220), Code: "unavailable"})
				}
			}
			tx, err := b.db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			for i := range count {
				sample.SampleID = fmt.Sprintf("sample-%04d", i)
				payload, e := protocol.CanonicalTelemetrySample(sample)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = tx.Exec("INSERT INTO telemetry_buffer(sample_id,observed_at,payload) VALUES(?,?,?)", sample.SampleID, sample.ObservedAt, string(payload)); e != nil {
					t.Fatal(e)
				}
			}
			if err = tx.Commit(); err != nil {
				t.Fatal(err)
			}
			old := telemetrySample("old", now.Add(-time.Minute))
			if err = b.Add(t.Context(), old, now); err != nil {
				t.Fatal(err)
			}
			status, err := b.Status(t.Context())
			if err != nil || status.Samples > TelemetryBufferLimit || status.PayloadBytes > 1024*1024 || status.DroppedCapacity == 0 {
				t.Fatalf("bounds not enforced %+v %v", status, err)
			}
			var remains int
			if err = b.db.QueryRow("SELECT count(*) FROM telemetry_buffer WHERE sample_id='old'").Scan(&remains); err != nil || remains != 0 {
				t.Fatal("older arrival displaced newer data", remains, err)
			}
			if err = b.Add(t.Context(), telemetrySample("expired", now.Add(-25*time.Hour)), now); err != nil {
				t.Fatal(err)
			}
			status, err = b.Status(t.Context())
			if err != nil || status.DroppedExpired != 1 {
				t.Fatal(status, err)
			}
			before := status
			if _, err = b.db.Exec("CREATE TRIGGER reject_telemetry BEFORE INSERT ON telemetry_buffer BEGIN SELECT RAISE(FAIL,'storage failure'); END"); err != nil {
				t.Fatal(err)
			}
			if err = b.Add(t.Context(), telemetrySample("failed", now), now); err == nil {
				t.Fatal("failed write reported success")
			}
			after, err := b.Status(t.Context())
			if err != nil || after != before {
				t.Fatal("failed transaction modified durable buffer", before, after, err)
			}
		})
	}
}

func TestTelemetryBufferHeldDataAndSchemaPreserved(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	b, err := OpenTelemetryBuffer(dir, "node", 1024*1024, true)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for _, id := range []string{"bad", "good"} {
		if err = b.Add(t.Context(), telemetrySample(id, now), now); err != nil {
			t.Fatal(err)
		}
	}
	if err = b.Hold(t.Context(), "bad", "telemetry_invalid"); err != nil {
		t.Fatal(err)
	}
	pending, err := b.Pending(t.Context(), now)
	if err != nil || len(pending) != 1 || pending[0].SampleID != "good" {
		t.Fatal(pending, err)
	}
	status, err := b.Status(t.Context())
	if err != nil || status.HeldSamples != 1 || status.Samples != 2 {
		t.Fatal(status, err)
	}
	if _, err = b.db.Exec("PRAGMA user_version=999"); err != nil {
		t.Fatal(err)
	}
	if err = b.Close(); err != nil {
		t.Fatal(err)
	}
	if incompatible, e := OpenTelemetryBuffer(dir, "node", 1024*1024, true); e == nil {
		incompatible.Close()
		t.Fatal("incompatible schema overwritten")
	}
}
