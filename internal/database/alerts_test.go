package database

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestAlertSustainedEvidenceDeduplicationUnknownAndRecovery(t *testing.T) {
	s := fixture(t)
	cert := telemetryCertificate(t, s)
	start := time.Now().Unix()
	now := start
	s.clock = func() time.Time { return time.Unix(now, 0) }
	upload := func(offset int64, cpu float64, available bool) protocol.TelemetrySample {
		t.Helper()
		now = start + offset
		sample := telemetrySample(fmt.Sprintf("sample-%d", offset), now)
		if available {
			sample.Metrics.CPU.BusyPercent = cpu
		} else {
			sample.Metrics.CPU = protocol.CPUStats{}
		}
		if _, err := s.SubmitTelemetry(t.Context(), cert, protocol.TelemetryBatch{SchemaVersion: 1, Samples: []protocol.TelemetrySample{sample}}); err != nil {
			t.Fatal(err)
		}
		return sample
	}
	page := func(status string) AlertPage {
		t.Helper()
		p, err := s.QueryAlerts(t.Context(), AlertQuery{NodeID: "node", Status: status, Limit: 20})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	upload(0, 95, true)
	upload(60, 95, true)
	if p := page("FIRING"); len(p.Items) != 0 {
		t.Fatal("alert fired without persistence", p)
	}
	peak := upload(120, 95, true)
	p := page("FIRING")
	if len(p.Items) != 1 || p.Items[0].RuleID != "cpu-critical" {
		t.Fatal(p)
	}
	id := p.Items[0].ID
	if _, err := s.SubmitTelemetry(t.Context(), cert, protocol.TelemetryBatch{SchemaVersion: 1, Samples: []protocol.TelemetrySample{peak}}); err != nil {
		t.Fatal(err)
	}
	late := telemetrySample("late", start+30)
	late.Metrics.CPU.BusyPercent = 1
	if _, err := s.SubmitTelemetry(t.Context(), cert, protocol.TelemetryBatch{SchemaVersion: 1, Samples: []protocol.TelemetrySample{late}}); err != nil {
		t.Fatal(err)
	}
	upload(180, 20, true)
	upload(240, 0, false)
	upload(300, 20, true)
	upload(360, 20, true)
	if p := page("FIRING"); len(p.Items) != 1 || p.Items[0].ID != id {
		t.Fatal("unknown data resolved active incident", p)
	}
	upload(420, 20, true)
	if p := page("FIRING"); len(p.Items) != 0 {
		t.Fatal("valid recovery did not resolve", p)
	}
	p = page("RESOLVED")
	if len(p.Items) != 1 || p.Items[0].Reason != "valid_observations_recovered" {
		t.Fatal(p)
	}
	events, err := s.QueryAlertEvents(t.Context(), AlertEventQuery{AlertID: id, Limit: 200})
	if err != nil || len(events) != 2 || events[0].State != "FIRING" || events[1].State != "RESOLVED" {
		t.Fatal(events, err)
	}
}

func TestMissingTelemetryAlertSweepsAndValidRecovery(t *testing.T) {
	s := fixture(t)
	cert := telemetryCertificate(t, s)
	start := time.Now().Unix()
	now := start
	s.clock = func() time.Time { return time.Unix(now, 0) }
	if _, err := s.DB.Exec("UPDATE nodes SET created_at=? WHERE id='node'", start); err != nil {
		t.Fatal(err)
	}
	sweep := func(offset int64) {
		t.Helper()
		now = start + offset
		if err := s.SweepAlerts(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	check := func(want int) {
		t.Helper()
		p, err := s.QueryAlerts(t.Context(), AlertQuery{Status: "FIRING", Limit: 20})
		if err != nil || len(p.Items) != want {
			t.Fatal(p, err)
		}
	}
	sweep(179)
	check(0)
	sweep(180)
	check(1)
	sweep(240)
	check(1)
	for _, offset := range []int64{240, 300, 360} {
		now = start + offset
		sample := telemetrySample(fmt.Sprintf("recovery-%d", offset), now)
		if _, err := s.SubmitTelemetry(t.Context(), cert, protocol.TelemetryBatch{SchemaVersion: 1, Samples: []protocol.TelemetrySample{sample}}); err != nil {
			t.Fatal(err)
		}
		if offset < 360 {
			check(1)
		}
	}
	check(0)
	events, err := s.QueryAlertEvents(t.Context(), AlertEventQuery{NodeID: "node", Limit: 200})
	if err != nil || len(events) != 2 || events[0].Reason != "telemetry_missing" {
		t.Fatal(events, err)
	}
	sweep(540)
	check(1)
	if err = s.Disable(t.Context(), "admin", "node"); err != nil {
		t.Fatal(err)
	}
	sweep(900)
	// Disabled nodes are no longer evaluated. Existing events remain traceable.
	events, err = s.QueryAlertEvents(t.Context(), AlertEventQuery{NodeID: "node", Limit: 200})
	if err != nil || len(events) < 3 {
		t.Fatal(events, err)
	}
}

func TestAlertGapRuleChangeAndAtomicAuditFailure(t *testing.T) {
	s := fixture(t)
	cert := telemetryCertificate(t, s)
	start := time.Now().Unix()
	now := start
	s.clock = func() time.Time { return time.Unix(now, 0) }
	upload := func(offset int64) error {
		now = start + offset
		sample := telemetrySample(fmt.Sprintf("high-%d", offset), now)
		sample.Metrics.CPU.BusyPercent = 99
		_, err := s.SubmitTelemetry(t.Context(), cert, protocol.TelemetryBatch{SchemaVersion: 1, Samples: []protocol.TelemetrySample{sample}})
		return err
	}
	if err := upload(0); err != nil {
		t.Fatal(err)
	}
	if err := upload(181); err != nil {
		t.Fatal(err)
	}
	p, err := s.QueryAlerts(t.Context(), AlertQuery{Limit: 20})
	if err != nil || len(p.Items) != 0 {
		t.Fatal("gap counted as sustained evidence", p, err)
	}
	if _, err = s.DB.Exec("CREATE TRIGGER fail_alert_audit BEFORE INSERT ON audit_events WHEN NEW.action='alert.firing' BEGIN SELECT RAISE(FAIL,'audit failure'); END"); err != nil {
		t.Fatal(err)
	}
	if err = upload(301); err == nil {
		t.Fatal("firing committed without audit")
	}
	var count int
	if err = s.DB.QueryRow("SELECT count(*) FROM telemetry_samples WHERE sample_id='high-301'").Scan(&count); err != nil || count != 0 {
		t.Fatal("partial alert telemetry transaction", count, err)
	}
	if _, err = s.DB.Exec("DROP TRIGGER fail_alert_audit"); err != nil {
		t.Fatal(err)
	}
	if err = upload(301); err != nil {
		t.Fatal(err)
	}
	rules, err := s.ListAlertRules(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var cpu AlertRule
	for _, rule := range rules {
		if rule.ID == "cpu-critical" {
			cpu = rule
		}
	}
	if err = s.PutAlertRule(t.Context(), "admin", cpu); err != nil {
		t.Fatal(err)
	}
	p, err = s.QueryAlerts(t.Context(), AlertQuery{Status: "FIRING", Limit: 20})
	if err != nil || len(p.Items) != 1 {
		t.Fatal("identical rule update resolved incident", p, err)
	}
	cpu.Enabled = false
	if err = s.PutAlertRule(t.Context(), "admin", cpu); err != nil {
		t.Fatal(err)
	}
	p, err = s.QueryAlerts(t.Context(), AlertQuery{Status: "RESOLVED", Limit: 20})
	if err != nil || len(p.Items) != 1 || p.Items[0].Reason != "rule_disabled" {
		t.Fatal(p, err)
	}
	if err = upload(361); err != nil {
		t.Fatal(err)
	}
	p, err = s.QueryAlerts(t.Context(), AlertQuery{Status: "FIRING", Limit: 20})
	if err != nil || len(p.Items) != 0 {
		t.Fatal("disabled rule fired", p, err)
	}
}

type testAlertNotifier struct {
	ids    []int64
	failAt int64
}

func (n *testAlertNotifier) Notify(_ context.Context, event AlertEvent) error {
	if event.ID == n.failAt {
		return errors.New("delivery unavailable")
	}
	n.ids = append(n.ids, event.ID)
	return nil
}

func TestAlertEventNotificationCursorAndRuleValidation(t *testing.T) {
	s := fixture(t)
	now := time.Now().Unix()
	s.clock = func() time.Time { return time.Unix(now, 0) }
	if err := s.SweepAlerts(t.Context()); err != nil {
		t.Fatal(err)
	}
	rules, err := s.ListAlertRules(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Metric == "telemetry_missing" {
			rule.Enabled = false
			if err = s.PutAlertRule(t.Context(), "admin", rule); err != nil {
				t.Fatal(err)
			}
		}
	}
	events, err := s.QueryAlertEvents(t.Context(), AlertEventQuery{Limit: 200})
	if err != nil || len(events) != 2 {
		t.Fatal(events, err)
	}
	n := &testAlertNotifier{failAt: events[1].ID}
	cursor, err := s.DeliverAlertEvents(t.Context(), 0, 200, n)
	if err == nil || cursor != events[0].ID || len(n.ids) != 1 {
		t.Fatal(cursor, n, err)
	}
	n.failAt = 0
	cursor, err = s.DeliverAlertEvents(t.Context(), cursor, 200, n)
	if err != nil || cursor != events[1].ID || len(n.ids) != 2 {
		t.Fatal(cursor, n, err)
	}
	for _, rule := range []AlertRule{{ID: "r", Metric: "cpu_percent", Severity: "CRITICAL", Threshold: 101, RecoverySeconds: 30}, {ID: "r", Metric: "exec", Severity: "CRITICAL", Threshold: 90, RecoverySeconds: 30}, {ID: "r", Metric: "telemetry_missing", Severity: "WARNING", Threshold: 10, RecoverySeconds: 30}, {ID: "r", Metric: "cpu_percent", Severity: "CRITICAL", Threshold: 90, RecoverySeconds: 0}} {
		if err = s.PutAlertRule(t.Context(), "admin", rule); !errors.Is(err, ErrInvalidAlert) {
			t.Fatal("invalid rule accepted", rule, err)
		}
	}
}

func TestAlertRestartRetainsWindowsAndDoesNotDuplicateIncidents(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("INSERT INTO nodes(id,hostname,certificate_fingerprint,status,created_at,certificate_expires_at,certificate) VALUES('node','host','fp','active',1,9999999999,'cert')"); err != nil {
		t.Fatal(err)
	}
	cert := telemetryCertificate(t, s)
	start := time.Now().Unix()
	now := start
	s.clock = func() time.Time { return time.Unix(now, 0) }
	upload := func(offset int64, high bool) {
		t.Helper()
		now = start + offset
		sample := telemetrySample(fmt.Sprintf("restart-%d", offset), now)
		if high {
			sample.Metrics.CPU.BusyPercent = 99
		}
		if _, err := s.SubmitTelemetry(t.Context(), cert, protocol.TelemetryBatch{SchemaVersion: 1, Samples: []protocol.TelemetrySample{sample}}); err != nil {
			t.Fatal(err)
		}
	}
	upload(0, true)
	s.Close()
	s, err = Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	s.clock = func() time.Time { return time.Unix(now, 0) }
	upload(60, true)
	upload(120, true)
	s.Close()
	s, err = Open(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.clock = func() time.Time { return time.Unix(now, 0) }
	upload(120, true)
	upload(180, false)
	upload(240, false)
	upload(300, false)
	upload(360, true)
	upload(420, true)
	upload(480, true)
	page, err := s.QueryAlerts(t.Context(), AlertQuery{NodeID: "node", Limit: 1})
	if err != nil || len(page.Items) != 1 || page.NextCursor == "" || page.Items[0].Status != "FIRING" {
		t.Fatal(page, err)
	}
	second, err := s.QueryAlerts(t.Context(), AlertQuery{NodeID: "node", Limit: 1, Cursor: page.NextCursor})
	if err != nil || len(second.Items) != 1 || second.NextCursor != "" || second.Items[0].Status != "RESOLVED" {
		t.Fatal(second, err)
	}
	if _, err = s.QueryAlerts(t.Context(), AlertQuery{NodeID: "other", Limit: 1, Cursor: page.NextCursor}); !errors.Is(err, ErrInvalidAlert) {
		t.Fatal("cross-node cursor accepted", err)
	}
	events, err := s.QueryAlertEvents(t.Context(), AlertEventQuery{NodeID: "node", Limit: 200})
	if err != nil || len(events) != 3 {
		t.Fatal("restart duplicated transitions", events, err)
	}
}
