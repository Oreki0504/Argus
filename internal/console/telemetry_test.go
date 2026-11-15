package console

import (
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func telemetryConsole(t *testing.T, now int64) (*Server, string, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	store, err := database.Open(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	s, err := New(store, Config{Origin: "https://console.example", StateDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Unix(now, 0) }
	node := identity.RandomID()
	_, err = store.DB.Exec(`INSERT INTO nodes(id,hostname,certificate_fingerprint,status,last_seen_at,created_at,certificate_expires_at,certificate) VALUES(?,'private-host','fp','active',?,1,?,'cert')`, node, now, now+1000)
	if err != nil {
		t.Fatal(err)
	}
	var public string
	if err = store.DB.QueryRow("SELECT public_id FROM console_nodes WHERE node_id=?", node).Scan(&public); err != nil {
		t.Fatal(err)
	}
	return s, node, public
}
func consoleSample(at int64, cpu float64, rx uint64) protocol.TelemetrySample {
	return protocol.TelemetrySample{SampleID: identity.RandomID(), BootID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ObservedAt: at, AgentVersion: "test", IntervalSeconds: 60,
		Metrics: protocol.SystemMeasurements{CPU: protocol.CPUStats{Available: true, BusyPercent: cpu, WindowMS: 1000}, Memory: protocol.MemoryStats{Available: true, TotalBytes: 1000, AvailableBytes: 600}, Disks: []protocol.DiskStats{{Path: "/private/data", Available: true, TotalBytes: 1000, AvailableBytes: 500}}, Networks: []protocol.NetworkStats{{Interface: "private0", Available: true, RXBytes: rx, TXBytes: rx * 2}}},
		System:  protocol.SystemInformation{Available: true, OS: "Ubuntu 24.04", Architecture: "amd64", Hostname: "private-host", Kernel: "6.8.0-private", BootTime: at - 1000}, Errors: []protocol.TelemetryCollectionError{}}
}
func insertConsoleSample(t *testing.T, s *Server, node string, v protocol.TelemetrySample, received int64, skew bool) {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.store.DB.Exec(`INSERT INTO telemetry_samples(node_id,sample_id,boot_id,observed_at,received_at,agent_version,schema_version,interval_seconds,clock_skew,payload_json) VALUES(?,?,?,?,?,'test',1,?,?,?)`, node, v.SampleID, v.BootID, v.ObservedAt, received, v.IntervalSeconds, skew, string(raw))
	if err != nil {
		t.Fatal(err)
	}
}
func readHistory(t *testing.T, s *Server, public, span string) publicHistory {
	t.Helper()
	r := httptest.NewRequest("GET", "https://console.example/v1/console/public/nodes/"+public+"/telemetry?range="+span, nil)
	r.SetPathValue("id", public)
	w := httptest.NewRecorder()
	s.history(w, r)
	return decodeTest[publicHistory](t, w, 200)
}
func readSummary(t *testing.T, s *Server) publicSummary {
	t.Helper()
	w := httptest.NewRecorder()
	s.summary(w, httptest.NewRequest("GET", "https://console.example/v1/console/public/summary", nil))
	return decodeTest[publicSummary](t, w, 200)
}
func TestTelemetryConsoleUsesObservationTimeAndKeepsFourStatesIndependent(t *testing.T) {
	const now = int64(1800000000)
	s, node, public := telemetryConsole(t, now)
	empty := readSummary(t, s).Nodes[0]
	if empty.Status.Connectivity != "ONLINE" || empty.Status.Authorization != "ACTIVE" || empty.Status.Telemetry != "MISSING" || empty.Status.Health != "UNKNOWN" {
		t.Fatal(empty.Status)
	}
	old := consoleSample(now-3600, 20, 100)
	insertConsoleSample(t, s, node, old, now, false)
	delayed := readSummary(t, s).Nodes[0]
	if delayed.Status.Telemetry != "STALE" || delayed.Status.Health != "UNKNOWN" || *delayed.Resources.AsOf != old.ObservedAt || *delayed.Telemetry.ReceivedAt != now {
		t.Fatal(delayed)
	}
	// Insert delayed older observations after newer ones: ordering is observation time.
	current := consoleSample(now-60, 25, 700)
	insertConsoleSample(t, s, node, current, now, false)
	before := consoleSample(now-120, 20, 100)
	insertConsoleSample(t, s, node, before, now, false)
	got := readSummary(t, s).Nodes[0]
	if got.Status.Telemetry != "FRESH" || got.Status.Health != "HEALTHY" || *got.Resources.CPU != 25 || got.Traffic.Inbound == nil || *got.Traffic.Inbound != 80 {
		t.Fatal(got)
	}
	if _, err := s.store.DB.Exec(`INSERT INTO alerts(id,node_id,rule_id,severity,status,opened_at,last_observed_at,reason) VALUES('active-critical',?,'cpu-critical','CRITICAL','FIRING',?,?,'threshold_sustained')`, node, now-240, now-60); err != nil {
		t.Fatal(err)
	}
	if recovery := readSummary(t, s).Nodes[0]; recovery.Status.Health != "CRITICAL" {
		t.Fatal("active critical alert ignored during recovery", recovery.Status)
	}
	if _, err := s.store.DB.Exec("UPDATE alerts SET status='RESOLVED',resolved_at=? WHERE id='active-critical'", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.DB.Exec("UPDATE nodes SET status='disabled' WHERE id=?", node); err != nil {
		t.Fatal(err)
	}
	disabled := readSummary(t, s).Nodes[0]
	if disabled.Status.Authorization != "DISABLED" || disabled.Status.Connectivity != "ONLINE" || disabled.Status.Health != "HEALTHY" {
		t.Fatal(disabled.Status)
	}
	history := readHistory(t, s, public, "1h")
	if len(history.Points) != 3 || history.Points[0].Timestamp != old.ObservedAt || history.Points[1].InboundBPS != nil || *history.Points[2].InboundBPS != 80 {
		t.Fatal(history)
	}
	raw, _ := json.Marshal(history)
	for _, secret := range []string{node, current.SampleID, current.BootID, "private-host", "private0", "/private/data"} {
		if strings.Contains(string(raw), secret) {
			t.Fatal("public history leak", secret)
		}
	}
	future := consoleSample(now+100, 30, 800)
	insertConsoleSample(t, s, node, future, now, true)
	projected := readSummary(t, s).Nodes[0]
	if projected.Status.Telemetry != "STALE" || projected.Status.Health != "UNKNOWN" || !projected.Telemetry.ClockSkew {
		t.Fatal(projected)
	}
	if h := readHistory(t, s, public, "1h"); len(h.Points) != 3 {
		t.Fatal("future data entered present chart", h)
	}
}
func TestTelemetryConsoleThirtyDaysAggregatesWholeWindowAndReportsCounts(t *testing.T) {
	const now = int64(1800000000)
	s, node, public := telemetryConsole(t, now)
	// More than the raw API page limit, spanning both edges and interior buckets.
	for i := 0; i < 1500; i++ {
		at := now - 30*86400 + int64(i)*1729
		insertConsoleSample(t, s, node, consoleSample(at, 25, uint64(i)*100), now, false)
	}
	last := consoleSample(now, 42, 150000)
	insertConsoleSample(t, s, node, last, now, false)
	h := readHistory(t, s, public, "30d")
	if h.Source != "telemetry" || h.Aggregation != "latest_per_bucket" || h.SampleCount != 1501 || len(h.Points) > 1441 || len(h.Points) < 1400 || h.Points[0].Timestamp < h.WindowStart || h.Points[len(h.Points)-1].Timestamp != now || *h.Points[len(h.Points)-1].CPU != 42 {
		t.Fatalf("counts=%d points=%d first=%+v last=%+v", h.SampleCount, len(h.Points), h.Points[0], h.Points[len(h.Points)-1])
	}
	for i, p := range h.Points {
		if i > 0 && p.Timestamp <= h.Points[i-1].Timestamp {
			t.Fatal("unsorted", i)
		}
	}
}

func TestTelemetryConsoleThirtyDayVolume(t *testing.T) {
	if os.Getenv("ARGUS_TELEMETRY_VOLUME") != "1" {
		t.Skip("set ARGUS_TELEMETRY_VOLUME=1 for 43,100 sample chart benchmark")
	}
	const now = int64(1800000000)
	s, node, public := telemetryConsole(t, now)
	tx, err := s.store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO telemetry_samples(node_id,sample_id,boot_id,observed_at,received_at,agent_version,schema_version,interval_seconds,clock_skew,payload_json) VALUES(?,?,?,?,?,'test',1,60,0,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer stmt.Close()
	started := time.Now()
	// 100 missing minutes inside 30 days. Resume within a bucket to ensure
	// aggregation preserves the outage even when the selected sample is later.
	const count = 43100
	for i := 0; i < count; i++ {
		step := i
		if i >= 20000 {
			step += 100
		}
		at := now - int64(43199-step)*60
		sample := consoleSample(at, 25, uint64(i)*1000)
		raw, _ := json.Marshal(sample)
		if _, err = stmt.Exec(node, sample.SampleID, sample.BootID, at, now, string(raw)); err != nil {
			t.Fatal(err)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	fixtureTime := time.Since(started)
	started = time.Now()
	history := readHistory(t, s, public, "30d")
	queryTime := time.Since(started)
	if history.SampleCount != count || len(history.Points) > 1441 || history.Points[len(history.Points)-1].Timestamp != now || history.Points[0].Timestamp > now-30*86400+1800 {
		t.Fatalf("count=%d points=%d", history.SampleCount, len(history.Points))
	}
	gap := false
	for _, point := range history.Points {
		if point.GapBefore && point.Timestamp > now-30*86400+1800 {
			gap = true
		}
	}
	if !gap {
		t.Fatal("30-day aggregation hid missing intervals")
	}
	if queryTime > 10*time.Second {
		t.Fatalf("bounded 30-day query exceeded10s: %s", queryTime)
	}
	t.Logf("samples=%d points=%d fixture=%s 30d_query=%s", history.SampleCount, len(history.Points), fixtureTime, queryTime)
}
