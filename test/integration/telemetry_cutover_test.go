package integration

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/api"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/enrollment"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestTelemetryCutoverPreservesManualDiagnosticsAndHistory(t *testing.T) {
	f := newFleet(t)
	// Change the handler only before any requests are in flight.
	f.server.Config.Handler = (&api.Server{Store: f.store, Enrollment: enrollment.Service{Store: f.store, Issuer: f.issuer}, Admins: f.admins, Monitoring: true}).Handler()
	p := policy.Default()
	p.Telemetry.SampleMilliseconds = 100
	r := f.enroll("cutover", p)
	for range 2 {
		if err := r.Step(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var before, metrics int
	if err := f.store.DB.QueryRow("SELECT count(*) FROM tasks").Scan(&before); err != nil || before != 2 {
		t.Fatal("comparison mode did not preserve legacy scheduling", before, err)
	}
	if err := f.store.DB.QueryRow("SELECT count(*) FROM tasks WHERE task_type='system.metrics' AND status='SUCCEEDED'").Scan(&metrics); err != nil || metrics != 1 {
		t.Fatal("legacy snapshot unavailable", metrics, err)
	}
	node := r.Engine.State.NodeID
	latest, err := f.store.LatestTelemetry(t.Context(), node)
	if err != nil || latest == nil {
		t.Fatal("independent observations missing during comparison", latest, err)
	}
	var payload string
	if err := f.store.DB.QueryRow("SELECT r.payload FROM results r JOIN tasks t ON r.task_id=t.id WHERE t.task_type='system.metrics'").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	snapshot, err := protocol.DecodeMeasurements([]byte(payload))
	if err != nil || snapshot.Memory.Available != latest.Metrics.Memory.Available || snapshot.Memory.TotalBytes != latest.Metrics.Memory.TotalBytes || len(snapshot.Disks) != len(latest.Metrics.Disks) {
		t.Fatal("collector semantics diverged", snapshot, latest, err)
	}
	if latest.ObservedAt <= 0 || latest.ReceivedAt < latest.ObservedAt || len(latest.NetworkRates) != len(latest.Metrics.Networks) {
		t.Fatal("observation metadata or initial rate availability invalid", latest)
	}
	// Restart with the normal default: no automatic monitoring tasks.
	address := f.server.Listener.Addr().String()
	f.server.Close()
	r.Client.CloseIdleConnections()
	f.start(address)
	for range 3 {
		if err := r.Step(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	var after int
	if err := f.store.DB.QueryRow("SELECT count(*) FROM tasks").Scan(&after); err != nil || after != before {
		t.Fatal("monitoring still depends on tasks after cutover", before, after, err)
	}
	manual := f.task(node, protocol.SystemMetrics, "{}")
	if err := r.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	view, err := f.store.Task(t.Context(), manual.ID)
	if err != nil || view.Result == nil || view.Task.Status != protocol.Succeeded {
		t.Fatal("manual metrics snapshot broken", view, err)
	}
	if _, err := json.Marshal(view); err != nil {
		t.Fatal(err)
	}
	page, err := f.store.QueryTelemetry(t.Context(), node, database.TelemetryQuery{From: time.Now().Add(-time.Hour).Unix(), To: time.Now().Unix(), Limit: 100})
	if err != nil || len(page.Items) == 0 || page.Items[0].SampleID != latest.SampleID {
		t.Fatal("history lost after cutover", page, err)
	}
	if err := f.store.DB.QueryRow("SELECT count(*) FROM results").Scan(&after); err != nil || after != before+1 {
		t.Fatal("diagnostic history lost", after, err)
	}
}
