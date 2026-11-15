package agent

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func telemetryRunner(t *testing.T, handler http.Handler) *Runner {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	state, err := OpenState(dir, "node", true)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(protocol.VersionHeader, strconv.Itoa(protocol.Version))
		w.Header().Set("Content-Type", "application/json")
		handler.ServeHTTP(w, r)
	}))
	p := policy.Default()
	p.Telemetry.SampleMilliseconds = 100
	r := &Runner{Server: server.URL, Client: server.Client(), Dir: dir, Engine: &Engine{State: state, Policy: p}, cert: &x509.Certificate{NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * 24 * time.Hour)}, bootID: "test-boot", startedAt: time.Now()}
	t.Cleanup(func() { r.Close(); server.Close() })
	return r
}

func TestTelemetryAndHeartbeatContinueDuringDiagnosticAndBlockedUpload(t *testing.T) {
	var heartbeat, polled atomic.Int32
	uploadStarted := make(chan struct{}, 1)
	r := telemetryRunner(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/v1/agent/heartbeat":
			heartbeat.Add(1)
			io.WriteString(w, "{}")
		case "/v1/agent/poll":
			if polled.Add(1) == 1 {
				json.NewEncoder(w).Encode(task("slow"))
			} else {
				w.WriteHeader(http.StatusNoContent)
			}
		case "/v1/agent/tasks/slow/running":
			io.WriteString(w, "{}")
		case "/v1/agent/telemetry":
			io.Copy(io.Discard, req.Body)
			select {
			case uploadStarted <- struct{}{}:
			default:
			}
			<-req.Context().Done()
		case "/v1/agent/results":
			io.WriteString(w, "{}")
		default:
			t.Errorf("unexpected route %s", req.URL.Path)
			w.WriteHeader(404)
		}
	}))
	started := make(chan struct{})
	r.Engine.Execute = func(ctx context.Context, _ protocol.Task, _ policy.Policy) (json.RawMessage, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	r.testHeartbeatInterval = 40 * time.Millisecond
	r.testTelemetryInterval = 150 * time.Millisecond
	buffer, err := r.telemetryBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if err = buffer.Add(t.Context(), telemetrySample("already-buffered", time.Now()), time.Now()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	for _, ready := range []<-chan struct{}{started, uploadStarted} {
		select {
		case <-ready:
		case <-time.After(3 * time.Second):
			t.Fatal("independent worker did not start")
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		status, err := buffer.Status(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if status.Samples >= 4 && heartbeat.Load() >= 4 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("diagnostic or upload blocked independent scheduling: %+v heartbeats=%d", status, heartbeat.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if polled.Load() != 1 {
		t.Fatal("more than one concurrent diagnostic", polled.Load())
	}
	cancel()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("workers did not join after cancellation")
	}
}

func TestTelemetryDeliveryRequiresExactACKAndIsolatesRejectedSamples(t *testing.T) {
	var malformed atomic.Bool
	malformed.Store(true)
	r := telemetryRunner(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/v1/agent/telemetry" {
			t.Errorf("unexpected route %s", req.URL.Path)
			w.WriteHeader(404)
			return
		}
		if malformed.Load() {
			io.WriteString(w, "{}")
			return
		}
		raw, err := io.ReadAll(req.Body)
		if err != nil {
			t.Error(err)
			return
		}
		batch, err := protocol.DecodeTelemetryBatch(raw)
		if err != nil {
			t.Error(err)
			return
		}
		ids := []string{}
		for _, sample := range batch.Samples {
			if sample.SampleID == "bad" {
				w.WriteHeader(400)
				io.WriteString(w, `{"error":"invalid sample","code":"telemetry_invalid"}`)
				return
			}
			ids = append(ids, sample.SampleID)
		}
		json.NewEncoder(w).Encode(protocol.TelemetryAck{SampleIDs: ids})
	}))
	b, err := r.telemetryBuffer()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"bad", "good"} {
		if err = b.Add(t.Context(), telemetrySample(id, time.Now()), time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	if err = r.flushTelemetry(t.Context()); err == nil {
		t.Fatal("arbitrary 2xx response accepted as ACK")
	}
	if status, err := b.Status(t.Context()); err != nil || status.Samples != 2 {
		t.Fatal(status, err)
	}
	malformed.Store(false)
	if err = r.flushTelemetry(t.Context()); err != nil {
		t.Fatal(err)
	}
	if status, err := b.Status(t.Context()); err != nil || status.Samples != 1 || status.HeldSamples != 1 {
		t.Fatal("good sample blocked or invalid sample discarded", status, err)
	}
}

func TestTelemetryStorageFailureDoesNotStopHeartbeatOrDiagnostics(t *testing.T) {
	var heartbeat, poll atomic.Int32
	r := telemetryRunner(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/v1/agent/heartbeat":
			heartbeat.Add(1)
			io.WriteString(w, "{}")
		case "/v1/agent/poll":
			poll.Add(1)
			w.WriteHeader(204)
		default:
			t.Errorf("unexpected route %s", req.URL.Path)
			w.WriteHeader(404)
		}
	}))
	b, err := r.telemetryBuffer()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.db.Exec("CREATE TRIGGER reject_telemetry BEFORE INSERT ON telemetry_buffer BEGIN SELECT RAISE(FAIL,'storage full'); END"); err != nil {
		t.Fatal(err)
	}
	if err = r.Step(t.Context()); err != nil {
		t.Fatal(err)
	}
	if heartbeat.Load() != 1 || poll.Load() != 1 {
		t.Fatal("telemetry storage affected communication", heartbeat.Load(), poll.Load())
	}
}
