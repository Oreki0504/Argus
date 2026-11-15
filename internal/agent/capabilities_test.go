package agent

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestCapabilitiesReportLocalPolicyAndThrottle(t *testing.T) {
	var received atomic.Int32
	r := telemetryRunner(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set(protocol.CapabilitiesHeader, "1")
		switch req.URL.Path {
		case "/v1/agent/heartbeat":
			io.WriteString(w, "{}")
		case "/v1/agent/poll":
			w.WriteHeader(204)
		case "/v1/agent/capabilities":
			raw, _ := io.ReadAll(req.Body)
			v, err := protocol.DecodeAgentCapabilities(raw)
			if err != nil || len(v.AllowedCollectors) != 0 || len(v.SupportedCollectors) != 6 || len(v.PolicyHash) != 64 || v.PolicyVersion != 1 {
				t.Errorf("invalid capabilities %+v %v", v, err)
			}
			received.Add(1)
			io.WriteString(w, "{}")
		default:
			t.Errorf("unexpected route %s", req.URL.Path)
			w.WriteHeader(404)
		}
	}))
	r.Engine.Policy.Allowed = []protocol.TaskType{}
	r.Engine.Policy.TelemetryRuntime = &policy.TelemetryRuntime{Enabled: false, IntervalSeconds: 60, BufferMaxBytes: 1024 * 1024}
	for range 2 {
		if err := r.Step(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if received.Load() != 1 {
		t.Fatal("capabilities not throttled", received.Load())
	}
	before, err := r.capabilities()
	if err != nil {
		t.Fatal(err)
	}
	r.Engine.Policy.Allowed = []protocol.TaskType{protocol.SystemInfo}
	after, err := r.capabilities()
	if err != nil || after.PolicyHash == before.PolicyHash {
		t.Fatal("policy change invisible", before, after, err)
	}
}

func TestBlockedCapabilitiesDoNotBlockHeartbeat(t *testing.T) {
	var heartbeat atomic.Int32
	started := make(chan struct{}, 1)
	r := telemetryRunner(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set(protocol.CapabilitiesHeader, "1")
		switch req.URL.Path {
		case "/v1/agent/heartbeat":
			heartbeat.Add(1)
			io.WriteString(w, "{}")
		case "/v1/agent/poll":
			w.WriteHeader(204)
		case "/v1/agent/capabilities":
			io.Copy(io.Discard, req.Body)
			select {
			case started <- struct{}{}:
			default:
			}
			<-req.Context().Done()
		default:
			t.Errorf("unexpected route %s", req.URL.Path)
			w.WriteHeader(404)
		}
	}))
	r.Engine.Policy.TelemetryRuntime = &policy.TelemetryRuntime{Enabled: false, IntervalSeconds: 60, BufferMaxBytes: 1024 * 1024}
	r.testHeartbeatInterval = 30 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("capabilities worker did not start")
	}
	deadline := time.Now().Add(2 * time.Second)
	for heartbeat.Load() < 4 {
		if time.Now().After(deadline) {
			t.Fatal("capabilities blocked heartbeat")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("capabilities worker did not stop")
	}
}
