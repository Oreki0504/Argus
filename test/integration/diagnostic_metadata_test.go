package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestDiagnosticMetadataSurvivesServerAndAgentRestartAfterLostACK(t *testing.T) {
	f := newFleet(t)
	p := policy.Default()
	p.TelemetryRuntime = &policy.TelemetryRuntime{Enabled: false, IntervalSeconds: 60, BufferMaxBytes: 1024 * 1024}
	r := f.enroll("metadata", p)
	job := f.task(r.Engine.State.NodeID, protocol.SystemInfo, "{}")
	calls := 0
	r.Engine.Execute = func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		calls++
		return json.RawMessage(`{"available":false,"os":"linux","architecture":"amd64","hostname":"","kernel":"","boot_time":0}`), nil
	}
	base := r.Client.Transport
	r.Client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		response, err := base.RoundTrip(req)
		if err == nil && req.URL.Path == "/v1/agent/results" {
			response.Body.Close()
			return nil, errors.New("injected lost result acknowledgment")
		}
		return response, err
	})
	if err := r.Step(t.Context()); err == nil {
		t.Fatal("lost ACK not simulated")
	}
	stored, err := f.store.Task(t.Context(), job.ID)
	if err != nil || stored.Result == nil || stored.Result.Collection == nil {
		t.Fatal("metadata not committed with result", stored, err)
	}
	metadata := *stored.Result.Collection
	dir, ca := r.Dir, r.CA
	r.Close()
	address := f.server.Listener.Addr().String()
	f.server.Close()
	f.store.Close()
	f.store, err = database.Open(filepath.Join(f.dir, "state"), false)
	if err != nil {
		t.Fatal(err)
	}
	f.start(address)
	r, err = agent.Open(f.url, ca, dir, p)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.Engine.Execute = func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		t.Fatal("completed collector reran after ACK loss")
		return nil, nil
	}
	if err = r.Step(t.Context()); err != nil {
		t.Fatal("exact retry rejected after restart", err)
	}
	stored, err = f.store.Task(t.Context(), job.ID)
	if err != nil || stored.Result == nil || stored.Result.Collection == nil || *stored.Result.Collection != metadata || calls != 1 {
		t.Fatal("metadata changed", stored, err)
	}
	pending, err := r.Engine.State.Pending(t.Context())
	if err != nil || len(pending) != 0 {
		t.Fatal("committed retry not acknowledged", pending, err)
	}
	changed := *stored.Result
	replacement := *changed.Collection
	replacement.ID = "different"
	changed.Collection = &replacement
	if err = f.store.SubmitResult(t.Context(), nodeCertificate(t, r), changed); !errors.Is(err, database.ErrResultConflict) {
		t.Fatal("changed collection accepted", err)
	}
}
