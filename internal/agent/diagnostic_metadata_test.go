package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestDiagnosticMetadataSurvivesRestartAndDuplicateDelivery(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenState(dir, "node", true)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	engine := Engine{State: s, Policy: policy.Default(), BootID: "boot", ReportMetadata: true, Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
		calls++
		return goodPayload(), nil
	}}
	job := task("metadata")
	first, err := engine.Process(t.Context(), job, start)
	if err != nil || first.Collection == nil || first.Collection.Coverage != "unavailable" || first.Status != protocol.Succeeded {
		t.Fatal(first, err)
	}
	if err = first.CheckAssignment(job); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenState(dir, "node", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	engine.State = s
	engine.BootID = "new-boot"
	repeated, err := engine.Process(t.Context(), job, start)
	if err != nil || calls != 1 || repeated.Collection == nil || *repeated.Collection != *first.Collection {
		t.Fatal("metadata regenerated during retry", first, repeated, calls, err)
	}
	engine.Policy.Allowed = []protocol.TaskType{}
	denied, err := engine.Process(t.Context(), task("denied"), start)
	if err != nil || denied.Collection != nil || denied.Error != "local_policy_denied" {
		t.Fatal("policy rejection invented collection", denied, err)
	}
}

func TestRunnerNegotiatesDiagnosticMetadataWithServer(t *testing.T) {
	for _, supported := range []bool{false, true} {
		t.Run(map[bool]string{false: "legacy", true: "supported"}[supported], func(t *testing.T) {
			var received atomic.Bool
			r := telemetryRunner(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if supported {
					w.Header().Set(protocol.DiagnosticMetadataHeader, "1")
				}
				switch req.URL.Path {
				case "/v1/agent/heartbeat", "/v1/agent/tasks/metadata/running":
					io.WriteString(w, "{}")
				case "/v1/agent/poll":
					json.NewEncoder(w).Encode(task("metadata"))
				case "/v1/agent/results":
					raw, _ := io.ReadAll(req.Body)
					result, err := protocol.DecodeResult(raw)
					if err != nil || (result.Collection != nil) != supported {
						t.Errorf("metadata negotiation failed %+v %v", result, err)
					}
					received.Store(true)
					io.WriteString(w, "{}")
				default:
					t.Errorf("unexpected route %s", req.URL.Path)
					w.WriteHeader(404)
				}
			}))
			r.Engine.Policy.TelemetryRuntime = &policy.TelemetryRuntime{Enabled: false, IntervalSeconds: 60, BufferMaxBytes: 1024 * 1024}
			r.Engine.Execute = func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
				return goodPayload(), nil
			}
			if err := r.Step(t.Context()); err != nil {
				t.Fatal(err)
			}
			if !received.Load() {
				t.Fatal("result not delivered")
			}
		})
	}
}

func TestOptionalAssociationTimeoutPreservesPrimaryEvidence(t *testing.T) {
	s, err := OpenState(filepath.Join(t.TempDir(), "state"), "node", true)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	p := policy.Default()
	p.Allowed = append(p.Allowed, protocol.NetworkListeners)
	engine := Engine{State: s, Policy: p, BootID: "boot", ReportMetadata: true,
		Execute: func(context.Context, protocol.Task, policy.Policy) (json.RawMessage, error) {
			return json.RawMessage(`{"available":true,"coverage":"complete","truncated":false,"items":[]}`), nil
		},
		associate: func(ctx context.Context, _ protocol.Listeners) protocol.ListenerProcesses {
			<-ctx.Done()
			return protocol.ListenerProcesses{Coverage: "partial", Items: []protocol.ListenerProcess{}}
		},
	}
	job := task("association-timeout")
	job.Type = protocol.NetworkListeners
	job.ExecutionTimeoutMS = 20
	result, err := engine.Process(t.Context(), job, start)
	if err != nil || result.Status != protocol.Succeeded || result.Collection == nil || result.Collection.ListenerProcesses == nil || result.Collection.ListenerProcesses.Coverage != "partial" {
		t.Fatal("optional collection erased valid primary report", result, err)
	}
	if err = result.CheckAssignment(job); err != nil {
		t.Fatal(err)
	}
}
