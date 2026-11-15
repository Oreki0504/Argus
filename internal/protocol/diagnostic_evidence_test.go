package protocol

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticMetadataStrictCompatibilityAndEvidence(t *testing.T) {
	now := time.Now().Unix()
	task := Task{ID: "task", NodeID: "node", Type: SystemMetrics}
	metrics := SystemMeasurements{CPU: CPUStats{Available: true, BusyPercent: 20, WindowMS: 100}, Memory: MemoryStats{}, Disks: []DiskStats{{Path: "/", Available: true, TotalBytes: 100, AvailableBytes: 50}}, Networks: []NetworkStats{}}
	payload, err := json.Marshal(metrics)
	if err != nil {
		t.Fatal(err)
	}
	result := Result{TaskID: task.ID, NodeID: task.NodeID, Status: Succeeded, Payload: payload, CompletedAt: now}
	legacy, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResult(legacy)
	if err != nil || decoded.Collection != nil {
		t.Fatal("legacy report rejected", decoded, err)
	}
	evidence, err := DiagnosticEvidenceFor(task, result)
	if err != nil || evidence.Coverage != "partial" || evidence.ResourcesTotal != 3 || evidence.ResourcesAvailable != 2 {
		t.Fatal(evidence, err)
	}
	result.Collection = &DiagnosticCollection{ID: "collection", BootID: "boot", CollectorVersion: "test", StartedAt: now + 1, CompletedAt: now, DurationMS: 100, DiagnosticEvidence: evidence}
	// A wall-clock correction does not invalidate a monotonic measured duration.
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err = DecodeResult(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err = decoded.CheckAssignment(task); err != nil {
		t.Fatal(err)
	}
	if same, err := EquivalentResults(task, result, decoded); err != nil || !same {
		t.Fatal(same, err)
	}
	for _, changed := range []string{
		strings.Replace(string(raw), `"duration_ms":100`, `"duration_ms":100,"remote_override":true`, 1),
		strings.Replace(string(raw), `"duration_ms":100,`, "", 1),
		strings.Replace(string(raw), `"duration_ms":100`, `"duration_ms":-1`, 1),
	} {
		if _, err := DecodeResult([]byte(changed)); err == nil {
			t.Fatal("invalid metadata accepted", changed)
		}
	}
	changed := result
	metadata := *result.Collection
	changed.Collection = &metadata
	changed.Collection.ID = "other"
	if same, err := EquivalentResults(task, result, changed); err != nil || same {
		t.Fatal("metadata identity not immutable", same, err)
	}
	changed.Collection.Coverage = "complete"
	changed.Collection.ResourcesAvailable = changed.Collection.ResourcesTotal
	if err = changed.CheckAssignment(task); err == nil {
		t.Fatal("partial evidence overstated")
	}
	if same, err := EquivalentResults(task, result, Result{TaskID: task.ID, NodeID: task.NodeID, Status: Succeeded, Payload: payload, CompletedAt: now}); err != nil || same {
		t.Fatal("metadata silently stripped", same, err)
	}
}

func TestDiagnosticEvidenceDistinguishesUnavailablePartialAndTruncation(t *testing.T) {
	cases := []struct {
		kind      TaskType
		payload   string
		coverage  string
		truncated bool
	}{
		{ProcessList, `{"available":true,"truncated":true,"items":[]}`, "partial", true},
		{ProcessList, `{"available":true,"truncated":false,"items":[]}`, "complete", false},
		{ProcessList, `{"available":false,"truncated":false,"items":[]}`, "unavailable", false},
		{NetworkListeners, `{"available":true,"truncated":false,"coverage":"partial","items":[]}`, "partial", false},
		{SystemInfo, `{"available":false,"os":"linux","architecture":"amd64","hostname":"","kernel":"","boot_time":0}`, "unavailable", false},
	}
	for _, tc := range cases {
		evidence, err := DiagnosticEvidenceFor(Task{Type: tc.kind}, Result{Status: Succeeded, Payload: json.RawMessage(tc.payload), CompletedAt: time.Now().Unix()})
		if err != nil || evidence.Coverage != tc.coverage || evidence.Truncated != tc.truncated {
			t.Fatal(tc, evidence, err)
		}
	}
	evidence, err := DiagnosticEvidenceFor(Task{Type: SystemMetrics}, Result{Status: Failed, Error: "local_policy_denied", Payload: json.RawMessage(`{}`)})
	if err != nil || evidence.ResourcesTotal != 0 || evidence.Coverage != "unavailable" {
		t.Fatal("failed execution invented coverage", evidence, err)
	}
}

func TestListenerAssociationsMustMatchObservedEndpoint(t *testing.T) {
	now := time.Now().Unix()
	job := Task{ID: "task", NodeID: "node", Type: NetworkListeners}
	result := Result{TaskID: "task", NodeID: "node", Status: Succeeded, CompletedAt: now, Payload: json.RawMessage(`{"available":true,"truncated":false,"coverage":"complete","items":[{"protocol":"tcp","address":"127.0.0.1","port":22}]}`)}
	evidence, err := DiagnosticEvidenceFor(job, result)
	if err != nil {
		t.Fatal(err)
	}
	result.Collection = &DiagnosticCollection{ID: "collection", BootID: "boot", CollectorVersion: "test", StartedAt: now, CompletedAt: now, DiagnosticEvidence: evidence, ListenerProcesses: &ListenerProcesses{Coverage: "partial", ScannedProcesses: 1, ScannedFDs: 1, Items: []ListenerProcess{{Protocol: "tcp", Address: "127.0.0.1", Port: 22, PID: 123, ProcessName: "service", ProcessStartTicks: "9007199254740993", SocketInode: "99"}}}}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeResult(raw)
	if err != nil || decoded.Collection.ListenerProcesses.Items[0].ProcessStartTicks != "9007199254740993" {
		t.Fatal(decoded, err)
	}
	if err = decoded.CheckAssignment(job); err != nil {
		t.Fatal(err)
	}
	decoded.Collection.ListenerProcesses.Items[0].Port = 80
	if err = decoded.CheckAssignment(job); err == nil {
		t.Fatal("unobserved endpoint accepted")
	}
	modified := strings.Replace(string(raw), `"socket_inode":"99"`, `"socket_inode":"99","execute":"shell"`, 1)
	if _, err = DecodeResult([]byte(modified)); err == nil {
		t.Fatal("unknown association field accepted")
	}
}
