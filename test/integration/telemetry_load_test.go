package integration

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/agent"
	"github.com/Oreki0504/Argus-C2/internal/database"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/policy"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/transport"
)

// This accelerated workload uses 50 enrolled mTLS identities on one machine.
// It is deliberately opt-in; it cannot establish VPS or 72-hour acceptance.
func TestTelemetryFiftyNodeLoad(t *testing.T) {
	if os.Getenv("ARGUS_TELEMETRY_LOAD") != "1" {
		t.Skip("set ARGUS_TELEMETRY_LOAD=1 for the 50-node accelerated workload")
	}
	if runtime.GOOS != "linux" {
		t.Skip("Linux Agent diagnostic collector integration")
	}
	perNode := 1440
	if raw := os.Getenv("ARGUS_TELEMETRY_LOAD_SAMPLES"); raw != "" {
		var err error
		perNode, err = strconv.Atoi(raw)
		if err != nil || perNode < 2 || perNode > 43100 {
			t.Fatal("ARGUS_TELEMETRY_LOAD_SAMPLES must be 2..43100")
		}
	}
	f := newFleet(t)
	policy := policy.Default()
	policy.Telemetry.SampleMilliseconds = 100
	agents := make([]*agent.Runner, 50)
	for i := range agents {
		agents[i] = f.enroll(fmt.Sprintf("load-%02d", i), policy)
	}
	now := time.Now().Unix()
	startAt := now - int64(perNode-1)*60
	started := time.Now()
	var lock sync.Mutex
	latencies := []time.Duration{}
	errors := make(chan error, 50)
	workers := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, runner := range agents {
		wg.Go(func() {
			workers <- struct{}{}
			defer func() { <-workers }()
			boot := identity.RandomID()
			for offset := 0; offset < perNode; offset += 32 {
				batch := protocol.TelemetryBatch{SchemaVersion: 1, Samples: []protocol.TelemetrySample{}}
				for j := offset; j < min(offset+32, perNode); j++ {
					batch.Samples = append(batch.Samples, protocol.TelemetrySample{
						SampleID: fmt.Sprintf("load-%02d-%06d", i, j), BootID: boot, ObservedAt: startAt + int64(j)*60,
						AgentVersion: "load-test", IntervalSeconds: 60,
						System: protocol.SystemInformation{Available: true, OS: "linux", Architecture: "amd64", Hostname: "simulated", Kernel: "6.0.0", BootTime: startAt - 3600},
						Metrics: protocol.SystemMeasurements{
							CPU:      protocol.CPUStats{Available: true, BusyPercent: float64(10 + j%50), WindowMS: 100},
							Memory:   protocol.MemoryStats{Available: true, TotalBytes: 8 << 30, AvailableBytes: 4 << 30},
							Disks:    []protocol.DiskStats{{Path: "/", Available: true, TotalBytes: 100 << 30, AvailableBytes: 50 << 30}},
							Networks: []protocol.NetworkStats{{Interface: "eth0", Available: true, RXBytes: uint64(j) * 6000, TXBytes: uint64(j) * 12000}},
						}, Errors: []protocol.TelemetryCollectionError{},
					})
				}
				begin := time.Now()
				data, err := transport.Request(t.Context(), runner.Client, f.url, "", "POST", "/v1/agent/telemetry", batch)
				if err != nil {
					errors <- err
					return
				}
				var ack protocol.TelemetryAck
				if err = json.Unmarshal(data, &ack); err != nil || len(ack.SampleIDs) != len(batch.Samples) {
					errors <- fmt.Errorf("invalid batch acknowledgment: %v", err)
					return
				}
				lock.Lock()
				latencies = append(latencies, time.Since(begin))
				lock.Unlock()
				// Retry an already committed batch over the same identity/TLS client.
				if offset%128 == 0 {
					if _, err = transport.Request(t.Context(), runner.Client, f.url, "", "POST", "/v1/agent/telemetry", batch); err != nil {
						errors <- err
						return
					}
				}
			}
		})
	}
	// Real diagnostic tasks execute concurrently with the accelerated upload load.
	for _, runner := range agents[:5] {
		task := f.task(runner.Engine.State.NodeID, protocol.SystemInfo, "{}")
		if err := runner.Step(t.Context()); err != nil {
			t.Fatal(err)
		}
		view, err := f.store.Task(t.Context(), task.ID)
		if err != nil || view.Task.Status != protocol.Succeeded {
			t.Fatal("diagnostic failed during telemetry load", view, err)
		}
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	if t.Failed() {
		return
	}
	elapsed := time.Since(started)
	var count int
	if err := f.store.DB.QueryRow("SELECT count(*) FROM telemetry_samples WHERE agent_version='load-test'").Scan(&count); err != nil || count != 50*perNode {
		t.Fatal("lost or duplicated committed samples", count, err)
	}
	queryStarted := time.Now()
	for _, runner := range agents {
		page, err := f.store.QueryTelemetry(t.Context(), runner.Engine.State.NodeID, database.TelemetryQuery{From: startAt, To: now, Limit: 1000})
		if err != nil || len(page.Items) < 2 || page.Items[1].NetworkRates[0].RXBytesPerSecond != 100 {
			t.Fatal("history or counter rate failed", page, err)
		}
	}
	queryDuration := time.Since(queryStarted)
	backup := filepath.Join(f.dir, "telemetry-load-backup.db")
	if err := f.store.Backup(t.Context(), backup); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	report := map[string]any{
		"nodes": 50, "samples_per_node": perNode, "committed_samples": count,
		"simulated_interval_seconds": 60, "elapsed_seconds": elapsed.Seconds(),
		"batch_requests": len(latencies), "batch_latency_p95_ms": float64(latencies[(len(latencies)-1)*95/100].Microseconds()) / 1000,
		"fifty_history_queries_seconds": queryDuration.Seconds(), "snapshot_bytes": info.Size(),
		"process_go_heap_bytes": memory.HeapAlloc, "concurrent_real_diagnostics": 5,
		"limitations": "accelerated single-host mTLS workload; not a 72-hour soak or independent VPS deployment",
	}
	b, _ := json.Marshal(report)
	t.Log(string(b))
	if output := os.Getenv("ARGUS_TELEMETRY_LOAD_REPORT"); output != "" {
		if err := os.WriteFile(output, append(b, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
