package protocol

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func telemetryFixture() TelemetrySample {
	return TelemetrySample{SampleID: "sample-1", BootID: "boot-1", ObservedAt: 1700000000, AgentVersion: "test", IntervalSeconds: 60,
		Metrics: SystemMeasurements{CPU: CPUStats{true, 12.5, 1000}, Memory: MemoryStats{true, 1<<63 + 1, 1<<62 + 1}, Disks: []DiskStats{{"/", true, 1000, 500}}, Networks: []NetworkStats{{"eth0", true, 1<<63 + 1, 1<<63 + 2}}},
		System:  SystemInformation{Available: true, OS: "linux", Architecture: "amd64", Hostname: "test", Kernel: "test", BootTime: 1600000000}, Errors: []TelemetryCollectionError{}}
}

func TestTelemetryStrictSchemaAndExactCounters(t *testing.T) {
	b := TelemetryBatch{TelemetrySchemaVersion, []TelemetrySample{telemetryFixture()}}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeTelemetryBatch(raw)
	if err != nil || got.Samples[0].Metrics.Networks[0].RXBytes != 1<<63+1 {
		t.Fatal(got, err)
	}
	for _, change := range [][2]string{
		{`"schema_version":1`, `"schema_version":2`},
		{`"sample_id":"sample-1"`, `"sample_id":"../bad"`},
		{`"sample_id":"sample-1"`, `"node_id":"other","sample_id":"sample-1"`},
		{`"boot_id":"boot-1"`, `"boot_id":null`},
		{`"observed_at":1700000000`, `"observed_at":0`},
		{`"interval_seconds":60`, `"interval_seconds":29`},
		{`"interval_seconds":60`, `"interval_seconds":301`},
		{`"uptime_seconds":0`, `"uptime_seconds":0,"uptime_seconds":1`},
		{`"uptime_seconds":0`, `"uptime_seconds":-1`},
		{`"errors":[]`, `"errors":[{"resource_id":"cpu","code":"secret detail"}]`},
		{`"errors":[]`, `"errors":[{"resource_id":"cpu","code":"timeout","detail":"x"}]`},
		{`"errors":[]`, `"errors":null`},
		{`"disks":[{`, `"disks":null,"ignored":[{`},
		{`"networks":[{`, `"networks":null,"ignored":[{`},
		{`"rx_bytes":9223372036854775809`, `"rx_bytes":18446744073709551616`},
		{`"busy_percent":12.5`, `"busy_percent":101`},
		{`"boot_time":1600000000`, `"boot_time":1800000000`},
	} {
		bad := strings.Replace(string(raw), change[0], change[1], 1)
		if bad == string(raw) {
			t.Fatal("invalid test replacement", change)
		}
		if _, err := DecodeTelemetryBatch([]byte(bad)); err == nil {
			t.Fatal("invalid telemetry accepted", change)
		}
	}
	b.Samples = append(b.Samples, b.Samples[0])
	raw, _ = json.Marshal(b)
	if _, err := DecodeTelemetryBatch(raw); err == nil {
		t.Fatal("duplicate batch ID accepted")
	}
	b.Samples = []TelemetrySample{}
	raw, _ = json.Marshal(b)
	if _, err := DecodeTelemetryBatch(raw); err == nil {
		t.Fatal("empty batch accepted")
	}
}

func TestTelemetryCanonicalResourceOrder(t *testing.T) {
	s := telemetryFixture()
	s.Metrics.Networks = append(s.Metrics.Networks, NetworkStats{"eth1", true, 12, 13})
	s.Errors = []TelemetryCollectionError{{"cpu", "unavailable"}, {"memory", "timeout"}}
	first, err := CanonicalTelemetrySample(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Metrics.Networks[0], s.Metrics.Networks[1] = s.Metrics.Networks[1], s.Metrics.Networks[0]
	s.Errors[0], s.Errors[1] = s.Errors[1], s.Errors[0]
	second, err := CanonicalTelemetrySample(s)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("enumeration order changed identity", err)
	}
	s.Metrics.Networks[1].RXBytes++
	third, _ := CanonicalTelemetrySample(s)
	if bytes.Equal(second, third) {
		t.Fatal("exact large-counter difference lost")
	}
}

func FuzzDecodeTelemetryBatch(f *testing.F) {
	b, _ := json.Marshal(TelemetryBatch{TelemetrySchemaVersion, []TelemetrySample{telemetryFixture()}})
	f.Add(b)
	f.Fuzz(func(t *testing.T, data []byte) {
		batch, err := DecodeTelemetryBatch(data)
		if err != nil {
			return
		}
		for _, sample := range batch.Samples {
			if _, err := CanonicalTelemetrySample(sample); err != nil {
				t.Fatal(err)
			}
		}
	})
}
