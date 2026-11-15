package protocol

import (
	"encoding/json"
	"errors"
	"sort"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const TelemetrySchemaVersion = 1
const MaxTelemetryBatchSamples = 32
const MaxTelemetryBatchBytes = 512 * 1024
const MaxTelemetrySampleBytes = 16 * 1024
const TelemetryFutureSkewSeconds = 300
const TelemetryRetentionSeconds = 30 * 24 * 60 * 60

// Telemetry is an observation stream, independent of diagnostic assignments.
// Node identity is taken exclusively from the authenticated client certificate.
type TelemetryBatch struct {
	SchemaVersion int               `json:"schema_version"`
	Samples       []TelemetrySample `json:"samples"`
}

type TelemetrySample struct {
	SampleID        string                     `json:"sample_id"`
	BootID          string                     `json:"boot_id"`
	ObservedAt      int64                      `json:"observed_at"`
	AgentVersion    string                     `json:"agent_version"`
	IntervalSeconds int                        `json:"interval_seconds"`
	Metrics         SystemMeasurements         `json:"metrics"`
	System          SystemInformation          `json:"system"`
	Agent           TelemetryAgentHealth       `json:"agent"`
	Errors          []TelemetryCollectionError `json:"errors"`
}

type TelemetryAgentHealth struct {
	UptimeSeconds   int64  `json:"uptime_seconds"`
	BufferedSamples int    `json:"buffered_samples"`
	DroppedSamples  uint64 `json:"dropped_samples"`
}

type TelemetryCollectionError struct {
	ResourceID string `json:"resource_id"`
	Code       string `json:"code"`
}

type TelemetryAck struct {
	SampleIDs []string `json:"sample_ids"`
}

func (s TelemetrySample) Validate() error {
	bad := errors.New("invalid telemetry sample")
	if !identity.Valid(s.SampleID) || !identity.Valid(s.BootID) || s.ObservedAt <= 0 ||
		!(AgentMetadata{ProtocolVersion: Version, AgentVersion: s.AgentVersion}).Valid() ||
		s.IntervalSeconds < 30 || s.IntervalSeconds > 300 || s.Agent.UptimeSeconds < 0 ||
		s.Agent.BufferedSamples < 0 || s.Agent.BufferedSamples > 2000 || s.Errors == nil || len(s.Errors) > 32 {
		return bad
	}
	if err := s.Metrics.Validate(); err != nil {
		return err
	}
	if err := s.System.Validate(s.ObservedAt); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, e := range s.Errors {
		if e.ResourceID == "" || !CleanText(e.ResourceID, 256) || seen[e.ResourceID+"\x00"+e.Code] {
			return bad
		}
		switch e.Code {
		case "unavailable", "permission_denied", "timeout", "collection_failed", "storage_pressure":
		default:
			return bad
		}
		seen[e.ResourceID+"\x00"+e.Code] = true
	}
	return nil
}

// CanonicalTelemetrySample compares the logical observation, not JSON spelling
// or resource enumeration order. Integer counters remain exact uint64 values.
func CanonicalTelemetrySample(s TelemetrySample) ([]byte, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	s.Metrics.Disks = append([]DiskStats{}, s.Metrics.Disks...)
	s.Metrics.Networks = append([]NetworkStats{}, s.Metrics.Networks...)
	s.Errors = append([]TelemetryCollectionError{}, s.Errors...)
	sort.Slice(s.Metrics.Disks, func(i, j int) bool { return s.Metrics.Disks[i].Path < s.Metrics.Disks[j].Path })
	sort.Slice(s.Metrics.Networks, func(i, j int) bool { return s.Metrics.Networks[i].Interface < s.Metrics.Networks[j].Interface })
	sort.Slice(s.Errors, func(i, j int) bool {
		if s.Errors[i].ResourceID == s.Errors[j].ResourceID {
			return s.Errors[i].Code < s.Errors[j].Code
		}
		return s.Errors[i].ResourceID < s.Errors[j].ResourceID
	})
	if s.Metrics.CPU.BusyPercent == 0 {
		s.Metrics.CPU.BusyPercent = 0 // Normalize negative zero.
	}
	b, err := json.Marshal(s)
	if err == nil && len(b) > MaxTelemetrySampleBytes {
		return nil, errors.New("telemetry sample exceeds size limit")
	}
	return b, err
}

func DecodeTelemetrySample(data []byte) (TelemetrySample, error) {
	var s TelemetrySample
	var raw struct {
		SampleID        string            `json:"sample_id"`
		BootID          string            `json:"boot_id"`
		ObservedAt      int64             `json:"observed_at"`
		AgentVersion    string            `json:"agent_version"`
		IntervalSeconds int               `json:"interval_seconds"`
		Metrics         json.RawMessage   `json:"metrics"`
		System          json.RawMessage   `json:"system"`
		Agent           json.RawMessage   `json:"agent"`
		Errors          []json.RawMessage `json:"errors"`
	}
	if err := strictjson.Decode(data, &raw, MaxTelemetrySampleBytes, "sample_id", "boot_id", "observed_at", "agent_version", "interval_seconds", "metrics", "system", "agent", "errors"); err != nil {
		return s, err
	}
	s = TelemetrySample{SampleID: raw.SampleID, BootID: raw.BootID, ObservedAt: raw.ObservedAt, AgentVersion: raw.AgentVersion, IntervalSeconds: raw.IntervalSeconds, Errors: []TelemetryCollectionError{}}
	var err error
	if s.Metrics, err = DecodeMeasurements(raw.Metrics); err != nil {
		return s, err
	}
	if s.System, err = DecodeInformation(raw.System); err != nil {
		return s, err
	}
	if err = strictjson.Decode(raw.Agent, &s.Agent, 512, "uptime_seconds", "buffered_samples", "dropped_samples"); err != nil {
		return s, err
	}
	if len(raw.Errors) > 32 {
		return s, errors.New("too many telemetry collection errors")
	}
	for _, data := range raw.Errors {
		var e TelemetryCollectionError
		if err = strictjson.Decode(data, &e, 2048, "resource_id", "code"); err != nil {
			return s, err
		}
		s.Errors = append(s.Errors, e)
	}
	return s, s.Validate()
}

func DecodeTelemetryBatch(data []byte) (TelemetryBatch, error) {
	var raw struct {
		SchemaVersion int               `json:"schema_version"`
		Samples       []json.RawMessage `json:"samples"`
	}
	b := TelemetryBatch{Samples: []TelemetrySample{}}
	if err := strictjson.Decode(data, &raw, MaxTelemetryBatchBytes, "schema_version", "samples"); err != nil {
		return b, err
	}
	if raw.SchemaVersion != TelemetrySchemaVersion || len(raw.Samples) < 1 || len(raw.Samples) > MaxTelemetryBatchSamples {
		return b, errors.New("invalid telemetry schema or batch size")
	}
	b.SchemaVersion = raw.SchemaVersion
	seen := map[string]bool{}
	for _, data := range raw.Samples {
		s, err := DecodeTelemetrySample(data)
		if err != nil {
			return b, err
		}
		if seen[s.SampleID] {
			return b, errors.New("duplicate sample ID in telemetry batch")
		}
		seen[s.SampleID] = true
		b.Samples = append(b.Samples, s)
	}
	return b, nil
}
