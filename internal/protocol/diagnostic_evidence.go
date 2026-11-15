package protocol

import (
	"encoding/json"
	"errors"
	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const DiagnosticMetadataHeader = "X-Argus-Diagnostic-Metadata"

// DiagnosticEvidence describes data quality independently of execution state.
// Counts represent configured resources (or one collection channel for process
// and listener lists), not an assertion about the number of host resources.
type DiagnosticEvidence struct {
	Coverage           string `json:"coverage"`
	ResourcesTotal     int    `json:"resources_total"`
	ResourcesAvailable int    `json:"resources_available"`
	Truncated          bool   `json:"truncated"`
}

type DiagnosticCollection struct {
	ID               string `json:"id"`
	BootID           string `json:"boot_id"`
	CollectorVersion string `json:"collector_version"`
	StartedAt        int64  `json:"started_at"`
	CompletedAt      int64  `json:"completed_at"`
	DurationMS       int64  `json:"duration_ms"`
	DiagnosticEvidence
	ListenerProcesses *ListenerProcesses `json:"listener_processes,omitempty"`
}

func (c DiagnosticCollection) Validate(completed int64) error {
	if !identity.Valid(c.ID) || !identity.Valid(c.BootID) || !(AgentMetadata{ProtocolVersion: Version, AgentVersion: c.CollectorVersion}).Valid() || c.StartedAt < 1 || c.StartedAt > MaxUnixTime || c.CompletedAt != completed || c.DurationMS < 0 || !oneOf(c.Coverage, "complete", "partial", "unavailable") || c.ResourcesTotal < 0 || c.ResourcesTotal > 32 || c.ResourcesAvailable < 0 || c.ResourcesAvailable > c.ResourcesTotal {
		return errors.New("invalid diagnostic collection metadata")
	}
	if c.Coverage == "complete" && (c.ResourcesAvailable != c.ResourcesTotal || c.Truncated) || c.Coverage == "unavailable" && c.ResourcesAvailable != 0 {
		return errors.New("inconsistent diagnostic evidence")
	}
	if c.ListenerProcesses != nil {
		if err := c.ListenerProcesses.Validate(); err != nil {
			return err
		}
	}
	// Agent wall clock may move backwards during collection. DurationMS is
	// monotonic, so timestamp ordering is deliberately not used as a duration.
	return nil
}

func decodeDiagnosticCollection(raw []byte) (*DiagnosticCollection, error) {
	var c DiagnosticCollection
	fields := []string{"id", "boot_id", "collector_version", "started_at", "completed_at", "duration_ms", "coverage", "resources_total", "resources_available", "truncated"}
	if err := strictjson.Decode(raw, &c, MaxResultBytes, fields...); err != nil {
		if err = strictjson.Decode(raw, &c, MaxResultBytes, append(fields, "listener_processes")...); err != nil {
			return nil, err
		}
		var nested struct {
			ListenerProcesses json.RawMessage `json:"listener_processes"`
		}
		if err = json.Unmarshal(raw, &nested); err != nil {
			return nil, err
		}
		if c.ListenerProcesses, err = decodeListenerProcesses(nested.ListenerProcesses); err != nil {
			return nil, err
		}
	}
	return &c, nil
}

func DiagnosticEvidenceFor(task Task, result Result) (DiagnosticEvidence, error) {
	out := DiagnosticEvidence{Coverage: "unavailable"}
	if result.Status != Succeeded {
		return out, nil
	}
	available := func(ok bool) {
		out.ResourcesTotal++
		if ok {
			out.ResourcesAvailable++
		}
	}
	switch task.Type {
	case SystemInfo:
		v, err := DecodeInformation(result.Payload)
		if err != nil {
			return out, err
		}
		available(v.Available)
	case SystemMetrics:
		v, err := DecodeMeasurements(result.Payload)
		if err != nil {
			return out, err
		}
		available(v.CPU.Available)
		available(v.Memory.Available)
		for _, d := range v.Disks {
			available(d.Available)
		}
		for _, n := range v.Networks {
			available(n.Available)
		}
	case ServiceStatus:
		v, err := DecodeServiceReport(result.Payload, result.CompletedAt)
		if err != nil {
			return out, err
		}
		available(v.Available)
	case ProcessList:
		if err := ValidateProcesses(result.Payload); err != nil {
			return out, err
		}
		var v Processes
		json.Unmarshal(result.Payload, &v)
		available(v.Available)
		out.Truncated = v.Truncated
	case NetworkListeners:
		if err := ValidateListeners(result.Payload); err != nil {
			return out, err
		}
		var v Listeners
		json.Unmarshal(result.Payload, &v)
		available(v.Available)
		out.Truncated = v.Truncated
		out.Coverage = v.Coverage
		return out, nil
	case SSHAudit:
		v, err := DecodeSSHReport(result.Payload, result.CompletedAt)
		if err != nil {
			return out, err
		}
		for _, f := range v.Files {
			available(f.Status == "ok" || f.Status == "partial")
			for _, finding := range f.Findings {
				if oneOf(finding, "key_limit", "line_limit", "directive_limit") {
					out.Truncated = true
				}
			}
			if f.Status == "too_large" {
				out.Truncated = true
			}
		}
		out.Coverage = v.Coverage
		return out, nil
	default:
		return out, errors.New("unsupported diagnostic evidence")
	}
	if out.ResourcesAvailable > 0 {
		out.Coverage = "partial"
		if out.ResourcesAvailable == out.ResourcesTotal && !out.Truncated {
			out.Coverage = "complete"
		}
	}
	return out, nil
}
