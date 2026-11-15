package protocol

import (
	"encoding/json"
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type DiagnosticProfile struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Collectors       []TaskType `json:"collectors"`
	RequiresResource bool       `json:"requires_resource"`
}

// Profiles contain fixed read-only collectors only, never remote executable text.
func DiagnosticProfiles() []DiagnosticProfile {
	return []DiagnosticProfile{
		{"overview", "System investigation", []TaskType{SystemInfo, SystemMetrics, ProcessList, NetworkListeners}, false},
		{"system", "System snapshot", []TaskType{SystemInfo, SystemMetrics}, false},
		{"service", "Service status", []TaskType{ServiceStatus}, true},
		{"security", "SSH configuration audit", []TaskType{SSHAudit}, true},
	}
}

type DiagnosticRequest struct {
	NodeIDs            []string `json:"node_ids"`
	ProfileID          string   `json:"profile_id"`
	ResourceID         string   `json:"resource_id"`
	TTLSeconds         int      `json:"ttl_seconds"`
	ExecutionTimeoutMS int      `json:"execution_timeout_ms"`
}

func (r DiagnosticRequest) Profile() (DiagnosticProfile, error) {
	for _, profile := range DiagnosticProfiles() {
		if profile.ID == r.ProfileID {
			return profile, nil
		}
	}
	return DiagnosticProfile{}, errors.New("unknown diagnostic profile")
}

func (r DiagnosticRequest) Tasks() ([]TaskRequest, error) {
	p, err := r.Profile()
	if err != nil {
		return nil, err
	}
	if len(r.NodeIDs) < 1 || len(r.NodeIDs) > 50 || p.RequiresResource && !ResourceID(r.ResourceID) || !p.RequiresResource && r.ResourceID != "" {
		return nil, errors.New("invalid diagnostic nodes or resource")
	}
	seen := map[string]bool{}
	out := []TaskRequest{}
	for _, node := range r.NodeIDs {
		if !identity.Valid(node) || seen[node] {
			return nil, errors.New("invalid or duplicate diagnostic node")
		}
		seen[node] = true
		for _, kind := range p.Collectors {
			params := json.RawMessage(`{}`)
			if p.RequiresResource {
				key := "service_id"
				if kind == SSHAudit {
					key = "profile_id"
				}
				params, _ = json.Marshal(map[string]string{key: r.ResourceID})
			}
			task := TaskRequest{NodeID: node, Type: kind, Params: params, TTLSeconds: r.TTLSeconds, ExecutionTimeoutMS: r.ExecutionTimeoutMS}
			b, _ := json.Marshal(task)
			if _, err = DecodeTaskRequest(b); err != nil {
				return nil, err
			}
			out = append(out, task)
		}
	}
	return out, nil
}

func DecodeDiagnosticRequest(data []byte) (DiagnosticRequest, error) {
	var r DiagnosticRequest
	if err := strictjson.Decode(data, &r, MaxPayloadBytes, "node_ids", "profile_id", "resource_id", "ttl_seconds", "execution_timeout_ms"); err != nil {
		return r, err
	}
	_, err := r.Tasks()
	return r, err
}
