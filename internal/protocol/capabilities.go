package protocol

import (
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const CapabilitiesHeader = "X-Argus-Capabilities"

// Reported capabilities inform administrative preflight. They neither grant
// execution permission nor replace the Agent's local policy enforcement.
type AgentCapabilities struct {
	AgentVersion        string     `json:"agent_version"`
	ProtocolVersion     int        `json:"protocol_version"`
	PolicyVersion       int        `json:"policy_version"`
	PolicyHash          string     `json:"policy_hash"`
	SupportedCollectors []TaskType `json:"supported_collectors"`
	AllowedCollectors   []TaskType `json:"allowed_collectors"`
}

func (c AgentCapabilities) Validate() error {
	bad := errors.New("invalid agent capabilities")
	if !(AgentMetadata{ProtocolVersion: c.ProtocolVersion, AgentVersion: c.AgentVersion}).Valid() || c.PolicyVersion != 1 || !identity.Hex(c.PolicyHash, 64) || len(c.SupportedCollectors) < 1 || len(c.SupportedCollectors) > 6 || c.AllowedCollectors == nil || len(c.AllowedCollectors) > 6 {
		return bad
	}
	supported := map[TaskType]bool{}
	allowed := map[TaskType]bool{}
	for _, kind := range c.SupportedCollectors {
		if !KnownTask(kind) || supported[kind] {
			return bad
		}
		supported[kind] = true
	}
	for _, kind := range c.AllowedCollectors {
		if !supported[kind] || allowed[kind] {
			return bad
		}
		allowed[kind] = true
	}
	return nil
}

func DecodeAgentCapabilities(data []byte) (AgentCapabilities, error) {
	var c AgentCapabilities
	if err := strictjson.Decode(data, &c, 4096, "agent_version", "protocol_version", "policy_version", "policy_hash", "supported_collectors", "allowed_collectors"); err != nil {
		return c, err
	}
	return c, c.Validate()
}
