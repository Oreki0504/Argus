package database

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

const capabilitiesSchema = `
CREATE TABLE agent_capabilities(
 node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
 agent_version TEXT NOT NULL,protocol_version INTEGER NOT NULL,policy_version INTEGER NOT NULL,policy_hash TEXT NOT NULL,
 supported_collectors TEXT NOT NULL CHECK(json_valid(supported_collectors)),
 allowed_collectors TEXT NOT NULL CHECK(json_valid(allowed_collectors)),reported_at INTEGER NOT NULL
);
`

var ErrInvalidCapabilities = errors.New("invalid agent capability report")

type ReportedCapabilities struct {
	protocol.AgentCapabilities
	ReportedAt int64 `json:"reported_at"`
}

func (s *Store) ReportCapabilities(ctx context.Context, cert *x509.Certificate, c protocol.AgentCapabilities) error {
	if err := c.Validate(); err != nil {
		return ErrInvalidCapabilities
	}
	supported, _ := json.Marshal(c.SupportedCollectors)
	allowed, _ := json.Marshal(c.AllowedCollectors)
	return s.Write(ctx, func(tx *sql.Tx) error {
		node, err := Authorize(ctx, tx, cert)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO agent_capabilities(node_id,agent_version,protocol_version,policy_version,policy_hash,supported_collectors,allowed_collectors,reported_at) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(node_id) DO UPDATE SET agent_version=excluded.agent_version,protocol_version=excluded.protocol_version,policy_version=excluded.policy_version,policy_hash=excluded.policy_hash,supported_collectors=excluded.supported_collectors,allowed_collectors=excluded.allowed_collectors,reported_at=excluded.reported_at`, node, c.AgentVersion, c.ProtocolVersion, c.PolicyVersion, c.PolicyHash, string(supported), string(allowed), s.now().Unix())
		return err
	})
}

func (s *Store) Capabilities(ctx context.Context, node string) (*ReportedCapabilities, error) {
	var c ReportedCapabilities
	var supported, allowed []byte
	err := s.DB.QueryRowContext(ctx, "SELECT agent_version,protocol_version,policy_version,policy_hash,supported_collectors,allowed_collectors,reported_at FROM agent_capabilities WHERE node_id=?", node).Scan(&c.AgentVersion, &c.ProtocolVersion, &c.PolicyVersion, &c.PolicyHash, &supported, &allowed, &c.ReportedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(supported, &c.SupportedCollectors); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(allowed, &c.AllowedCollectors); err != nil {
		return nil, err
	}
	return &c, c.Validate()
}
