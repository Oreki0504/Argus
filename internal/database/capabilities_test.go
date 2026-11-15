package database

import (
	"errors"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestCapabilityReportsCannotGrantExecutionOrSurviveRevocation(t *testing.T) {
	s := fixture(t)
	cert := telemetryCertificate(t, s)
	if c, err := s.Capabilities(t.Context(), "node"); err != nil || c != nil {
		t.Fatal(c, err)
	}
	c := protocol.AgentCapabilities{AgentVersion: "test", ProtocolVersion: 1, PolicyVersion: 1, PolicyHash: strings.Repeat("b", 64), SupportedCollectors: []protocol.TaskType{protocol.SystemInfo}, AllowedCollectors: []protocol.TaskType{}}
	if err := s.ReportCapabilities(t.Context(), cert, c); err != nil {
		t.Fatal(err)
	}
	got, err := s.Capabilities(t.Context(), "node")
	if err != nil || got == nil || got.PolicyHash != c.PolicyHash || got.ReportedAt <= 0 || len(got.AllowedCollectors) != 0 {
		t.Fatal(got, err)
	}
	// Reporting capabilities never creates tasks, running grants or results.
	for _, table := range []string{"tasks", "results"} {
		if historyCount(t, s, table) != 0 {
			t.Fatal("capability report changed execution state", table)
		}
	}
	if err = s.RevokeNode(t.Context(), "admin", "node"); err != nil {
		t.Fatal(err)
	}
	if err = s.ReportCapabilities(t.Context(), cert, c); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("revoked node reported capabilities", err)
	}
	if err = s.DeleteConsoleNode(t.Context(), "admin", "node"); err != nil {
		t.Fatal(err)
	}
	if historyCount(t, s, "agent_capabilities") != 0 || historyCount(t, s, "node_revocations") != 0 {
		t.Fatal("deleted node metadata retained")
	}
}
