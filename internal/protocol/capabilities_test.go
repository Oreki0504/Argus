package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCapabilitiesStrictAndInformational(t *testing.T) {
	c := AgentCapabilities{AgentVersion: "test", ProtocolVersion: 1, PolicyVersion: 1, PolicyHash: strings.Repeat("a", 64), SupportedCollectors: []TaskType{SystemInfo, SystemMetrics}, AllowedCollectors: []TaskType{SystemInfo}}
	raw, _ := json.Marshal(c)
	if _, err := DecodeAgentCapabilities(raw); err != nil {
		t.Fatal(err)
	}
	for _, change := range [][2]string{{`"policy_version":1`, `"policy_version":2`}, {`"protocol_version":1`, `"protocol_version":2`}, {`"allowed_collectors":["system.info"]`, `"allowed_collectors":["ssh.audit"]`}, {`"allowed_collectors":["system.info"]`, `"allowed_collectors":["system.info","system.info"]`}, {`"allowed_collectors":["system.info"]`, `"allowed_collectors":null`}, {`"policy_hash":`, `"grant":true,"policy_hash":`}} {
		bad := strings.Replace(string(raw), change[0], change[1], 1)
		if _, err := DecodeAgentCapabilities([]byte(bad)); err == nil {
			t.Fatal("invalid report accepted", change)
		}
	}
	c.AllowedCollectors = []TaskType{}
	if err := c.Validate(); err != nil {
		t.Fatal("deny-all policy invisible", err)
	}
}
