//go:build !linux

package network

import (
	"context"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func AssociateProcesses(context.Context, protocol.Listeners) protocol.ListenerProcesses {
	return protocol.ListenerProcesses{Coverage: "unavailable", Items: []protocol.ListenerProcess{}}
}
