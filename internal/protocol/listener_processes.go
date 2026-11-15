package protocol

import (
	"encoding/json"
	"errors"
	"net"
	"strconv"

	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

type ListenerProcess struct {
	Protocol          string `json:"protocol"`
	Address           string `json:"address"`
	Port              uint16 `json:"port"`
	PID               int    `json:"pid"`
	ProcessName       string `json:"process_name"`
	ProcessStartTicks string `json:"process_start_ticks"`
	SocketInode       string `json:"socket_inode"`
}

type ListenerProcesses struct {
	Coverage         string            `json:"coverage"`
	ScannedProcesses int               `json:"scanned_processes"`
	ScannedFDs       int               `json:"scanned_fds"`
	Items            []ListenerProcess `json:"items"`
}

func (p ListenerProcesses) Validate() error {
	if !oneOf(p.Coverage, "complete", "partial", "unavailable") || p.ScannedProcesses < 0 || p.ScannedProcesses > 4096 || p.ScannedFDs < 0 || p.ScannedFDs > 16384 || p.Items == nil || len(p.Items) > 128 || p.Coverage == "unavailable" && len(p.Items) > 0 {
		return errors.New("invalid listener process coverage")
	}
	seen := map[string]bool{}
	for _, item := range p.Items {
		start, e1 := strconv.ParseUint(item.ProcessStartTicks, 10, 64)
		inode, e2 := strconv.ParseUint(item.SocketInode, 10, 64)
		if !oneOf(item.Protocol, "tcp", "tcp6", "udp", "udp6") || net.ParseIP(item.Address) == nil || item.Port == 0 || item.PID < 1 || !CleanText(item.ProcessName, 64) || e1 != nil || e2 != nil || start == 0 || inode == 0 || strconv.FormatUint(start, 10) != item.ProcessStartTicks || strconv.FormatUint(inode, 10) != item.SocketInode {
			return errors.New("invalid listener process identity")
		}
		key := item.Protocol + "/" + item.Address + "/" + strconv.Itoa(int(item.Port)) + "/" + strconv.Itoa(item.PID) + "/" + item.SocketInode
		if seen[key] {
			return errors.New("duplicate listener process identity")
		}
		seen[key] = true
	}
	return nil
}

func decodeListenerProcesses(raw []byte) (*ListenerProcesses, error) {
	var p ListenerProcesses
	if err := strictjson.Decode(raw, &p, MaxResultBytes, "coverage", "scanned_processes", "scanned_fds", "items"); err != nil {
		return nil, err
	}
	var nested struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(raw, &nested); err != nil {
		return nil, err
	}
	for _, item := range nested.Items {
		var value ListenerProcess
		if err := strictjson.Decode(item, &value, 1024, "protocol", "address", "port", "pid", "process_name", "process_start_ticks", "socket_inode"); err != nil {
			return nil, err
		}
	}
	return &p, p.Validate()
}
