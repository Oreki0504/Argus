//go:build linux

package network

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

// AssociateProcesses is a best-effort, bounded non-root observation. The
// caller gives it a short independent context inside the diagnostic budget.
// It never reads command lines, environments, socket contents, or executable
// files, and never treats inaccessible process descriptors as absent sockets.
func AssociateProcesses(ctx context.Context, listeners protocol.Listeners) protocol.ListenerProcesses {
	return associateProcesses(ctx, "/proc", listeners)
}

type socketIdentity struct {
	protocol, address string
	port              uint16
	inode             string
}

func listenerSocketIdentities(ctx context.Context, root string, listeners protocol.Listeners) (map[string][]socketIdentity, bool, bool) {
	out := map[string][]socketIdentity{}
	complete := true
	any := false
	wanted := map[string]bool{}
	for _, l := range listeners.Items {
		wanted[l.Protocol+"/"+l.Address+"/"+strconv.Itoa(int(l.Port))] = true
	}
	for _, kind := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if ctx.Err() != nil {
			return out, false, any
		}
		f, err := os.Open(filepath.Join(root, "net", kind))
		if err != nil {
			complete = false
			continue
		}
		limited := &io.LimitedReader{R: f, N: 2 * 1024 * 1024}
		scan := bufio.NewScanner(limited)
		scan.Buffer(make([]byte, 4096), 8192)
		if !scan.Scan() {
			complete = false
			f.Close()
			continue
		}
		any = true
		lines := 0
		for scan.Scan() {
			lines++
			if lines > 8192 || ctx.Err() != nil {
				complete = false
				break
			}
			fields := strings.Fields(scan.Text())
			if len(fields) < 10 {
				complete = false
				continue
			}
			state := "0A"
			if strings.HasPrefix(kind, "udp") {
				state = "07"
			}
			if fields[3] != state {
				continue
			}
			addr, port, err := address(fields[1])
			inode, parseErr := strconv.ParseUint(fields[9], 10, 64)
			if err != nil || parseErr != nil || inode == 0 {
				complete = false
				continue
			}
			if !wanted[kind+"/"+addr+"/"+strconv.Itoa(int(port))] {
				continue
			}
			id := socketIdentity{kind, addr, port, strconv.FormatUint(inode, 10)}
			if len(out) >= 4096 && out[id.inode] == nil {
				complete = false
				continue
			}
			duplicate := false
			for _, old := range out[id.inode] {
				if old == id {
					duplicate = true
				}
			}
			if !duplicate {
				out[id.inode] = append(out[id.inode], id)
			}
		}
		if scan.Err() != nil || limited.N == 0 {
			complete = false
		}
		f.Close()
	}
	return out, complete, any
}

func processIdentity(root, name string) (string, string, error) {
	raw, err := localfile.Read(filepath.Join(root, name, "stat"), 16384, false)
	if err != nil {
		return "", "", err
	}
	text := string(raw)
	open := strings.IndexByte(text, '(')
	close := strings.LastIndexByte(text, ')')
	if open < 1 || close <= open || strings.TrimSpace(text[:open]) != name {
		return "", "", errors.New("invalid process identity")
	}
	fields := strings.Fields(text[close+1:])
	if len(fields) <= 19 {
		return "", "", errors.New("missing process start ticks")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 {
		return "", "", errors.New("invalid process start ticks")
	}
	comm := text[open+1 : close]
	if !protocol.CleanText(comm, 64) {
		comm = ""
	}
	return strconv.FormatUint(start, 10), comm, nil
}

func associateProcesses(ctx context.Context, root string, listeners protocol.Listeners) protocol.ListenerProcesses {
	out := protocol.ListenerProcesses{Coverage: "unavailable", Items: []protocol.ListenerProcess{}}
	if !listeners.Available {
		return out
	}
	sockets, complete, any := listenerSocketIdentities(ctx, root, listeners)
	if !any {
		return out
	}
	dir, err := os.Open(root)
	if err != nil {
		return out
	}
	defer dir.Close()
	visible := false
	matched := map[string]bool{}
	seen := map[string]bool{}
	entries := 0
	for {
		if ctx.Err() != nil {
			complete = false
			break
		}
		names, readErr := dir.Readdirnames(128)
		if len(names) > 0 || errors.Is(readErr, io.EOF) {
			visible = true
		}
		stop := false
		for _, name := range names {
			entries++
			if entries > 8192 || ctx.Err() != nil {
				complete = false
				stop = true
				break
			}
			pid, err := strconv.Atoi(name)
			if err != nil || pid < 1 {
				continue
			}
			if out.ScannedProcesses >= 4096 {
				complete = false
				stop = true
				break
			}
			out.ScannedProcesses++
			start, comm, err := processIdentity(root, name)
			if err != nil {
				complete = false
				continue
			}
			fds, err := os.Open(filepath.Join(root, name, "fd"))
			if err != nil {
				complete = false
				continue
			}
			fdNames, readErr := fds.Readdirnames(257)
			fds.Close()
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				complete = false
			}
			if len(fdNames) > 256 {
				fdNames = fdNames[:256]
				complete = false
			}
			candidates := []protocol.ListenerProcess{}
			for _, fd := range fdNames {
				if ctx.Err() != nil || out.ScannedFDs >= 16384 {
					complete = false
					stop = true
					break
				}
				out.ScannedFDs++
				link, err := os.Readlink(filepath.Join(root, name, "fd", fd))
				if err != nil {
					complete = false
					continue
				}
				if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
					continue
				}
				inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
				for _, socket := range sockets[inode] {
					if len(candidates) >= 128 {
						complete = false
						stop = true
						break
					}
					candidates = append(candidates, protocol.ListenerProcess{Protocol: socket.protocol, Address: socket.address, Port: socket.port, PID: pid, ProcessName: comm, ProcessStartTicks: start, SocketInode: inode})
				}
				if stop {
					break
				}
			}
			current, _, err := processIdentity(root, name)
			if err != nil || current != start {
				complete = false
				continue
			}
			for _, candidate := range candidates {
				key := strconv.Itoa(candidate.PID) + "/" + candidate.SocketInode + "/" + candidate.Protocol + "/" + candidate.Address + "/" + strconv.Itoa(int(candidate.Port))
				if seen[key] {
					continue
				}
				if len(out.Items) >= 128 {
					complete = false
					stop = true
					break
				}
				seen[key] = true
				matched[candidate.SocketInode] = true
				out.Items = append(out.Items, candidate)
			}
			if stop {
				break
			}
		}
		if stop {
			break
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			complete = false
			break
		}
	}
	if !visible {
		return out
	}
	// Re-read socket identities to avoid binding a process to a reused inode
	// when a socket disappears or changes endpoint during the scan.
	current, stable, _ := listenerSocketIdentities(ctx, root, listeners)
	complete = complete && stable
	kept := out.Items[:0]
	for _, item := range out.Items {
		found := false
		for _, socket := range current[item.SocketInode] {
			if socket.protocol == item.Protocol && socket.address == item.Address && socket.port == item.Port {
				found = true
				break
			}
		}
		if found {
			kept = append(kept, item)
		} else {
			complete = false
		}
	}
	out.Items = kept
	for inode := range sockets {
		if !matched[inode] {
			complete = false
		}
	}
	if len(listeners.Items) > 0 && len(sockets) == 0 {
		complete = false
	}
	sort.Slice(out.Items, func(i, j int) bool {
		a, b := out.Items[i], out.Items[j]
		if a.PID != b.PID {
			return a.PID < b.PID
		}
		if a.Protocol != b.Protocol {
			return a.Protocol < b.Protocol
		}
		if a.Address != b.Address {
			return a.Address < b.Address
		}
		return a.Port < b.Port
	})
	out.Coverage = "partial"
	if complete && listeners.Coverage == "complete" {
		out.Coverage = "complete"
	}
	return out
}
