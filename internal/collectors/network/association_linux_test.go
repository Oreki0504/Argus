//go:build linux

package network

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func associationFixture(t *testing.T) (string, protocol.Listeners) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "net"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"tcp", "tcp6", "udp", "udp6"} {
		body := "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
		if kind == "tcp" {
			body += "0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 1000 0 1234\n"
		}
		if err := os.WriteFile(filepath.Join(root, "net", kind), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, protocol.Listeners{Available: true, Coverage: "complete", Items: []protocol.Listener{{Protocol: "tcp", Address: "127.0.0.1", Port: 22}}}
}

func associationProcess(t *testing.T, root string, pid int, inode string) {
	t.Helper()
	dir := filepath.Join(root, fmt.Sprint(pid))
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0700); err != nil {
		t.Fatal(err)
	}
	fields := []string{"S"}
	for range 18 {
		fields = append(fields, "0")
	}
	fields = append(fields, "9007199254740993", "0")
	stat := fmt.Sprintf("%d (test worker) %s\n", pid, strings.Join(fields, " "))
	if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:["+inode+"]", filepath.Join(dir, "fd", "3")); err != nil {
		t.Fatal(err)
	}
}

func TestListenerProcessAssociationUsesInodesAndStableProcessIdentity(t *testing.T) {
	root, listeners := associationFixture(t)
	associationProcess(t, root, 123, "1234")
	associationProcess(t, root, 456, "9999")
	if err := os.Symlink("socket:[1234]", filepath.Join(root, "123", "fd", "4")); err != nil {
		t.Fatal(err)
	}
	out := associateProcesses(t.Context(), root, listeners)
	if err := out.Validate(); err != nil {
		t.Fatal(out, err)
	}
	if out.Coverage != "complete" || len(out.Items) != 1 || out.Items[0].PID != 123 || out.Items[0].SocketInode != "1234" || out.Items[0].ProcessStartTicks != "9007199254740993" {
		t.Fatal(out)
	}
	if out.Items[0].ProcessName != "test worker" {
		t.Fatal("process identity parsed incorrectly", out)
	}
	if err := os.RemoveAll(filepath.Join(root, "123", "fd")); err != nil {
		t.Fatal(err)
	}
	out = associateProcesses(t.Context(), root, listeners)
	if out.Coverage != "partial" || len(out.Items) != 0 {
		t.Fatal("inaccessible descriptors treated as absent", out)
	}
}

func TestListenerAssociationCancellationAndFDLimitArePartial(t *testing.T) {
	root, listeners := associationFixture(t)
	associationProcess(t, root, 123, "1234")
	for i := range 300 {
		if err := os.Symlink("socket:[9999]", filepath.Join(root, "123", "fd", fmt.Sprintf("extra-%d", i))); err != nil {
			t.Fatal(err)
		}
	}
	out := associateProcesses(t.Context(), root, listeners)
	if out.Coverage != "partial" || out.ScannedFDs > 256 {
		t.Fatal("descriptor bounds ignored", out)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	out = associateProcesses(ctx, root, listeners)
	if out.Coverage == "complete" || len(out.Items) != 0 {
		t.Fatal("cancelled observation claimed complete", out)
	}
	if _, _, err := processIdentity(root, "999"); err == nil {
		t.Fatal("missing process identity accepted")
	}
}
