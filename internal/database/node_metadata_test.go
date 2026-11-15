package database

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestNodeTagsBoundsOrderingAndAuditRollback(t *testing.T) {
	s := fixture(t)
	if err := s.SetNodeTags(t.Context(), "admin", "node", []string{"prod", "region:tokyo", "db"}); err != nil {
		t.Fatal(err)
	}
	tags, err := s.NodeTags(t.Context(), "node")
	if err != nil || !reflect.DeepEqual(tags, []string{"db", "prod", "region:tokyo"}) {
		t.Fatal(tags, err)
	}
	nodes, err := s.Nodes(t.Context(), "")
	if err != nil || len(nodes) != 1 || !reflect.DeepEqual(nodes[0].Tags, tags) || nodes[0].Authorization != "ACTIVE" {
		t.Fatal(nodes, err)
	}
	for _, bad := range [][]string{nil, {""}, {"a", "a"}, {"private\nline"}, {"leading space"}, {"a/b"}, {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}, make([]string, 17)} {
		if err = s.SetNodeTags(t.Context(), "admin", "node", bad); !errors.Is(err, ErrInvalidNodeTags) {
			t.Fatal("invalid tags", bad, err)
		}
	}
	if _, err = s.DB.Exec("CREATE TRIGGER fail_tags BEFORE INSERT ON audit_events WHEN NEW.action='node.tags.update' BEGIN SELECT RAISE(FAIL,'audit fail'); END"); err != nil {
		t.Fatal(err)
	}
	if err = s.SetNodeTags(t.Context(), "admin", "node", []string{"changed"}); err == nil {
		t.Fatal("tags changed without audit")
	}
	got, err := s.NodeTags(t.Context(), "node")
	if err != nil || !reflect.DeepEqual(got, tags) {
		t.Fatal("partial tags change", got, err)
	}
}

func TestRevocationRejectsCurrentAndPreviousIdentityAtomically(t *testing.T) {
	s := fixture(t)
	previous := telemetryCertificate(t, s)
	current := *previous
	current.Raw = []byte("current-cert")
	if _, err := s.DB.Exec("UPDATE nodes SET certificate_fingerprint=?,previous_fingerprint=?,previous_until=? WHERE id='node'", identity.Fingerprint(&current), identity.Fingerprint(previous), time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authorize(t.Context(), &current); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authorize(t.Context(), previous); err != nil {
		t.Fatal(err)
	}
	task, err := s.CreateTask(t.Context(), "admin", protocol.TaskRequest{NodeID: "node", Type: protocol.SystemInfo, Params: []byte(`{}`), TTLSeconds: 60, ExecutionTimeoutMS: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DB.Exec("CREATE TRIGGER fail_revoke BEFORE INSERT ON audit_events WHEN NEW.action='node.revoke' BEGIN SELECT RAISE(FAIL,'audit fail'); END"); err != nil {
		t.Fatal(err)
	}
	if err = s.RevokeNode(t.Context(), "admin", "node"); err == nil {
		t.Fatal("revocation without audit")
	}
	view, err := s.Task(t.Context(), task.ID)
	if err != nil || view.Task.Status != protocol.Pending {
		t.Fatal("partial revocation modified tasks", view, err)
	}
	if _, err = s.Authorize(t.Context(), &current); err != nil {
		t.Fatal("failed revoke removed identity", err)
	}
	if _, err = s.DB.Exec("DROP TRIGGER fail_revoke"); err != nil {
		t.Fatal(err)
	}
	if err = s.RevokeNode(t.Context(), "admin", "node"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authorize(t.Context(), &current); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("current cert survived revocation", err)
	}
	if _, err = s.Authorize(t.Context(), previous); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("previous cert survived revocation", err)
	}
	nodes, err := s.Nodes(t.Context(), "")
	if err != nil || len(nodes) != 1 || nodes[0].Authorization != "REVOKED" || nodes[0].Status != "disabled" {
		t.Fatal(nodes, err)
	}
	view, err = s.Task(t.Context(), task.ID)
	if err != nil || view.Task.Status != protocol.Failed || view.Result == nil || view.Result.Error != "node_revoked" {
		t.Fatal(view, err)
	}
	if err = s.RevokeNode(t.Context(), "admin", "node"); err != nil {
		t.Fatal("repeat revoke not idempotent", err)
	}
	var count int
	if err = s.DB.QueryRow("SELECT count(*) FROM audit_events WHERE action='node.revoke'").Scan(&count); err != nil || count != 1 {
		t.Fatal(count, err)
	}
	// Independent revocation remains authoritative even if legacy status is
	// accidentally set active by a future path or an offline repair.
	if _, err = s.DB.Exec("UPDATE nodes SET status='active' WHERE id='node'"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Authorize(t.Context(), &current); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("legacy state bypassed revocation", err)
	}
	if _, err = s.CreateTask(t.Context(), "admin", protocol.TaskRequest{NodeID: "node", Type: protocol.SystemInfo, Params: []byte(`{}`), TTLSeconds: 60, ExecutionTimeoutMS: 1000}); !errors.Is(err, ErrNodeDisabled) {
		t.Fatal("revoked identity accepted diagnostic assignment", err)
	}
}
