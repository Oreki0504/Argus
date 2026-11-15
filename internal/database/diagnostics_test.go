package database

import (
	"errors"
	"sync"
	"testing"

	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

func TestDiagnosticBatchAtomicProfileAndCancellation(t *testing.T) {
	s := fixture(t)
	request := protocol.DiagnosticRequest{NodeIDs: []string{"node", "missing"}, ProfileID: "overview", TTLSeconds: 300, ExecutionTimeoutMS: 10000}
	if _, err := s.CreateDiagnosticBatch(t.Context(), "admin", request); !errors.Is(err, ErrNotFound) {
		t.Fatal(err)
	}
	var count int
	if err := s.DB.QueryRow("SELECT count(*) FROM tasks").Scan(&count); err != nil || count != 0 {
		t.Fatal("partial batch committed", count, err)
	}
	request.NodeIDs = []string{"node"}
	batch, err := s.CreateDiagnosticBatch(t.Context(), "admin", request)
	if err != nil || len(batch.Tasks) != 4 {
		t.Fatal(batch, err)
	}
	got, err := s.DiagnosticBatch(t.Context(), batch.ID)
	if err != nil || got.ID != batch.ID || got.ProfileID != "overview" || len(got.Tasks) != 4 {
		t.Fatal(got, err)
	}
	id := batch.Tasks[0].ID
	if err = s.CancelTask(t.Context(), "admin", id); err != nil {
		t.Fatal(err)
	}
	if err = s.CancelTask(t.Context(), "admin", id); err != nil {
		t.Fatal("repeat cancellation", err)
	}
	view, err := s.Task(t.Context(), id)
	if err != nil || view.Task.Status != protocol.Failed || view.Result == nil || view.Result.Error != "cancelled_before_dispatch" || view.ExecutionAuthorizedAt != 0 {
		t.Fatal(view, err)
	}
	if err = s.DB.QueryRow("SELECT count(*) FROM audit_events WHERE task_id=? AND action='task.cancel'", id).Scan(&count); err != nil || count != 1 {
		t.Fatal("cancellation audit duplicated", count, err)
	}
	if _, err = s.DB.Exec("UPDATE tasks SET status='ACCEPTED' WHERE id=?", batch.Tasks[1].ID); err != nil {
		t.Fatal(err)
	}
	if err = s.CancelTask(t.Context(), "admin", batch.Tasks[1].ID); !errors.Is(err, ErrConflict) {
		t.Fatal("accepted task cancelled", err)
	}
	if _, err = s.DB.Exec(`CREATE TRIGGER fail_cancel_audit BEFORE INSERT ON audit_events WHEN NEW.action='task.cancel' BEGIN SELECT RAISE(FAIL,'audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err = s.CancelTask(t.Context(), "admin", batch.Tasks[2].ID); err == nil {
		t.Fatal("audit failure hidden")
	}
	view, err = s.Task(t.Context(), batch.Tasks[2].ID)
	if err != nil || view.Task.Status != protocol.Pending || view.Result != nil {
		t.Fatal("partial cancellation committed", view, err)
	}
}

func TestCancelRaceCannotAuthorizeCancelledTask(t *testing.T) {
	s := fixture(t)
	cert := telemetryCertificate(t, s)
	for range 20 {
		task, err := s.CreateTask(t.Context(), "admin", protocol.TaskRequest{NodeID: "node", Type: protocol.SystemInfo, Params: []byte(`{}`), TTLSeconds: 300, ExecutionTimeoutMS: 10000})
		if err != nil {
			t.Fatal(err)
		}
		var cancelErr, pollErr error
		var polled *protocol.Task
		var wg sync.WaitGroup
		wg.Go(func() { cancelErr = s.CancelTask(t.Context(), "admin", task.ID) })
		wg.Go(func() { polled, pollErr = s.Poll(t.Context(), cert) })
		wg.Wait()
		if pollErr != nil {
			t.Fatal(pollErr)
		}
		if cancelErr == nil {
			if polled != nil {
				t.Fatal("cancelled task dispatched", polled)
			}
			if err := s.Running(t.Context(), cert, task.ID); !errors.Is(err, ErrConflict) {
				t.Fatal("cancelled task authorized", err)
			}
		} else {
			if !errors.Is(cancelErr, ErrConflict) || polled == nil || polled.ID != task.ID {
				t.Fatal(cancelErr, polled)
			}
			if err := s.Running(t.Context(), cert, task.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.SubmitResult(t.Context(), cert, protocol.NewResult(task, protocol.Failed, "test_completed")); err != nil {
				t.Fatal(err)
			}
		}
	}
}
