package database

import (
	"context"
	"database/sql"
	"errors"

	"github.com/Oreki0504/Argus-C2/internal/identity"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
)

const diagnosticsSchema = `
CREATE TABLE diagnostic_batches (
 id TEXT PRIMARY KEY, profile_id TEXT NOT NULL, created_at INTEGER NOT NULL,
 actor TEXT NOT NULL
);
CREATE TABLE diagnostic_batch_tasks (
 batch_id TEXT NOT NULL REFERENCES diagnostic_batches(id),
 task_id TEXT NOT NULL UNIQUE REFERENCES tasks(id) ON DELETE CASCADE,
 ordinal INTEGER NOT NULL, PRIMARY KEY(batch_id,ordinal)
);
`

type DiagnosticBatch struct {
	ID        string          `json:"id"`
	ProfileID string          `json:"profile_id"`
	CreatedAt int64           `json:"created_at"`
	Tasks     []protocol.Task `json:"tasks"`
}

// CreateDiagnosticBatch validates every node and queue in one transaction.
// A rejected node never leaves a partially submitted multi-node request.
func (s *Store) CreateDiagnosticBatch(ctx context.Context, actor string, request protocol.DiagnosticRequest) (DiagnosticBatch, error) {
	out := DiagnosticBatch{Tasks: []protocol.Task{}}
	requests, err := request.Tasks()
	if err != nil {
		return out, err
	}
	profile, _ := request.Profile()
	now := s.now().Unix()
	out.ID, out.ProfileID, out.CreatedAt = identity.RandomID(), profile.ID, now
	err = s.Write(ctx, func(tx *sql.Tx) error {
		if err := expire(ctx, tx, now); err != nil {
			return err
		}
		for _, node := range request.NodeIDs {
			var status string
			if err := tx.QueryRowContext(ctx, "SELECT CASE WHEN EXISTS(SELECT 1 FROM node_revocations WHERE node_id=nodes.id) THEN 'revoked' ELSE status END FROM nodes WHERE id=?", node).Scan(&status); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrNotFound
				}
				return err
			}
			if status != "active" {
				return ErrNodeDisabled
			}
			var count int
			if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM tasks WHERE node_id=? AND status IN ('PENDING','ACCEPTED','RUNNING')", node).Scan(&count); err != nil {
				return err
			}
			if count+len(profile.Collectors) > 100 {
				return ErrConflict
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO diagnostic_batches(id,profile_id,created_at,actor) VALUES(?,?,?,?)", out.ID, profile.ID, now, actor); err != nil {
			return err
		}
		for i, request := range requests {
			t := protocol.Task{ID: identity.RandomID(), NodeID: request.NodeID, Type: request.Type, Params: request.Params, Status: protocol.Pending, CreatedAt: now, DispatchExpiresAt: now + int64(request.TTLSeconds), ExecutionTimeoutMS: request.ExecutionTimeoutMS, ResultDueAt: now + int64(request.TTLSeconds) + protocol.ResultGraceSeconds}
			if _, err := tx.ExecContext(ctx, "INSERT INTO tasks("+taskColumns+") VALUES(?,?,?,?,?,?,?,?,?)", t.ID, t.NodeID, t.Type, string(t.Params), t.Status, t.CreatedAt, t.DispatchExpiresAt, t.ExecutionTimeoutMS, t.ResultDueAt); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "INSERT INTO diagnostic_batch_tasks(batch_id,task_id,ordinal) VALUES(?,?,?)", out.ID, t.ID, i); err != nil {
				return err
			}
			if err := auditSubject(ctx, tx, actor, "task.create", t.NodeID, t.ID, out.ID, "profile:"+profile.ID); err != nil {
				return err
			}
			out.Tasks = append(out.Tasks, t)
		}
		return auditSubject(ctx, tx, actor, "diagnostic.create", "", "", out.ID, profile.ID)
	})
	if err != nil {
		return DiagnosticBatch{Tasks: []protocol.Task{}}, err
	}
	return out, nil
}

func (s *Store) DiagnosticBatch(ctx context.Context, id string) (DiagnosticBatch, error) {
	out := DiagnosticBatch{Tasks: []protocol.Task{}}
	if !identity.Valid(id) {
		return out, ErrNotFound
	}
	if err := s.ExpireTasks(ctx); err != nil {
		return out, err
	}
	err := s.DB.QueryRowContext(ctx, "SELECT id,profile_id,created_at FROM diagnostic_batches WHERE id=?", id).Scan(&out.ID, &out.ProfileID, &out.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrNotFound
	}
	if err != nil {
		return out, err
	}
	rows, err := s.DB.QueryContext(ctx, "SELECT "+taskColumns+" FROM tasks WHERE id IN (SELECT task_id FROM diagnostic_batch_tasks WHERE batch_id=?) ORDER BY created_at,id LIMIT 200", id)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		t, err := scanTask(rows)
		if err != nil {
			return out, err
		}
		out.Tasks = append(out.Tasks, t)
	}
	return out, rows.Err()
}

// CancelTask only cancels work which has never been dispatched. Repeated
// cancellation succeeds; racing acceptance wins or loses atomically.
func (s *Store) CancelTask(ctx context.Context, actor, id string) error {
	if !identity.Valid(id) {
		return ErrNotFound
	}
	return s.Write(ctx, func(tx *sql.Tx) error {
		task, err := scanTask(tx.QueryRowContext(ctx, "SELECT "+taskColumns+" FROM tasks WHERE id=?", id))
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if task.Status != protocol.Pending {
			if task.Status == protocol.Failed {
				result, err := resultTx(ctx, tx, id)
				if err == nil && result.Error == "cancelled_before_dispatch" {
					return nil
				}
			}
			return ErrConflict
		}
		now := s.now().Unix()
		result := protocol.NewResult(task, protocol.Failed, "cancelled_before_dispatch")
		result.CompletedAt = now
		if err = insertResult(ctx, tx, result, now); err != nil {
			return err
		}
		if err = updateOne(ctx, tx, "UPDATE tasks SET status='FAILED' WHERE id=? AND status='PENDING'", id); err != nil {
			return err
		}
		return Audit(ctx, tx, actor, "task.cancel", task.NodeID, id, "cancelled_before_dispatch")
	})
}
