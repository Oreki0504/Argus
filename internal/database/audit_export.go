package database

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Oreki0504/Argus-C2/internal/localfile"
	"github.com/Oreki0504/Argus-C2/internal/protocol"
	"github.com/Oreki0504/Argus-C2/internal/strictjson"
)

const MaxAuditExportEvents = 10000
const MaxAuditExportBytes = 32 * 1024 * 1024

type AuditExportEvent struct {
	ID        int64  `json:"id"`
	Timestamp int64  `json:"timestamp"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	NodeID    string `json:"node_id"`
	TaskID    string `json:"task_id"`
	SubjectID string `json:"subject_id"`
	Status    string `json:"status"`
}

type AuditExportData struct {
	Version    int                `json:"version"`
	ExportedAt int64              `json:"exported_at"`
	After      int64              `json:"after"`
	Through    int64              `json:"through"`
	NextAfter  int64              `json:"next_after"`
	HasMore    bool               `json:"has_more"`
	Events     []AuditExportEvent `json:"events"`
}

// SHA256 verifies accidental corruption against a separately trusted digest.
// This export is not signed: an attacker can rewrite both content and digest.
type AuditExport struct {
	Data   AuditExportData `json:"data"`
	SHA256 string          `json:"sha256"`
}

func (a AuditExportData) validate() error {
	if a.Version != 1 || a.ExportedAt < 1 || a.After < 0 || a.Through < 0 || a.NextAfter < a.After || a.Events == nil || len(a.Events) > MaxAuditExportEvents {
		return errors.New("invalid audit export")
	}
	previous := a.After
	for _, e := range a.Events {
		if e.ID <= previous || e.ID > a.Through || e.Timestamp < 1 || !protocol.CleanText(e.Actor, 256) || !protocol.CleanText(e.Action, 128) || !protocol.CleanText(e.NodeID, 128) || !protocol.CleanText(e.TaskID, 128) || !protocol.CleanText(e.SubjectID, 256) || !protocol.CleanText(e.Status, 1024) {
			return errors.New("invalid audit export event")
		}
		previous = e.ID
	}
	if a.NextAfter != previous || a.HasMore && (len(a.Events) == 0 || a.NextAfter >= a.Through) {
		return errors.New("invalid audit export cursor")
	}
	return nil
}

func (a AuditExportData) digest() (string, error) {
	if err := a.validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(a)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ExportAudit reads a single SQLite snapshot. Through freezes the last ID for
// later pages; retention can still remove older events between exports, so keep
// critical exports externally before lowering retention or deleting history.
func (s *Store) ExportAudit(ctx context.Context, after, through int64, limit int) (AuditExport, error) {
	out := AuditExport{Data: AuditExportData{Version: 1, ExportedAt: s.now().Unix(), After: after, NextAfter: after, Events: []AuditExportEvent{}}}
	if after < 0 || through < 0 || limit < 1 || limit > MaxAuditExportEvents {
		return out, errors.New("audit export requires nonnegative cursors and limit 1-10000")
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if through == 0 {
		if err = tx.QueryRowContext(ctx, "SELECT coalesce(max(id),0) FROM audit_events").Scan(&through); err != nil {
			return out, err
		}
	}
	out.Data.Through = through
	rows, err := tx.QueryContext(ctx, `SELECT id,timestamp,actor,action,node_id,task_id,subject_id,status FROM audit_events WHERE id>? AND id<=? ORDER BY id LIMIT ?`, after, through, limit+1)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		if len(out.Data.Events) == limit {
			out.Data.HasMore = true
			break
		}
		var e AuditExportEvent
		if err = rows.Scan(&e.ID, &e.Timestamp, &e.Actor, &e.Action, &e.NodeID, &e.TaskID, &e.SubjectID, &e.Status); err != nil {
			rows.Close()
			return out, err
		}
		out.Data.Events = append(out.Data.Events, e)
		out.Data.NextAfter = e.ID
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	out.SHA256, err = out.Data.digest()
	return out, err
}

func WriteAuditExport(path string, export AuditExport) error {
	if err := VerifyAuditExport(export); err != nil {
		return err
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return err
	}
	if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && parent.Mode().Perm()&0077 != 0 {
		return errors.New("audit export directory must be private and not a symlink")
	}
	b, err := json.MarshalIndent(export, "", "  ")
	if err != nil {
		return err
	}
	if len(b)+1 > MaxAuditExportBytes {
		return errors.New("audit export exceeds file limit")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		f.Close()
		if !ok {
			os.Remove(path)
		}
	}()
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		dir, err := os.Open(filepath.Dir(path))
		if err != nil {
			return err
		}
		err = dir.Sync()
		closeErr := dir.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	ok = true
	return nil
}

func VerifyAuditExport(export AuditExport) error {
	digest, err := export.Data.digest()
	if err != nil {
		return err
	}
	if len(export.SHA256) != 64 || subtle.ConstantTimeCompare([]byte(digest), []byte(export.SHA256)) != 1 {
		return errors.New("audit export SHA256 mismatch")
	}
	return nil
}

func ReadAuditExport(path string) (AuditExport, error) {
	var export AuditExport
	b, err := localfile.Read(path, MaxAuditExportBytes, true)
	if err != nil {
		return export, err
	}
	if err = strictjson.Decode(b, &export, MaxAuditExportBytes, "data", "sha256"); err != nil {
		return export, err
	}
	var raw struct {
		Data json.RawMessage `json:"data"`
	}
	if err = json.Unmarshal(b, &raw); err != nil {
		return export, err
	}
	if err = strictjson.Decode(raw.Data, &export.Data, MaxAuditExportBytes, "version", "exported_at", "after", "through", "next_after", "has_more", "events"); err != nil {
		return export, err
	}
	var data struct {
		Events []json.RawMessage `json:"events"`
	}
	if err = json.Unmarshal(raw.Data, &data); err != nil {
		return export, err
	}
	if len(data.Events) > MaxAuditExportEvents {
		return export, errors.New("too many audit export events")
	}
	for _, event := range data.Events {
		var checked AuditExportEvent
		if err = strictjson.Decode(event, &checked, 16384, "id", "timestamp", "actor", "action", "node_id", "task_id", "subject_id", "status"); err != nil {
			return export, err
		}
	}
	return export, VerifyAuditExport(export)
}
