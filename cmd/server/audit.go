package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/config"
	"github.com/Oreki0504/Argus-C2/internal/database"
)

func auditCommand(command string, args []string, out io.Writer) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	configFile := f.String("config", "/etc/argus-c2/server.json", "server configuration")
	file := f.String("file", "", "private audit export to verify")
	output := f.String("out", "", "new private audit export file")
	after := f.Int64("after", 0, "exclusive audit event ID cursor")
	through := f.Int64("through", 0, "fixed upper ID from the first page; zero captures current maximum")
	limit := f.Int("limit", 1000, "export page limit, 1-10000 events")
	capacity := f.Int("capacity", 0, "retained audit events, 1000-1000000; zero keeps current value")
	apply := f.Bool("apply", false, "apply audit capacity; default only previews")
	backup := f.String("backup", "", "new verified database backup required with -apply")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if command == "audit-verify" {
		if *file == "" {
			return errors.New("audit-verify requires -file")
		}
		export, err := database.ReadAuditExport(*file)
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"verified": true, "sha256": export.SHA256, "events": len(export.Data.Events), "next_after": export.Data.NextAfter, "through": export.Data.Through, "has_more": export.Data.HasMore})
	}
	if command == "audit-export" && *output == "" {
		return errors.New("audit-export requires -out in a private directory")
	}
	if command == "audit-retention" && (*apply && *backup == "" || !*apply && *backup != "") {
		return errors.New("-apply requires -backup; preview does not create a backup")
	}
	c, err := config.LoadServer(*configFile)
	if err != nil {
		return err
	}
	s, err := database.Open(c.StateDir, false)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	switch command {
	case "audit-export":
		export, err := s.ExportAudit(ctx, *after, *through, *limit)
		if err != nil {
			return err
		}
		if err = database.WriteAuditExport(*output, export); err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(map[string]any{"path": *output, "sha256": export.SHA256, "events": len(export.Data.Events), "next_after": export.Data.NextAfter, "through": export.Data.Through, "has_more": export.Data.HasMore})
	case "audit-retention":
		var report database.AuditRetentionReport
		if *apply {
			report, err = s.ConfigureAuditRetention(ctx, *capacity, *backup)
		} else {
			report, err = s.PreviewAuditRetention(ctx, *capacity)
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(out).Encode(report)
	default:
		return errors.New("unknown audit command")
	}
}
