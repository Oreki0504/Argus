package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Oreki0504/Argus-C2/internal/config"
	"github.com/Oreki0504/Argus-C2/internal/database"
)

// Missing observations require a timer: ingestion alone cannot detect silence.
func runAlertEvaluation(ctx context.Context, store *database.Store) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		pass, cancel := context.WithTimeout(ctx, 20*time.Second)
		err := store.SweepAlerts(pass)
		cancel()
		if err != nil && ctx.Err() == nil {
			slog.Warn("alert evaluation failed; will retry", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func telemetryMigrateCommand(args []string, out io.Writer) error {
	f := flag.NewFlagSet("telemetry-migrate", flag.ContinueOnError)
	file := f.String("config", "/etc/argus-c2/server.json", "server configuration")
	backup := f.String("backup", "", "new verified pre-upgrade snapshot in a private directory")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *backup == "" {
		return errors.New("telemetry-migrate requires -backup; stop the server first")
	}
	c, err := config.LoadServer(*file)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err = database.MigrateTelemetry(ctx, c.StateDir, *backup); err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Server schema migrated to %d; verified pre-upgrade backup: %s\n", database.SchemaVersion, *backup)
	return err
}

func telemetryPruneCommand(args []string, out io.Writer) error {
	f := flag.NewFlagSet("telemetry-prune", flag.ContinueOnError)
	file := f.String("config", "/etc/argus-c2/server.json", "server configuration")
	days := f.Int("retain-days", database.DefaultRetentionDays, "retain observations for this many days after measurement")
	limit := f.Int("limit", 1000, "maximum samples per batch, 1-1000")
	batches := f.Int("batches", 1, "maximum frozen batches per sweep, 1-100; one backup covers the sweep")
	timeout := f.Duration("timeout", 2*time.Minute, "bounded maintenance deadline, 1 second to 30 minutes")
	apply := f.Bool("apply", false, "delete the eligible frozen batches; default is preview only")
	backup := f.String("backup", "", "new verified snapshot required with -apply")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *timeout < time.Second || *timeout > 30*time.Minute {
		return errors.New("timeout must be between 1 second and 30 minutes")
	}
	if *apply {
		if *backup == "" {
			return errors.New("-apply requires -backup in a private directory")
		}
		parent, err := os.Lstat(filepath.Dir(*backup))
		if err != nil {
			return err
		}
		if !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && parent.Mode().Perm()&0077 != 0 {
			return errors.New("backup directory must be private and non-symlink")
		}
	} else if *backup != "" {
		return errors.New("-backup is only used with -apply")
	}
	c, err := config.LoadServer(*file)
	if err != nil {
		return err
	}
	s, err := database.Open(c.StateDir, false)
	if err != nil {
		return err
	}
	defer s.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var report database.TelemetryPruneReport
	if *apply {
		report, err = s.PruneTelemetrySweep(ctx, *days, *limit, *batches, *backup)
	} else {
		report, err = s.PreviewPruneTelemetrySweep(ctx, *days, *limit, *batches)
	}
	if err != nil {
		// Progress remains reviewable after a deadline or a later batch failure.
		// The caller still returns a nonzero exit status and the cause on stderr.
		if *apply && report.SweepID != "" {
			if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
				return errors.Join(err, encodeErr)
			}
		}
		return err
	}
	return json.NewEncoder(out).Encode(report)
}
