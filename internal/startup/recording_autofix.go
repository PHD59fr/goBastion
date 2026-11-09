package startup

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"goBastion/internal/recording/permissions"
)

func autoFixRecordingArchive(archive string, log *slog.Logger) error {
	if os.Geteuid() != 0 {
		return nil
	}
	entries, err := os.ReadDir(archive)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	backupDir := "/var/lib/goBastion/recording-migrations"
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return fmt.Errorf("prepare recording migration backup directory: %w", err)
	}
	if err := os.Chmod(backupDir, 0700); err != nil {
		return fmt.Errorf("secure recording migration backup directory: %w", err)
	}
	var failures []error
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || strings.HasPrefix(name, ".") || name == "lost+found" {
			continue
		}
		if err := autoFixRecordingAccount(archive, backupDir, name, log); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(failures...)
}

func autoFixRecordingAccount(archive, backupDir, account string, log *slog.Logger) error {
	plan, err := permissions.Plan(archive, account)
	if err != nil {
		// Not a migratable/valid legacy account namespace for this tool; leave it
		// to explicit validation/migration paths.
		return nil
	}
	needsFix := false
	for _, e := range plan.Entries {
		if e.UID != e.DesiredUID || e.GID != e.DesiredGID || e.Mode != e.DesiredMode {
			needsFix = true
			break
		}
	}
	if !needsFix {
		return nil
	}

	var suffix [8]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return err
	}
	backup := filepath.Join(backupDir, fmt.Sprintf("%s-%s-%s.json", account, time.Now().UTC().Format("20060102T150405Z"), hex.EncodeToString(suffix[:])))
	log.Warn("recording_autofix_start", slog.String("archive", archive), slog.String("user", account), slog.String("backup", backup))
	if err := permissions.Apply(archive, account, backup); err != nil {
		log.Error("recording_autofix_failed", slog.String("user", account), slog.String("backup", backup), slog.Any("error", err))
		if rbErr := permissions.Rollback(archive, account, backup); rbErr != nil {
			log.Error("recording_autofix_rollback_failed", slog.String("user", account), slog.String("backup", backup), slog.Any("error", rbErr))
			return fmt.Errorf("autofix failed: %w; rollback failed: %v", err, rbErr)
		}
		log.Warn("recording_autofix_rolled_back", slog.String("user", account), slog.String("backup", backup))
		return fmt.Errorf("autofix failed and was rolled back: %w", err)
	}
	log.Info("recording_autofix_applied", slog.String("user", account), slog.String("backup", backup))
	return nil
}
