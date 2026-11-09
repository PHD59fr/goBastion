// secret-migrate is an offline administrative upgrade/rotation command.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"goBastion/internal/config"
	"goBastion/internal/db"
	"goBastion/internal/models"
	"goBastion/internal/secretstore"
	"goBastion/internal/utils/cryptokey"

	"gorm.io/gorm"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, out, diagnostics io.Writer) int {
	flags := flag.NewFlagSet("secret-migrate", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	apply := flags.Bool("apply", false, "Apply persistent-secrets-v2; default validates without writes")
	plaintext := flags.Bool("allow-plaintext", false, "Explicitly authorize upgrading legacy plaintext while all instances are stopped")
	backup := flags.String("backup", "", "New encrypted logical backup path (required for --apply; DB_EXPORT_KEY required)")
	restore := flags.String("restore-backup", "", "Restore an encrypted migration backup into an empty database, upgrading legacy secrets")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if *apply && *backup == "" {
		_, _ = fmt.Fprintln(diagnostics, "--apply requires --backup to a new protected file")
		return 2
	}
	if *restore != "" && (*apply || *plaintext || *backup != "") {
		_, _ = fmt.Fprintln(diagnostics, "--restore-backup cannot be combined with migration flags")
		return 2
	}
	if os.Getuid() != 0 || os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_CLIENT") != "" || os.Getenv("SSH_TTY") != "" {
		_, _ = fmt.Fprintln(diagnostics, "secret-migrate requires a root administrative console outside SSH ForceCommand")
		return 2
	}
	config.Load()
	if err := cryptokey.Validate(); err != nil {
		_, _ = fmt.Fprintln(diagnostics, err)
		return 1
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	database, err := db.Init(log, *restore != "")
	if err != nil {
		_, _ = fmt.Fprintln(diagnostics, "database initialization failed")
		return 1
	}
	connection, err := database.DB()
	if err != nil {
		return 1
	}
	defer func() { _ = connection.Close() }()
	if *restore != "" {
		file, err := os.Open(*restore)
		if err != nil {
			_, _ = fmt.Fprintln(diagnostics, "cannot open encrypted backup")
			return 1
		}
		defer func() { _ = file.Close() }()
		if err := db.ImportForSecretMigration(database, file, log); err != nil {
			_, _ = fmt.Fprintln(diagnostics, "backup restore failed; target data transaction rolled back")
			return 1
		}
		if _, err := fmt.Fprintln(out, "Encrypted backup restored; all persistent secrets upgraded"); err != nil {
			return 1
		}
		return 0
	}
	var active int64
	if err := database.Model(&models.ActiveSession{}).Count(&active).Error; err != nil || active != 0 {
		_, _ = fmt.Fprintln(diagnostics, "cannot migrate while sessions are registered; stop every instance and reconcile stale sessions first")
		return 1
	}
	// Validate every row before creating a backup or writing any ciphertext.
	if _, err := secretstore.Migrate(database, secretstore.Options{AllowPlaintext: *plaintext}); err != nil {
		_, _ = fmt.Fprintln(diagnostics, err)
		return 1
	}
	if *apply {
		if err := writeBackup(database, *backup, log); err != nil {
			_, _ = fmt.Fprintln(diagnostics, "encrypted backup failed; no migration applied")
			return 1
		}
	}
	result, err := secretstore.Migrate(database, secretstore.Options{Apply: *apply, AllowPlaintext: *plaintext})
	if err != nil {
		_, _ = fmt.Fprintln(diagnostics, err)
		return 1
	}
	if err := json.NewEncoder(out).Encode(result); err != nil {
		return 1
	}
	return 0
}

func writeBackup(database *gorm.DB, path string, log *slog.Logger) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	if err := db.Export(database, file, log); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	if err := dir.Sync(); err != nil {
		return err
	}
	complete = true
	return nil
}
