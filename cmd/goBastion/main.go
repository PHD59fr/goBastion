package main

import (
	"errors"
	"log/slog"
	"os"
	"strings"
	"time"

	"goBastion/internal/config"
	internalDB "goBastion/internal/db"
	"goBastion/internal/osadapter"
	"goBastion/internal/session"
	"goBastion/internal/startup"
	"goBastion/internal/utils/cryptokey"
	"goBastion/internal/utils/logger"

	"gorm.io/gorm"
)

// isRootNonSSH returns true when running as root outside an SSH session.
func isRootNonSSH() bool {
	if os.Getuid() != 0 {
		return false
	}
	for _, env := range []string{"SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY"} {
		if _, exists := os.LookupEnv(env); exists {
			return false
		}
	}
	return true
}

// hasArg reports whether the given flag (e.g. "--sync") is present in os.Args.
func hasArg(name string) bool {
	for _, a := range os.Args[1:] {
		if a == name || strings.HasPrefix(a, name+"=") {
			return true
		}
	}
	return false
}

func shouldRunMigrate() bool {
	return os.Getuid() == 0 && !hasArg("--sync") && !hasArg("--syncUser")
}

func shouldBootstrapInstanceConfig() bool {
	return !hasArg("--dbImport")
}

func main() {
	tStart := time.Now()

	// Install the logger first so bootstrap logs (config.Load) are written to
	// the log file, not the client console. NewLogger uses the default config
	// path and does not trigger Load(), so this runs before bootstrap.
	log := logger.NewLogger()
	slog.SetDefault(log)

	// Phase 1: Bootstrap config from env vars (DB_DRIVER, DB_DSN, INSTANCE_ID).
	config.Load()

	// Phase 2: Initialize the database (connect + migrate) first. The instance
	// config lives in the DB, so this must happen before any config access.
	// Only root (master process) runs schema migration; ForceCommand sessions
	// and --sync invocations connect to the same DB but skip the expensive
	// AutoMigrate — the master process already ran it at startup.
	runMigrate := shouldRunMigrate()
	db, err := internalDB.Init(log, runMigrate)
	if err != nil {
		log.Error("Failed to initialize database",
			slog.Any("error", err),
			slog.String("error_text", err.Error()),
		)
		os.Exit(1)
	}

	// Phase 3: Check whether this instance's config row is present, then load
	// it. Only create the row (EnsureInstance) if it is missing — never the
	// other way around.
	if shouldBootstrapInstanceConfig() {
		tCfg := time.Now()
		if err := config.LoadFromDB(db); err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				log.Error("config_load_from_db_failed", slog.Any("error", err))
				os.Exit(1)
			}
			if err := config.EnsureInstance(db); err != nil {
				log.Error("config_ensure_instance_failed", slog.Any("error", err))
				os.Exit(1)
			}
			if err := config.LoadFromDB(db); err != nil {
				log.Error("config_load_from_db_failed", slog.Any("error", err))
				os.Exit(1)
			}
		}
		log.Info("config_loaded", slog.Duration("took", time.Since(tCfg)))
	}

	adapter := osadapter.NewLinuxAdapter()

	if isRootNonSSH() {
		exitCode := startup.Run(db, log, adapter)
		os.Exit(exitCode)
	}

	// Materialize the encryption primitive before removing bootstrap secrets
	// from the environment. Child processes such as ssh, ttyrec and mosh-server
	// must never inherit database credentials or the egress encryption key.
	_ = cryptokey.Enabled()
	if err := os.Unsetenv("DB_DSN"); err != nil {
		log.Warn("failed to unset DB_DSN", slog.Any("error", err))
	}
	if err := os.Unsetenv("EGRESS_ENC_KEY"); err != nil {
		log.Warn("failed to unset EGRESS_ENC_KEY", slog.Any("error", err))
	}

	log.Info("startup_total", slog.Duration("took", time.Since(tStart)))
	session.Run(db, log)
}
