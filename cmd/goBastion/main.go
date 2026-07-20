package main

import (
	"log/slog"
	"os"

	"goBastion/internal/config"
	internalDB "goBastion/internal/db"
	"goBastion/internal/osadapter"
	"goBastion/internal/session"
	"goBastion/internal/startup"
	"goBastion/internal/utils/logger"
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

func main() {
	// Phase 1: Bootstrap config from env vars (DB_DRIVER, DB_DSN, INSTANCE_ID).
	config.Load()

	log := logger.NewLogger()
	slog.SetDefault(log)

	// Phase 2: Connect to database using bootstrap DB config.
	db, err := internalDB.Init(log)
	if err != nil {
		log.Error("Failed to initialize database",
			slog.Any("error", err),
			slog.String("error_text", err.Error()),
		)
		return
	}

	// Phase 3: Ensure this instance has a config row, then load it.
	if err := config.EnsureInstance(db); err != nil {
		log.Warn("config_ensure_instance_failed", slog.Any("error", err))
	}
	if err := config.LoadFromDB(db); err != nil {
		log.Warn("config_load_from_db_failed", slog.Any("error", err))
	}

	adapter := osadapter.NewLinuxAdapter()

	if isRootNonSSH() {
		startup.Run(db, log, adapter)
		return
	}

	session.Run(db, log)
}
