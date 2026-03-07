package main

import (
	"log/slog"
	"os"

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
	log := logger.NewLogger()
	slog.SetDefault(log)

	db, err := internalDB.Init(log)
	if err != nil {
		log.Error("Failed to initialize database", slog.Any("error", err))
		return
	}

	adapter := osadapter.NewLinuxAdapter()

	if isRootNonSSH() {
		startup.Run(db, log, adapter)
		return
	}

	session.Run(db, log)
}
