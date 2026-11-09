// observability is a dedicated root process for the multi-process bastion. It
// reads shared counters/registry state; it never impersonates SSH event sources.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"gorm.io/gorm"

	"goBastion/internal/config"
	bastiondb "goBastion/internal/db"
	"goBastion/internal/observability"
)

func main() { os.Exit(run()) }

func run() int {
	cfg, err := observability.LoadConfigFromEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if !cfg.Enabled {
		return 0
	}
	if os.Geteuid() != 0 || os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_CLIENT") != "" || os.Getenv("SSH_TTY") != "" {
		fmt.Fprintln(os.Stderr, "observability requires a dedicated root process outside SSH sessions")
		return 1
	}
	config.Load()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	database, err := initializeDatabase(log, cfg.DBTimeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, "observation database initialization failed")
		return 1
	}
	connection, err := database.DB()
	if err != nil {
		fmt.Fprintln(os.Stderr, "observation database unavailable")
		return 1
	}
	defer func() { _ = connection.Close() }()
	// This process has no reason to pass bootstrap secrets to another process.
	for _, name := range []string{"DB_DSN", "EGRESS_ENC_KEY", "EGRESS_ENC_KEY_FILE", "EGRESS_ENC_KEYS", "EGRESS_ENC_KEYS_FILE", "DB_EXPORT_KEY", "OBS_AUTH_TOKEN_FILE"} {
		_ = os.Unsetenv(name)
	}
	store, err := observability.NewStore(database, config.InstanceID())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if cfg.RecordingSpool == "" {
		cfg.RecordingSpool = config.Get().Paths.TtyrecDir
	}
	service, err := observability.NewServer(cfg, database, store)
	cfg.Token = ""
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	if err := service.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// db.Init predates context-aware startup and performs its own connection ping.
// Keep that operation outside the exporter lifetime budget: an unsuccessful
// startup exits promptly, and any connection completing after cancellation is
// closed instead of being handed to a process which has already failed startup.
func initializeDatabase(log *slog.Logger, timeout time.Duration) (*gorm.DB, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	type initialized struct {
		database *gorm.DB
		err      error
	}
	result := make(chan initialized)
	go func() {
		database, err := bastiondb.Init(log, false)
		select {
		case result <- initialized{database, err}:
		case <-ctx.Done():
			if database != nil {
				if connection, err := database.DB(); err == nil {
					_ = connection.Close()
				}
			}
		}
	}()
	select {
	case initialized := <-result:
		return initialized.database, initialized.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
