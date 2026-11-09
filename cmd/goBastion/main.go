package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"goBastion/internal/config"
	internalDB "goBastion/internal/db"
	"goBastion/internal/observability"
	"goBastion/internal/osadapter"
	"goBastion/internal/secretstore"
	"goBastion/internal/session"
	"goBastion/internal/startup"
	"goBastion/internal/telemetry"
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
	return os.Getuid() == 0 && !hasArg("--sync") && !hasArg("--syncUser") && !hasArg("--dbSession")
}

func shouldBootstrapInstanceConfig() bool {
	return (len(os.Args) > 1 && os.Args[1] == "--dbSession") || !hasArg("--dbImport")
}

func main() {
	code := runMain()
	if err := telemetry.ShutdownDefault(context.Background()); err != nil {
		slog.Warn("trace_shutdown_incomplete")
	}
	os.Exit(code)
}

func runMain() int {
	tStart := time.Now()

	// Install the logger first so bootstrap logs (config.Load) are written to
	// the log file, not the client console. NewLogger uses the default config
	// path and does not trigger Load(), so this runs before bootstrap.
	log := logger.NewLogger()
	slog.SetDefault(log)

	// Phase 1: Bootstrap config from env vars (DB_DRIVER, DB_DSN, INSTANCE_ID).
	config.Load()
	if _, err := telemetry.ConfigureSessionFromEnv(log); err != nil {
		log.Error("tracing_configuration_invalid")
		return 1
	}
	logger.SetTraceResolver(telemetry.TraceIDs)
	// Fail before opening/migrating a database or executing privileged helpers.
	if err := cryptokey.Validate(); err != nil {
		log.Error("persistent_secret_configuration_invalid", slog.Any("error", err))
		return 1
	}

	// Phase 2: Initialize the database (connect + migrate) first. The instance
	// config lives in the DB, so this must happen before any config access.
	// Only root (master process) runs schema migration; ForceCommand sessions
	// and --sync invocations connect to the same DB but skip the expensive
	// AutoMigrate — the master process already ran it at startup.
	runMigrate := shouldRunMigrate()
	_, bootstrapSpan := telemetry.Start(context.Background(), "startup", telemetry.Component("startup"))
	db, err := internalDB.Init(log, runMigrate)
	if err != nil {
		bootstrapSpan.Failure()
	} else {
		bootstrapSpan.Success()
	}
	bootstrapSpan.End()
	if err != nil {
		log.Error("Failed to initialize database",
			slog.Any("error", err),
			slog.String("error_text", err.Error()),
		)
		return 1
	}
	if raw := os.Getenv("OBS_ENABLED"); raw != "" {
		enabled, err := strconv.ParseBool(raw)
		if err != nil {
			log.Error("observability_configuration_invalid")
			return 1
		}
		if enabled && !hasArg("--dbImport") && !hasArg("--dbExport") {
			store, err := observability.NewStore(db, config.InstanceID())
			if err != nil {
				log.Error("observability_configuration_invalid")
				return 1
			}
			logger.SetEventObserver(store)
		}
	}
	// Every execution has loaded its DB connection and immutable keyring. Keep
	// bootstrap credentials out of children, including root startup helpers.
	for _, name := range []string{"DB_DSN", "EGRESS_ENC_KEY", "EGRESS_ENC_KEY_FILE", "EGRESS_ENC_KEYS", "EGRESS_ENC_KEYS_FILE", "OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS"} {
		_ = os.Unsetenv(name)
	}
	if !hasArg("--dbImport") && !hasArg("--dbExport") {
		_ = os.Unsetenv("DB_EXPORT_KEY")
	}
	if isRootNonSSH() && !hasArg("--dbImport") && !hasArg("--dbExport") {
		if err := secretstore.ValidateStored(db); err != nil {
			log.Error("persistent_secret_validation_failed", slog.Any("error", err))
			return 1
		}
	}

	// Phase 3: Check whether this instance's config row is present, then load
	// it. Only create the row (EnsureInstance) if it is missing — never the
	// other way around.
	if shouldBootstrapInstanceConfig() {
		tCfg := time.Now()
		if err := config.LoadFromDB(db); err != nil {
			if !errors.Is(err, gorm.ErrRecordNotFound) {
				log.Error("config_load_from_db_failed", slog.Any("error", err))
				return 1
			}
			// Keep a pristine database empty until the first administrator is
			// created. This is also what makes a freshly migrated target suitable
			// for --dbImport. --firstInstall creates the instance row below.
			if !hasArg("--firstInstall") {
				log.Info("config_not_initialized")
			}
		}
		log.Info("config_loaded", slog.Duration("took", time.Since(tCfg)))
	}

	if len(os.Args) > 1 && os.Args[1] == "--dbSession" {
		_ = cryptokey.Enabled()
		_ = os.Unsetenv("DB_DSN")
		_ = os.Unsetenv("EGRESS_ENC_KEY")
		return session.RunDBSupervisor(db, log, os.Args[2:])
	}
	adapter := osadapter.NewLinuxAdapter()

	if isRootNonSSH() {
		exitCode := startup.Run(db, log, adapter)
		return exitCode
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
	return session.Run(db, log)
}
