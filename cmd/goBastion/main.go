package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"goBastion/internal/authkeys"
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
	return os.Getuid() == 0 && !hasArg("--sync") && !hasArg("--syncUser") && !hasArg("--dbSession") && !hasArg("--authorizedKeys")
}

func shouldBootstrapInstanceConfig() bool {
	return (len(os.Args) > 1 && os.Args[1] == "--dbSession") || !hasArg("--dbImport")
}

func authorizedKeysArg() (string, bool) {
	if len(os.Args) < 2 {
		return "", false
	}
	if os.Args[1] == "--authorizedKeys" {
		if len(os.Args) == 3 {
			return os.Args[2], true
		}
		return "", true
	}
	if strings.HasPrefix(os.Args[1], "--authorizedKeys=") {
		if len(os.Args) != 2 {
			return "", true
		}
		return strings.TrimPrefix(os.Args[1], "--authorizedKeys="), true
	}
	return "", false
}

func runAuthorizedKeys(username string) int {
	if os.Getuid() != 0 || username == "" {
		return 1
	}
	log := logger.NewLogger()
	slog.SetDefault(log)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Database initialization includes driver connection/configuration calls
	// without context support. Bound bootstrap and lookup in this one-shot
	// sshd helper. Only publish keys here after lookup meets the deadline.
	lines, err := boundedIngressLookup(ctx, func(ctx context.Context) ([]string, error) {
		if err := authkeys.LoadDBBootstrapFromConf(); err != nil {
			return nil, err
		}
		config.Load()
		db, err := internalDB.Init(log, false)
		if err != nil {
			return nil, err
		}
		if sqlDB, err := db.DB(); err == nil {
			defer func() { _ = sqlDB.Close() }()
		}
		return authkeys.LookupIngressKeys(ctx, db, username, time.Now())
	})
	if err != nil {
		slog.Error("authorized_keys_lookup_failed")
		return 1
	}
	if err := authkeys.WriteIngressKeys(os.Stdout, lines); err != nil {
		slog.Error("authorized_keys_write_failed")
		return 1
	}
	return 0
}

func boundedIngressLookup(ctx context.Context, lookup func(context.Context) ([]string, error)) ([]string, error) {
	type result struct {
		lines []string
		err   error
	}
	done := make(chan result, 1)
	go func() {
		lines, err := lookup(ctx)
		done <- result{lines, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return r.lines, r.err
	}
}

func bootstrapFDArg() (int, bool, error) {
	const prefix = "--bootstrap-fd="
	if len(os.Args) > 1 && strings.HasPrefix(os.Args[1], prefix) {
		n, err := strconv.Atoi(strings.TrimPrefix(os.Args[1], prefix))
		if err != nil || n <= 2 || n > 1024 {
			return 0, true, errors.New("invalid bootstrap descriptor")
		}
		return n, true, nil
	}
	return 0, false, nil
}

func loadBootstrapFD(fd int) error {
	f := os.NewFile(uintptr(fd), "bootstrap")
	if f == nil {
		return fmt.Errorf("invalid bootstrap fd")
	}
	defer func() { _ = f.Close() }()
	return readBootstrap(f)
}

func readBootstrap(r io.Reader) error {
	allowed := map[string]bool{
		"DB_DRIVER": true, "DB_DSN": true,
		"EGRESS_ENC_KEY": true, "EGRESS_ENC_KEY_ID": true, "EGRESS_ENC_KEYS": true,
		"INSTANCE_ID": true, "OBS_ENABLED": true,
		"OTEL_SDK_DISABLED": true, "OTEL_TRACES_EXPORTER": true,
		"OTEL_EXPORTER_OTLP_ENDPOINT": true, "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": true,
		"OTEL_EXPORTER_OTLP_ALLOW_HTTP_LOOPBACK": true, "OTEL_SERVICE_NAME": true,
	}
	const maxBootstrapBytes = 1024 * 1024
	input := &io.LimitedReader{R: r, N: maxBootstrapBytes + 1}
	sc := bufio.NewScanner(input)
	// Bootstrap payloads are small; keep a sane cap.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	values := make(map[string]string)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || !allowed[key] {
			continue
		}
		if strings.ContainsRune(value, '\x00') {
			return errors.New("invalid bootstrap value")
		}
		values[key] = value
	}
	if err := sc.Err(); err != nil {
		return err
	}
	if input.N == 0 {
		return errors.New("bootstrap size limit exceeded")
	}
	for key, value := range values {
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}
	return nil
}

func stripBootstrapFDArg(args []string) []string {
	if len(args) > 1 && strings.HasPrefix(args[1], "--bootstrap-fd=") {
		return append([]string{args[0]}, args[2:]...)
	}
	return args
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
	if username, ok := authorizedKeysArg(); ok {
		return runAuthorizedKeys(username)
	}

	// Install the logger first so bootstrap logs (config.Load) are written to
	// the log file, not the client console. NewLogger uses the default config
	// path and does not trigger Load(), so this runs before bootstrap.
	log := logger.NewLogger()
	slog.SetDefault(log)

	// G1: accept bootstrap secrets from an inherited fd (wrapper passes
	// --bootstrap-fd=N) so they do not appear in the process's initial
	// environment (/proc/<pid>/environ). The fd content is read once, loaded
	// into process env for legacy bootstrap code, and the fd is closed.
	if fd, ok, err := bootstrapFDArg(); err != nil {
		log.Error("bootstrap_fd_invalid")
		return 1
	} else if ok {
		if err := loadBootstrapFD(fd); err != nil {
			log.Error("bootstrap_fd_failed")
			return 1
		}
		os.Args = stripBootstrapFDArg(os.Args)
	}

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

	// Bootstrap secrets were cleared earlier after DB/keyring
	// initialization to prevent inheritance by child processes (ssh, ttyrec,
	// mosh-server). Re-affirm crypto materialization for the session path.
	_ = cryptokey.Enabled()

	log.Info("startup_total", slog.Duration("took", time.Since(tStart)))
	return session.Run(db, log)
}
