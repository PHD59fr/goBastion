package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestRunNonInteractiveStatusAndSessionRelease(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("ForceCommand sessions run as a non-root account")
	}
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	cfg := config.DefaultConfig()
	cfg.Splash.Enabled = false
	config.SetForTesting(cfg)
	db, err := gorm.Open(sqlite.Open("file:status-test?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&models.User{}, &models.ActiveSession{}); err != nil {
		t.Fatal(err)
	}
	name, err := currentSystemUser()
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	originalArgs := os.Args
	t.Cleanup(func() { os.Args = originalArgs })

	os.Args = []string{"bastion", "-osh", "notACommand"}
	if got := Run(db, log); got != 1 {
		t.Fatalf("unregistered user exit status = %d, want 1", got)
	}
	user := models.User{Username: name, Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		args []string
		want int
	}{
		{name: "unknown command", args: []string{"-osh", "notACommand"}, want: 1},
		{name: "missing osh command", args: []string{"-osh"}, want: 1},
		{name: "denied local mosh", args: []string{"mosh-server", "new"}, want: 1},
		{name: "successful help", args: []string{"-osh", "help"}, want: 0},
		{name: "intentional exit", args: []string{"-osh", "exit"}, want: 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			os.Args = append([]string{"bastion"}, tt.args...)
			if got := Run(db, log); got != tt.want {
				t.Fatalf("Run exit status = %d, want %d", got, tt.want)
			}
			var active int64
			if err := db.Model(&models.ActiveSession{}).Count(&active).Error; err != nil {
				t.Fatal(err)
			}
			if active != 0 {
				t.Fatalf("Run left %d active session rows", active)
			}
		})
	}
}

func TestExitStatusPreservesChildCode(t *testing.T) {
	err := exec.Command("sh", "-c", "exit 23").Run()
	if got := exitStatus(err); got != 23 {
		t.Fatalf("child exit status = %d, want 23", got)
	}
	if got := exitStatus(fmt.Errorf("wrapped child: %w", err)); got != 23 {
		t.Fatalf("wrapped child exit status = %d, want 23", got)
	}
	signalErr := exec.Command("sh", "-c", "kill -TERM $$").Run()
	if got := exitStatus(signalErr); got != 143 {
		t.Fatalf("signaled child exit status = %d, want 143", got)
	}
	if got := exitStatus(errors.New("denied")); got != 1 {
		t.Fatalf("ordinary error status = %d, want 1", got)
	}
	if got := exitStatus(nil); got != 0 {
		t.Fatalf("successful status = %d, want 0", got)
	}
}

func TestJSONCaptureFailureReturnsErrorAndEmitsJSON(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatal(err)
	}
	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	// Each execution refreshes the account before dispatch. Count those
	// queries to catch an accidental second command run after capture fails.
	executions := 0
	if err := db.Callback().Query().After("gorm:query").Register("test:json-executions", func(tx *gorm.DB) {
		if _, ok := tx.Statement.Dest.(*models.User); ok {
			executions++
		}
	}); err != nil {
		t.Fatal(err)
	}
	prior := captureCommandOutput
	t.Cleanup(func() { captureCommandOutput = prior })
	want := errors.New("capture failed")
	runs := 0
	captureCommandOutput = func(run func() error) (string, string, error, error) {
		runs++
		stdout, stderr, runErr, capErr := captureOutput(run)
		if capErr != nil {
			t.Fatalf("fixture capture failed before simulated post-run error: %v", capErr)
		}
		return stdout, stderr, runErr, want
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	stdout, _, runErr, capErr := captureOutput(func() error {
		return executeCommandJSONAware(db, &user, log, "info", []string{"--json"})
	})
	if capErr != nil || !errors.Is(runErr, want) {
		t.Fatalf("capture failure status = run %v, capture %v", runErr, capErr)
	}
	if runs != 1 {
		t.Fatalf("command capture invoked %d times, want exactly once", runs)
	}
	if executions != 1 {
		t.Fatalf("command executed %d times after capture failure, want exactly once", executions)
	}
	var payload map[string]any
	jsonBody := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(stdout, "JSON_START\n"), "JSON_END\n"))
	if err := json.Unmarshal([]byte(jsonBody), &payload); err != nil {
		t.Fatalf("invalid JSON response %q: %v", stdout, err)
	}
	if payload["error_code"] != "ERR_CAPTURE" {
		t.Fatalf("JSON error_code = %v, want ERR_CAPTURE", payload["error_code"])
	}
}
