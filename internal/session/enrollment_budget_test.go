package session

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestConcurrentEnrollmentPasswordAttemptsShareBudget(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	cfg := config.DefaultConfig()
	cfg.RequireMFA.Enabled = true
	cfg.MFA.MaxAttempts = 1
	config.SetForTesting(cfg)

	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "enrollment.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	pool, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	pool.SetMaxOpenConns(4)
	t.Cleanup(func() { _ = pool.Close() })
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("fixture-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := models.User{Username: "enrollment", Enabled: true, PasswordHash: string(hash)}
	if err := db.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	originalStdin := os.Stdin
	os.Stdin = input
	t.Cleanup(func() { os.Stdin = originalStdin; _ = input.Close() })

	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	start := make(chan struct{})
	results := make(chan bool, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			results <- checkMFAForRequest(db, &u, log, []string{"-osh", "selfSetupTOTP"})
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	for accepted := range results {
		if accepted {
			t.Fatal("enrollment accepted an unreadable password factor")
		}
	}
	var fresh models.User
	if err := db.First(&fresh, "id = ?", u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if fresh.MFAWindowAttempts != 1 {
		t.Fatalf("concurrent enrollment attempts charged %d slots, want one", fresh.MFAWindowAttempts)
	}
	if checkMFAForRequest(db, &u, log, []string{"-osh", "selfSetupTOTP"}) {
		t.Fatal("enrollment bypassed the exhausted shared MFA budget")
	}
	if err := db.First(&fresh, "id = ?", u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if fresh.MFAWindowAttempts != 1 {
		t.Fatalf("denied enrollment changed exhausted budget to %d", fresh.MFAWindowAttempts)
	}
}

func TestEnrollmentPasswordAttemptFailsClosedOnDatabaseLoss(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	cfg := config.DefaultConfig()
	cfg.RequireMFA.Enabled = true
	config.SetForTesting(cfg)
	u := models.User{Username: "enrollment", Enabled: true, PasswordHash: "configured-factor"}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if checkMFAForRequest(nil, &u, log, []string{"-osh", "selfSetupTOTP"}) {
		t.Fatal("enrollment accepted password factor without shared database")
	}
}
