package session

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"goBastion/internal/config"
	"goBastion/internal/models"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func TestDeniedMFAIsNotRecordedAsLogin(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("uses the unprivileged SSH login path")
	}
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	cfg := config.DefaultConfig()
	cfg.Splash.Enabled = false
	cfg.RequireMFA.Enabled = true
	config.SetForTesting(cfg)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatal(err)
	}
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	u := models.User{Username: "alice", Enabled: true, Role: models.RoleUser, LastLoginAt: old}
	if err := db.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&logs, nil))
	if !preConnectionCheck(db, u, log) {
		t.Fatal("fixture failed initial account checks")
	}
	if checkMFA(db, &u, log) {
		t.Fatal("fixture unexpectedly passed mandatory TOTP without enrollment")
	}
	var after models.User
	if err := db.First(&after, "id = ?", u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if !after.LastLoginAt.Equal(old) {
		t.Fatalf("denied MFA changed LastLoginAt from %s to %s", old, after.LastLoginAt)
	}
	if strings.Contains(logs.String(), `"msg":"login"`) {
		t.Fatal("denied authentication emitted a successful login")
	}
}

func TestAuthenticatedLoginRequiresActiveAccount(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	t.Cleanup(config.ResetForTesting)
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatal(err)
	}
	exerciseLoginHistory(t, db)
}

func TestLoginHistoryIntegration(t *testing.T) {
	if os.Getenv("GOB_POLICY_INTEGRATION") != "1" {
		t.Skip("requires disposable database fixtures")
	}
	for _, tc := range []struct {
		name      string
		dialector gorm.Dialector
	}{
		{"postgres", postgres.Open("host=127.0.0.1 port=55432 user=postgres dbname=policytest sslmode=disable")},
		{"mysql", mysql.Open("root@tcp(127.0.0.1:53306)/policytest?parseTime=true")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, err := gorm.Open(tc.dialector, &gorm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			sqlDB, err := db.DB()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = sqlDB.Close() }()
			exerciseLoginHistory(t, db)
		})
	}
}

func exerciseLoginHistory(t *testing.T, db *gorm.DB) {
	t.Helper()
	t.Setenv("SSH_CLIENT", "192.0.2.20 12345 22")
	old := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, state := range []string{"enabled", "disabled", "system", "deleted"} {
		t.Run(state, func(t *testing.T) {
			u := models.User{Username: "login-history-" + state, Enabled: true, Role: models.RoleUser, LastLoginAt: old}
			if err := db.Create(&u).Error; err != nil {
				t.Fatal(err)
			}
			switch state {
			case "disabled":
				if err := db.Model(&u).Update("enabled", false).Error; err != nil {
					t.Fatal(err)
				}
			case "system":
				if err := db.Model(&u).Update("system_user", true).Error; err != nil {
					t.Fatal(err)
				}
			case "deleted":
				if err := db.Model(&u).Update("deleted_at", time.Now()).Error; err != nil {
					t.Fatal(err)
				}
			}
			var logs bytes.Buffer
			ok := recordAuthenticatedLogin(db, u, slog.New(slog.NewJSONHandler(&logs, nil)))
			if ok != (state == "enabled") {
				t.Fatalf("recorded=%t for %s", ok, state)
			}
			var after models.User
			if err := db.Unscoped().First(&after, "id = ?", u.ID).Error; err != nil {
				t.Fatal(err)
			}
			if state == "enabled" {
				if !after.LastLoginAt.After(old) || after.LastLoginFrom != "192.0.2.20" {
					t.Fatalf("missing successful login history: %+v", after)
				}
			} else if !after.LastLoginAt.Equal(old) {
				t.Fatal("revoked account history changed")
			}
			if strings.Contains(logs.String(), `"msg":"login"`) != ok {
				t.Fatalf("incorrect login event: %s", logs.String())
			}
			if !u.LastLoginAt.Equal(old) {
				t.Fatal("welcome snapshot was overwritten")
			}
		})
	}
}
