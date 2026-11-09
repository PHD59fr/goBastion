package main

import (
	"encoding/base64"
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestRunMainReturnsNonInteractiveCommandFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("ForceCommand sessions run as a non-root account")
	}
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name    string
		command string
		want    int
	}{
		{name: "known command", command: "info", want: 0},
		{name: "unknown command", command: "notACommand", want: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config.ResetForTesting()
			t.Cleanup(config.ResetForTesting)
			dsn := "file:" + filepath.Join(t.TempDir(), "bastion.db") + "?cache=shared&mode=rwc"
			t.Setenv("DB_DRIVER", "sqlite")
			t.Setenv("DB_DSN", dsn)
			t.Setenv("EGRESS_ENC_KEY", base64.StdEncoding.EncodeToString(make([]byte, 32)))
			t.Setenv("INSTANCE_ID", "test-main-status")
			db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			sqlDB, err := db.DB()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = sqlDB.Close() })
			if err := db.AutoMigrate(&models.BastionInstance{}, &models.User{}, &models.ActiveSession{}); err != nil {
				t.Fatal(err)
			}
			if err := db.Create(&models.BastionInstance{InstanceID: "test-main-status", Role: "master", Config: "{}"}).Error; err != nil {
				t.Fatal(err)
			}
			account := models.User{Username: current.Username, Role: models.RoleUser, Enabled: true}
			if err := db.Create(&account).Error; err != nil {
				t.Fatal(err)
			}
			originalArgs := os.Args
			t.Cleanup(func() { os.Args = originalArgs })
			os.Args = []string{"goBastion", "-osh", tt.command}
			if got := runMain(); got != tt.want {
				t.Fatalf("runMain status = %d, want %d", got, tt.want)
			}
			if err := db.First(&account, account.ID).Error; err != nil {
				t.Fatal(err)
			}
			if account.LastLoginAt.IsZero() {
				t.Fatal("command did not reach authenticated session dispatch")
			}
			var active int64
			if err := db.Model(&models.ActiveSession{}).Count(&active).Error; err != nil {
				t.Fatal(err)
			}
			if active != 0 {
				t.Fatalf("runMain left %d active session rows", active)
			}
		})
	}
}
