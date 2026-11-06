package session

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/totp"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestDatabaseConnectionEnforcesPolicies(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		enabled, mfa                 bool
		guest, validCode, wantLaunch bool
	}{
		{"disabled database", false, false, false, false, false},
		{"required group MFA", true, true, false, false, false},
		{"required guest MFA", true, true, true, false, false},
		{"valid JIT code", true, true, false, true, true},
		{"unprotected database", true, false, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config.ResetForTesting()
			_ = config.Load()
			t.Cleanup(config.ResetForTesting)
			cfg := config.DefaultConfig()
			cfg.Database.Enabled = tc.enabled
			cfg.TTYRec.Enabled = false
			config.SetForTesting(cfg)
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if err = db.AutoMigrate(&models.User{}, &models.Group{}, &models.UserGroup{}, &models.SelfDBAccess{}, &models.GroupDBAccess{}, &models.GroupGuestDBAccess{}, &models.DatabaseAlias{}); err != nil {
				t.Fatal(err)
			}
			u := models.User{Username: "audit", Role: models.RoleUser, Enabled: true}
			if tc.validCode {
				u.TOTPSecret = "JBSWY3DPEHPK3PXP"
			}
			mustPolicyCreate(t, db, &u)
			g := models.Group{Name: "audit", MFARequired: tc.mfa}
			mustPolicyCreate(t, db, &g)
			role := models.GroupRoleMember
			if tc.guest {
				role = models.GroupRoleGuest
			}
			mustPolicyCreate(t, db, &models.UserGroup{UserID: u.ID, GroupID: g.ID, Role: role})
			if tc.guest {
				mustPolicyCreate(t, db, &models.GroupGuestDBAccess{GroupID: g.ID, UserID: u.ID, Host: "audit.invalid", Port: 3306, Protocol: "mysql", Username: "reader"})
			}
			mustPolicyCreate(t, db, &models.GroupDBAccess{GroupID: g.ID, Host: "audit.invalid", Port: 3306, Protocol: "mysql", Username: "reader"})
			dir := t.TempDir()
			marker := filepath.Join(dir, "launched")
			oldConnect := connectDB
			t.Cleanup(func() { connectDB = oldConnect })
			connectDB = func(_ *gorm.DB, _ models.User, _ models.DBAccessRight) error {
				return os.WriteFile(marker, []byte("launched"), 0600)
			}
			script := []byte("#!/bin/sh\nprintf launched > '" + marker + "'\n")
			for _, name := range []string{"mysql", "mariadb"} {
				if err = os.WriteFile(filepath.Join(dir, name), script, 0755); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			if tc.validCode {
				code, err := totp.GenerateCode(u.TOTPSecret, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				input, writer, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				if _, err = writer.WriteString(code + "\n"); err != nil {
					t.Fatal(err)
				}
				_ = writer.Close()
				original := os.Stdin
				os.Stdin = input
				defer func() { os.Stdin = original; _ = input.Close() }()
			}
			runNonInteractiveMode(db, &u, slog.New(slog.NewTextHandler(io.Discard, nil)), "--db", []string{"reader@audit.invalid:3306:mysql"})
			_, err = os.Stat(marker)
			if tc.wantLaunch && err != nil {
				t.Fatalf("authorized DB client did not launch: %v", err)
			}
			if !tc.wantLaunch && !os.IsNotExist(err) {
				t.Fatalf("policy must prevent DB client launch: %v", err)
			}

		})
	}
}

func TestSFTPSessionEnforcesAccountMFA(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("SSH sessions run as a non-root account")
	}
	for _, policy := range []string{"password", "totp", "global"} {
		t.Run(policy, func(t *testing.T) {
			config.ResetForTesting()
			_ = config.Load()
			t.Cleanup(config.ResetForTesting)
			cfg := config.DefaultConfig()
			cfg.RequireMFA.Enabled = policy == "global"
			cfg.Splash.Enabled = false
			cfg.Paths.HomeBaseDir = t.TempDir()
			config.SetForTesting(cfg)
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if err = db.AutoMigrate(&models.User{}, &models.ActiveSession{}, &models.SelfAccess{}, &models.SelfEgressKey{}, &models.Group{}, &models.UserGroup{}, &models.GroupAccess{}, &models.GroupGuestAccess{}, &models.Aliases{}, &models.KnownHostsEntry{}); err != nil {
				t.Fatal(err)
			}
			name, err := currentSystemUser()
			if err != nil {
				t.Fatal(err)
			}
			u := models.User{Username: name, Role: models.RoleUser, Enabled: true, PasswordHash: "invalid-hash", TOTPEnabled: true, TOTPSecret: "invalid-secret"}
			if policy != "password" {
				u.PasswordHash = ""
			}
			if policy != "totp" {
				u.TOTPEnabled = false
				u.TOTPSecret = ""
			}
			mustPolicyCreate(t, db, &u)
			mustPolicyCreate(t, db, &models.SelfAccess{UserID: u.ID, Username: "deploy", Server: "audit.invalid", Port: 22, Protocol: "sftp"})
			mustPolicyCreate(t, db, &models.SelfEgressKey{UserID: u.ID, PrivKey: "invalid-private-key", PubKey: "invalid"})
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "ssh-keyscan"), []byte("#!/bin/sh\nexit 1\n"), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			oldArgs := os.Args
			os.Args = []string{"audit", "sftp-session deploy@audit.invalid"}
			defer func() { os.Args = oldArgs }()
			var log bytes.Buffer
			stdout, stderr, _, captureErr := captureOutput(func() error { Run(db, slog.New(slog.NewTextHandler(&log, nil))); return nil })
			if captureErr != nil {
				t.Fatal(captureErr)
			}
			if strings.Contains(log.String(), "parse egress key") || strings.Contains(log.String(), "sftp_session_failed") {
				t.Fatalf("MFA-protected SFTP reached proxy: %s", log.String())
			}
			if !strings.Contains(stdout+stderr, "MFA") {
				t.Fatalf("expected explicit MFA refusal, got %q", stdout+stderr)
			}

		})
	}
}

func TestExistingSessionLosesRevokedAdmin(t *testing.T) {
	for _, change := range []string{"demoted", "disabled", "deleted"} {
		t.Run(change, func(t *testing.T) {
			config.ResetForTesting()
			_ = config.Load()
			t.Cleanup(config.ResetForTesting)
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if err = db.AutoMigrate(&models.User{}, &models.UserGroup{}); err != nil {
				t.Fatal(err)
			}
			u := models.User{Username: "audit", Role: models.RoleAdmin, Enabled: true}
			mustPolicyCreate(t, db, &u)
			switch change {
			case "demoted":
				err = db.Model(&models.User{}).Where("id = ?", u.ID).Update("role", models.RoleUser).Error
			case "disabled":
				err = db.Model(&models.User{}).Where("id = ?", u.ID).Update("enabled", false).Error
			case "deleted":
				fresh := u
				err = db.Delete(&fresh).Error
			}
			if err != nil {
				t.Fatal(err)
			}
			_, _, runErr, capErr := captureOutput(func() error {
				return executeCommand(db, &u, slog.New(slog.NewTextHandler(io.Discard, nil)), "accountList", nil)
			})
			if capErr != nil || !errors.Is(runErr, ErrPermissionDenied) {
				t.Fatalf("revoked session must be blocked: %v / %v", runErr, capErr)
			}
		})
	}
}

func TestInteractiveRestrictionsCoverAllEntryPoints(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("SSH sessions run as a non-root account")
	}
	for _, policy := range []string{"account", "instance", "interactive disabled"} {
		for _, entry := range [][]string{nil, {"--"}, {" "}, {"-osh"}, {"-osh "}} {
			t.Run(policy+fmt.Sprint(entry), func(t *testing.T) {
				config.ResetForTesting()
				_ = config.Load()
				t.Cleanup(config.ResetForTesting)
				cfg := config.DefaultConfig()
				cfg.Splash.Enabled = false
				cfg.ForceOSHOnly.Enabled = policy == "instance"
				cfg.Interactive.Enabled = policy != "interactive disabled"
				config.SetForTesting(cfg)
				db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
				if err != nil {
					t.Fatal(err)
				}
				if err = db.AutoMigrate(&models.User{}, &models.ActiveSession{}); err != nil {
					t.Fatal(err)
				}
				name, err := currentSystemUser()
				if err != nil {
					t.Fatal(err)
				}
				u := models.User{Username: name, Role: models.RoleUser, Enabled: true, OSHOnly: policy == "account"}
				mustPolicyCreate(t, db, &u)
				oldArgs := os.Args
				os.Args = append([]string{"bastion"}, entry...)
				defer func() { os.Args = oldArgs }()
				out, stderr, _, err := captureOutput(func() error { Run(db, slog.New(slog.NewTextHandler(io.Discard, nil))); return nil })
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(out+stderr, "Type 'help'") || (!strings.Contains(out+stderr, "disabled") && !strings.Contains(out+stderr, "Usage:")) {
					t.Fatalf("interactive restriction missing: %q", out+stderr)
				}
			})
		}
	}
}

func mustPolicyCreate(t *testing.T, db *gorm.DB, model any) {
	t.Helper()
	if err := db.Create(model).Error; err != nil {
		t.Fatal(err)
	}
}
