package sshConnector

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestIPv6HostKeyScanAndChangeDetection(t *testing.T) {
	for _, port := range []int64{22, 2222} {
		t.Run(strconv.FormatInt(port, 10), func(t *testing.T) {
			dir := t.TempDir()
			cfg := config.DefaultConfig()
			cfg.Paths.HomeBaseDir = dir
			cfg.SSH.HostKeyTTL = 0 // Re-scan to verify key change detection.
			_ = config.Load()
			config.SetForTesting(cfg)
			t.Cleanup(config.ResetForTesting)
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.AutoMigrate(&models.User{}, &models.KnownHostsEntry{}); err != nil {
				t.Fatal(err)
			}
			current, err := user.Current()
			if err != nil {
				t.Fatal(err)
			}
			user := models.User{Username: current.Username, Role: models.RoleUser, Enabled: true}
			if err := db.Create(&user).Error; err != nil {
				t.Fatal(err)
			}
			token := "2001:db8::1"
			if port != 22 {
				token = fmt.Sprintf("[%s]:%d", token, port)
			}
			argsFile := filepath.Join(dir, "scan.args")
			keyFile := filepath.Join(dir, "scan.key")
			t.Setenv("TEST_SCAN_ARGS", argsFile)
			t.Setenv("TEST_SCAN_KEY", keyFile)
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			if err := os.WriteFile(filepath.Join(dir, "ssh-keyscan"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$TEST_SCAN_ARGS\"\ncat \"$TEST_SCAN_KEY\"\n"), 0700); err != nil {
				t.Fatal(err)
			}
			entry := token + " ssh-ed25519 AAAAold\n"
			if err := os.WriteFile(keyFile, []byte(entry), 0600); err != nil {
				t.Fatal(err)
			}
			if err := CheckAndUpdateHostKey(db, user, "[2001:db8::1]", port); err != nil {
				t.Fatal(err)
			}
			args, err := os.ReadFile(argsFile)
			if err != nil || !strings.HasSuffix(string(args), "\n2001:db8::1\n") {
				t.Fatalf("keyscan must receive bare IPv6: args=%q, err=%v", args, err)
			}
			knownHosts, err := os.ReadFile(filepath.Join(dir, user.Username, ".ssh", "known_hosts"))
			if err != nil || string(knownHosts) != entry {
				t.Fatalf("known_hosts=%q, err=%v", knownHosts, err)
			}
			if err := os.WriteFile(keyFile, []byte(token+" ssh-ed25519 AAAAnew\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := CheckAndUpdateHostKey(db, user, "2001:db8::1", port); err == nil || !strings.Contains(err.Error(), "Host key verification failed") {
				t.Fatalf("changed IPv6 host key must be rejected: %v", err)
			}
		})
	}
}

func TestHostKeyTTLRefreshAfterUnchangedScan(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Paths.HomeBaseDir = dir
	cfg.SSH.HostKeyTTL = config.Duration(time.Hour)
	cfg.SSH.KeyscanTimeout = config.Duration(time.Second)
	_ = config.Load()
	config.SetForTesting(cfg)
	t.Cleanup(config.ResetForTesting)

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.KnownHostsEntry{}); err != nil {
		t.Fatal(err)
	}
	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}

	keyFile := filepath.Join(dir, "scan.key")
	countFile := filepath.Join(dir, "scan.count")
	t.Setenv("TEST_SCAN_KEY", keyFile)
	t.Setenv("TEST_SCAN_COUNT", countFile)
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	writeScan := func(body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "ssh-keyscan"), []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeScan("#!/bin/sh\n" +
		"count=0\n" +
		"[ -f \"$TEST_SCAN_COUNT\" ] && count=$(cat \"$TEST_SCAN_COUNT\")\n" +
		"count=$((count+1))\n" +
		"printf '%s' \"$count\" > \"$TEST_SCAN_COUNT\"\n" +
		"cat \"$TEST_SCAN_KEY\"\n")
	entry := "host.example ssh-ed25519 AAAAkey\n"
	if err := os.WriteFile(keyFile, []byte(entry), 0600); err != nil {
		t.Fatal(err)
	}
	scanCount := func() int {
		t.Helper()
		data, err := os.ReadFile(countFile)
		if err != nil {
			t.Fatalf("read scan count: %v", err)
		}
		n, err := strconv.Atoi(string(data))
		if err != nil {
			t.Fatalf("parse scan count: %v", err)
		}
		return n
	}
	entryTimestamp := func() time.Time {
		t.Helper()
		var stored models.KnownHostsEntry
		if err := db.First(&stored).Error; err != nil {
			t.Fatalf("load known host entry: %v", err)
		}
		return stored.UpdatedAt
	}

	if err := CheckAndUpdateHostKey(db, user, "host.example", 22); err != nil {
		t.Fatal(err)
	}
	if got := scanCount(); got != 1 {
		t.Fatalf("initial scans = %d, want 1", got)
	}

	stale := time.Now().Add(-2 * time.Hour)
	if err := db.Model(&models.KnownHostsEntry{}).Where("user_id = ?", user.ID).UpdateColumn("updated_at", stale).Error; err != nil {
		t.Fatal(err)
	}
	if err := CheckAndUpdateHostKey(db, user, "host.example", 22); err != nil {
		t.Fatal(err)
	}
	if got := scanCount(); got != 2 {
		t.Fatalf("stale entry scans = %d, want 2", got)
	}
	refreshed := entryTimestamp()
	if !refreshed.After(stale) {
		t.Fatalf("unchanged scan did not refresh timestamp: %s", refreshed)
	}

	if err := CheckAndUpdateHostKey(db, user, "host.example", 22); err != nil {
		t.Fatal(err)
	}
	if got := scanCount(); got != 2 {
		t.Fatalf("fresh entry was rescanned: %d scans", got)
	}

	if err := db.Model(&models.KnownHostsEntry{}).Where("user_id = ?", user.ID).UpdateColumn("updated_at", stale).Error; err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, []byte("host.example ssh-ed25519 AAAAchanged\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckAndUpdateHostKey(db, user, "host.example", 22); err == nil || !strings.Contains(err.Error(), "Host key verification failed") {
		t.Fatalf("changed key was not rejected: %v", err)
	}
	if got := scanCount(); got != 3 {
		t.Fatalf("changed-key scans = %d, want 3", got)
	}
	if got := entryTimestamp(); got.After(stale.Add(time.Second)) {
		t.Fatalf("changed key refreshed the verification timestamp: %s", got)
	}

	writeScan("#!/bin/sh\nexit 1\n")
	if err := os.WriteFile(keyFile, []byte(entry), 0600); err != nil {
		t.Fatal(err)
	}
	if err := CheckAndUpdateHostKey(db, user, "host.example", 22); err != nil {
		t.Fatalf("scan failure must leave SSH to fail naturally: %v", err)
	}
	if got := scanCount(); got != 3 {
		t.Fatalf("failed scan counter = %d, want 3", got)
	}
	if got := entryTimestamp(); got.After(stale.Add(time.Second)) {
		t.Fatalf("failed scan refreshed the verification timestamp: %s", got)
	}
}

func commandExitError(t *testing.T, code string) error {
	t.Helper()
	return exec.Command("sh", "-c", "exit "+code).Run()
}

func TestCleanInteractiveSessionExit(t *testing.T) {
	if err := commandExitError(t, "1"); !isCleanInteractiveSessionExit(err) {
		t.Fatal("exit status 1 after an interactive shell logout should be accepted")
	}
	if err := commandExitError(t, "254"); !isCleanInteractiveSessionExit(err) {
		t.Fatal("a remote interactive shell exit status should be accepted")
	}
	if err := commandExitError(t, "255"); isCleanInteractiveSessionExit(err) {
		t.Fatal("SSH transport/setup exit status 255 must be reported")
	}
}

func TestExpectedSessionStop(t *testing.T) {
	if err := commandExitError(t, "130"); !isExpectedSessionStop(err) {
		t.Fatal("exit status 130 should be accepted")
	}
	if err := commandExitError(t, "1"); isExpectedSessionStop(err) {
		t.Fatal("exit status 1 is not a generic expected stop")
	}
}
