package sync

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
)

func TestKnownHostsPreservesDistinctCanonicalAccountNames(t *testing.T) {
	database, cfg := newSyncTestDB(t)
	account := models.User{Username: "alice..ops", Enabled: true, Role: models.RoleUser}
	if err := database.Create(&account).Error; err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(cfg.Paths.HomeBaseDir, "alice_ops", ".ssh")
	if err := os.MkdirAll(alias, 0700); err != nil {
		t.Fatal(err)
	}
	aliasFile := filepath.Join(alias, "known_hosts")
	if err := os.WriteFile(aliasFile, []byte("unrelated account\n"), 0600); err != nil {
		t.Fatal(err)
	}
	entry := models.KnownHostsEntry{UserID: account.ID, Entry: "literal account host"}
	if err := database.Create(&entry).Error; err != nil {
		t.Fatal(err)
	}
	syncer := New(database, osadapter.NewMockAdapter(), *slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := syncer.KnownHostsFromDB(&account); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(cfg.Paths.HomeBaseDir, account.Username, ".ssh", "known_hosts")
	if data, err := os.ReadFile(path); err != nil || string(data) != "literal account host\n" {
		t.Fatalf("literal home publication: %q %v", data, err)
	}
	if data, err := os.ReadFile(aliasFile); err != nil || string(data) != "unrelated account\n" {
		t.Fatalf("other account changed: %q %v", data, err)
	}
	if err := os.WriteFile(path, []byte("new literal host\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := syncer.KnownHostsEntriesFromSystemToDb(&account); err != nil {
		t.Fatal(err)
	}
	var entries []models.KnownHostsEntry
	if err := database.Where("user_id = ?", account.ID).Find(&entries).Error; err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Entry != "new literal host" {
		t.Fatalf("wrong account imported: %+v", entries)
	}
	for _, name := range []string{"realm/alice", "../alice", "ALICE", "gobastion-session"} {
		invalid := models.User{Username: name}
		if err := syncer.KnownHostsFromDB(&invalid); err == nil {
			t.Fatalf("invalid identity %q published", name)
		}
		if err := syncer.KnownHostsEntriesFromSystemToDb(&invalid); err == nil {
			t.Fatalf("invalid identity %q imported", name)
		}
	}
}
