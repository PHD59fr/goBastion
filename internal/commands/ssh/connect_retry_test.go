package ssh

import (
	"errors"
	"io"
	"log/slog"
	"os/exec"
	"strings"
	"testing"

	"goBastion/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func TestConnectWithKeysRemoteCommandDoesNotRetry(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  func(*testing.T) error
	}{
		{name: "remote_exit_1", err: func(t *testing.T) error { return exec.Command("sh", "-c", "exit 1").Run() }},
		{name: "ssh_status_255", err: func(t *testing.T) error { return exec.Command("sh", "-c", "exit 255").Run() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, user, keys := twoEligibleTestKeys(t)
			firstErr := tc.err(t)
			if firstErr == nil {
				t.Fatal("expected an exit error")
			}
			calls := 0
			run := func(_ *gorm.DB, _ models.User, access models.AccessRight) error {
				calls++
				if access.RemoteCmd != "run-task" {
					t.Fatalf("remote command = %q", access.RemoteCmd)
				}
				if calls == 1 {
					return firstErr
				}
				return nil
			}
			err := connectWithKeys(db, user, discardSSHTestLogger(), keys, "run-task", nil, sshLogTarget{user: "deploy", host: "host", port: "22"}, run)
			if !errors.Is(err, firstErr) || calls != 1 {
				t.Fatalf("remote command attempts=%d, error=%v; want one attempt and original error", calls, err)
			}
		})
	}
}

func TestConnectWithKeysInteractiveFallback(t *testing.T) {
	db, user, keys := twoEligibleTestKeys(t)
	firstErr := errors.New("first key failed")
	calls := 0
	run := func(_ *gorm.DB, _ models.User, access models.AccessRight) error {
		calls++
		if access.RemoteCmd != "" {
			t.Fatalf("interactive access gained remote command %q", access.RemoteCmd)
		}
		if calls == 1 {
			return firstErr
		}
		return nil
	}
	if err := connectWithKeys(db, user, discardSSHTestLogger(), keys, "", nil, sshLogTarget{user: "deploy", host: "host", port: "22"}, run); err != nil || calls != 2 {
		t.Fatalf("interactive key attempts=%d, error=%v; want second key success", calls, err)
	}
}

func TestConnectWithKeysAllEmptyKeysReturnsError(t *testing.T) {
	db := newTestDB(t)
	user := mustCreateUser(t, db, "alice", models.RoleUser)
	accesses := []models.AccessRight{{Source: "first"}, {Source: "second"}}
	run := func(_ *gorm.DB, _ models.User, _ models.AccessRight) error {
		t.Fatal("SSH must not be invoked for empty key IDs")
		return nil
	}
	err := connectWithKeys(db, user, discardSSHTestLogger(), accesses, "run-task", nil, sshLogTarget{user: "deploy", host: "host", port: "22"}, run)
	if err == nil || !strings.Contains(err.Error(), "no usable SSH egress key found for deploy@host:22") {
		t.Fatalf("all empty keys must return an actionable error, got %v", err)
	}
}

func twoEligibleTestKeys(t *testing.T) (*gorm.DB, models.User, []models.AccessRight) {
	t.Helper()
	db := newTestDB(t)
	user := mustCreateUser(t, db, "alice", models.RoleUser)
	keys := make([]models.AccessRight, 0, 2)
	for i := 0; i < 2; i++ {
		access := models.SelfAccess{UserID: user.ID, Username: "deploy", Server: "host", Port: 22, Protocol: "ssh"}
		if err := db.Create(&access).Error; err != nil {
			t.Fatal(err)
		}
		keys = append(keys, models.AccessRight{ID: access.ID, Type: "self", Source: "test-key", KeyId: uuid.New(), KeyType: "ed25519", KeySize: 256})
	}
	return db, user, keys
}

func discardSSHTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
