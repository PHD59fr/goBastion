package self

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"goBastion/internal/models"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

func generateIngressTestPublicKey(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func TestAddIngressKey_RejectsInvalidArgumentsBeforeRegistration(t *testing.T) {
	key := generateIngressTestPublicKey(t)
	parts := strings.Split(key, " ")
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing flag", nil, "required"},
		{"missing value", []string{"--key"}, "needs an argument"},
		{"empty value", []string{"--key", ""}, "required"},
		{"whitespace value", []string{"--key", " \t "}, "required"},
		{"key type only", []string{"--key", "ssh-rsa"}, "invalid ssh key"},
		{"invalid base64", []string{"--key", parts[0] + " !!!!"}, "invalid ssh key"},
		{"truncated base64", []string{"--key", key[:len(key)-1]}, "invalid ssh key"},
		{"truncated wire key", []string{"--key", key[:len(key)-4]}, "invalid ssh key"},
		{"unquoted key", []string{"--key", parts[0], parts[1]}, "Quote the entire --key"},
		{"extra argument", []string{"--key", key, "unexpected"}, "Unexpected extra arguments"},
		{"extra before flag", []string{"unexpected", "--key", key}, "Unexpected extra arguments"},
		{"extra after separator", []string{"--key", key, "--", "unexpected"}, "Unexpected extra arguments"},
		{"expiry after extra", []string{"--key", key, "unexpected", "--expires", "7"}, "Unexpected extra arguments"},
		{"unknown flag", []string{"--key", key, "--unknown"}, "flag provided but not defined"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newTestDB(t)
			user := newRegularUser(t, db, "alice")
			// Guard against privileged sync if argument validation regresses.
			if err := db.Callback().Create().Before("gorm:create").Register("test:reject_insert", func(tx *gorm.DB) {
				if _, ok := tx.Statement.Dest.(*models.IngressKey); ok {
					t.Error("invalid arguments reached key registration")
					_ = tx.AddError(errors.New("test: unexpected registration"))
				}
			}); err != nil {
				t.Fatal(err)
			}
			err := AddIngressKey(db, user, tt.args)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
			var count int64
			if err := db.Model(&models.IngressKey{}).Count(&count).Error; err != nil {
				t.Fatal(err)
			}
			if count != 0 {
				t.Fatalf("stored %d keys after invalid arguments", count)
			}
		})
	}
}

func TestAddIngressKey_InvalidKeyNoArgs(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	if err := AddIngressKey(db, user, nil); err == nil {
		t.Fatal("expected missing key error")
	}
}

func TestAddIngressKey_RejectsNegativeExpiryBeforeInsert(t *testing.T) {
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")

	if err := AddIngressKey(db, user, []string{"--key", generateIngressTestPublicKey(t), "--expires", "-1"}); err == nil || !strings.Contains(err.Error(), "cannot be negative") {
		t.Fatalf("expected negative expiry error, got %v", err)
	}

	var count int64
	if err := db.Model(&models.IngressKey{}).Where("user_id = ?", user.ID).Count(&count).Error; err != nil {
		t.Fatalf("count ingress keys: %v", err)
	}
	if count != 0 {
		t.Fatalf("found %d ingress keys after validation failure, want 0", count)
	}
}
