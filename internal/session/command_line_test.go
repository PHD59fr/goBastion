package session

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

func TestParseCommandLine(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{"empty", " \t\n", nil},
		{"existing flags", "selfAddAccess --server host --port 22 --comment=office", []string{"selfAddAccess", "--server", "host", "--port", "22", "--comment=office"}},
		{"whitespace", "\tselfListIngressKeys  \u2003 --json\t", []string{"selfListIngressKeys", "--json"}},
		{"double quotes", `cmd --comment "user@laptop  with spaces"`, []string{"cmd", "--comment", "user@laptop  with spaces"}},
		{"single quotes", `cmd --comment 'user@laptop  with spaces'`, []string{"cmd", "--comment", "user@laptop  with spaces"}},
		{"equals and adjacent quotes", `cmd --comment="my "'laptop'`, []string{"cmd", "--comment=my laptop"}},
		{"empty arguments", `cmd --key "" ''`, []string{"cmd", "--key", "", ""}},
		{"escaped spaces", `cmd my\ laptop`, []string{"cmd", "my laptop"}},
		{"escaped quotes", `cmd "a \"quote\" and \\ backslash"`, []string{"cmd", `a "quote" and \ backslash`}},
		{"literal single quoted content", "cmd 'a \\\"quote\\\" $HOME'", []string{"cmd", `a \"quote\" $HOME`}},
		{"double quoted backslash", `cmd "C:\keys\public"`, []string{"cmd", `C:\keys\public`}},
		{"line continuation", "cmd a\\\nb", []string{"cmd", "ab"}},
		{"no expansion or execution", "cmd '$HOME' \"$(whoami)\" `id` ; # *.pub", []string{"cmd", "$HOME", "$(whoami)", "`id`", ";", "#", "*.pub"}},
		{"base64 characters", `cmd --key "ssh-rsa abC+/123== user@laptop"`, []string{"cmd", "--key", "ssh-rsa abC+/123== user@laptop"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCommandLine(tt.line)
			if err != nil || !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseCommandLine(%q) = %q, %v; want %q", tt.line, got, err, tt.want)
			}
		})
	}
}

func TestParseCommandLineRejectsIncompleteInput(t *testing.T) {
	for _, line := range []string{`cmd --key "unfinished`, `cmd 'unfinished`, `cmd trailing\`} {
		t.Run(line, func(t *testing.T) {
			got, err := parseCommandLine(line)
			if err == nil || got != nil {
				t.Fatalf("expected no arguments and an error, got %q, %v", got, err)
			}
		})
	}
}

func TestOSHQuotedIngressKey(t *testing.T) {
	config.ResetForTesting()
	_ = config.Load()
	config.SetForTesting(config.DefaultConfig())
	t.Cleanup(config.ResetForTesting)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " user@laptop with spaces"
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	if err := db.AutoMigrate(&models.User{}, &models.IngressKey{}); err != nil {
		t.Fatal(err)
	}
	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}

	// Stop at registration so the command never invokes privileged OS sync.
	stop := errors.New("test: stop before OS sync")
	var attempted *models.IngressKey
	if err := db.Callback().Create().Before("gorm:create").Register("test:ingress", func(tx *gorm.DB) {
		if key, ok := tx.Statement.Dest.(*models.IngressKey); ok {
			attempted = key
			_ = tx.AddError(stop)
		}
	}); err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, tt := range []struct {
		name    string
		command string
		args    []string
	}{
		{"double quotes", `-osh selfAddIngressKey --key "` + publicKey + `" --expires 7`, nil},
		{"single quotes", "-osh selfAddIngressKey --key '" + publicKey + "' --expires 7", nil},
		{"equals", `-osh selfAddIngressKey --key="` + publicKey + `" --expires=7`, nil},
		{"already parsed argv", "-osh", []string{"selfAddIngressKey", "--key", publicKey, "--expires", "7"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			attempted = nil
			runNonInteractiveMode(db, &user, log, tt.command, tt.args)
			if attempted == nil {
				t.Fatal("valid quoted key did not reach registration")
			}
			if attempted.Key != publicKey || attempted.Comment != "user@laptop with spaces" || attempted.ExpiresAt == nil {
				t.Fatalf("incorrect key passed to registration: %+v", attempted)
			}
		})
	}
}
