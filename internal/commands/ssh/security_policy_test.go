package ssh

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"goBastion/internal/config"
	"goBastion/internal/models"
)

func TestTransferOnlyAccessCannotExecuteShellCommands(t *testing.T) {
	for _, tc := range []struct{ protocol, command string }{
		{"sftp", "id; # sftp-server"},
		{"rsync", "rsync --server . /tmp; id"},
		{"scpupload", "scp -t /tmp; id"},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			_ = config.Load()
			t.Cleanup(config.ResetForTesting)
			cfg := config.DefaultConfig()
			cfg.SSH.Enabled = false
			config.SetForTesting(cfg)
			db := newTestDB(t)
			u := mustCreateUser(t, db, "alice", models.RoleUser)
			if err := db.Create(&models.SelfAccess{UserID: u.ID, Server: "host", Port: 22, Username: "deploy", Protocol: tc.protocol}).Error; err != nil {
				t.Fatal(err)
			}
			mustCreateSelfEgressKey(t, db, u.ID)
			err := Connect(db, u, *slog.New(slog.NewTextHandler(io.Discard, nil)), "deploy@host "+tc.command)
			if err == nil || (!strings.Contains(err.Error(), "invalid transfer command") && !strings.Contains(err.Error(), "SSH connections are disabled")) {
				t.Fatalf("unsafe transfer reached connection: %v", err)
			}
		})
	}
}

func TestSFTPRefusesGroupJITMFAWithoutPromptingOnProtocolStream(t *testing.T) {
	_ = config.Load()
	config.SetForTesting(config.DefaultConfig())
	t.Cleanup(config.ResetForTesting)
	db := newTestDB(t)
	u := mustCreateUser(t, db, "alice", models.RoleUser)
	g := mustCreateGroup(t, db, "secure")
	if err := db.Model(&g).Update("mfa_required", true).Error; err != nil {
		t.Fatal(err)
	}
	mustAddUserToGroup(t, db, u.ID, g.ID, models.GroupRoleMember)
	mustCreateGroupAccess(t, db, g.ID, "deploy", "host", 22)
	mustCreateGroupEgressKey(t, db, g.ID)
	err := SFTPSession(db, u, *slog.New(slog.NewTextHandler(io.Discard, nil)), "deploy@host")
	if err == nil || !strings.Contains(err.Error(), "unavailable when this access requires JIT MFA") {
		t.Fatalf("SFTP did not explicitly refuse group MFA: %v", err)
	}
}

func TestRemoteCommandQuotesSurviveForwardingOptions(t *testing.T) {
	input := `deploy@host --via jump@bastion -p 2222 scp -t 'two  spaces/--via'`
	clean, _, err := extractForwardHops(input)
	if err != nil {
		t.Fatal(err)
	}
	_, _, port, command, err := parseSSHCommand(clean)
	if err != nil || port != "2222" || command != `scp -t 'two  spaces/--via'` {
		t.Fatalf("remote command changed: port=%s command=%q error=%v", port, command, err)
	}
}
