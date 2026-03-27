package ssh

import (
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"github.com/google/uuid"
	"gorm.io/gorm"

	"goBastion/internal/models"
)

// --- test helpers ---

func newTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	if err := db.AutoMigrate(
		&models.User{}, &models.Group{}, &models.UserGroup{},
		&models.SelfAccess{}, &models.GroupAccess{},
		&models.SelfEgressKey{}, &models.GroupEgressKey{},
		&models.Aliases{}, &models.KnownHostsEntry{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func mustCreateUser(t *testing.T, db *gorm.DB, username, role string) models.User {
	t.Helper()
	u := models.User{Username: username, Role: role, Enabled: true}
	if err := db.Create(&u).Error; err != nil {
		t.Fatalf("create user %s: %v", username, err)
	}
	return u
}

func mustCreateGroup(t *testing.T, db *gorm.DB, name string) models.Group {
	t.Helper()
	g := models.Group{Name: name}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("create group %s: %v", name, err)
	}
	return g
}

func mustAddUserToGroup(t *testing.T, db *gorm.DB, userID, groupID uuid.UUID, role string) {
	t.Helper()
	ug := models.UserGroup{UserID: userID, GroupID: groupID, Role: role}
	if err := db.Create(&ug).Error; err != nil {
		t.Fatalf("add user to group: %v", err)
	}
}

func mustCreateSelfAccess(t *testing.T, db *gorm.DB, userID uuid.UUID, username, server string, port int64) {
	t.Helper()
	sa := models.SelfAccess{UserID: userID, Username: username, Server: server, Port: port, Protocol: "ssh"}
	if err := db.Create(&sa).Error; err != nil {
		t.Fatalf("create self access: %v", err)
	}
}

func mustCreateGroupAccess(t *testing.T, db *gorm.DB, groupID uuid.UUID, username, server string, port int64) {
	t.Helper()
	ga := models.GroupAccess{GroupID: groupID, Username: username, Server: server, Port: port, Protocol: "ssh"}
	if err := db.Create(&ga).Error; err != nil {
		t.Fatalf("create group access: %v", err)
	}
}

func mustCreateSelfEgressKey(t *testing.T, db *gorm.DB, userID uuid.UUID) {
	t.Helper()
	key := models.SelfEgressKey{
		UserID: userID, PubKey: "pub", PrivKey: "priv",
		Type: "ed25519", Size: 256, Fingerprint: "fp",
	}
	if err := db.Create(&key).Error; err != nil {
		t.Fatalf("create self egress key: %v", err)
	}
}

func mustCreateGroupEgressKey(t *testing.T, db *gorm.DB, groupID uuid.UUID) {
	t.Helper()
	key := models.GroupEgressKey{
		GroupID: groupID, PubKey: "pub", PrivKey: "priv",
		Type: "ed25519", Size: 256, Fingerprint: "fp",
	}
	if err := db.Create(&key).Error; err != nil {
		t.Fatalf("create group egress key: %v", err)
	}
}

func mustCreateRestrictedSelfAccess(t *testing.T, db *gorm.DB, userID uuid.UUID, allowedFrom string) {
	t.Helper()
	sa := models.SelfAccess{
		UserID: userID, Username: "deploy", Server: "myserver",
		Port: 22, Protocol: "ssh", AllowedFrom: allowedFrom,
	}
	if err := db.Create(&sa).Error; err != nil {
		t.Fatalf("create restricted self access: %v", err)
	}
}

// --- accessFilter priority tests ---

// TestAccessFilter_SelfExactBeforeGroupExact verifies self-exact (4) > group-exact (3).
func TestAccessFilter_SelfExactBeforeGroupExact(t *testing.T) {
	db := newTestDB(t)
	user := mustCreateUser(t, db, "alice", models.RoleUser)
	group := mustCreateGroup(t, db, "prod")
	mustAddUserToGroup(t, db, user.ID, group.ID, "member")

	mustCreateSelfAccess(t, db, user.ID, "deploy", "myserver", 22)
	mustCreateGroupAccess(t, db, group.ID, "deploy", "myserver", 22)
	mustCreateSelfEgressKey(t, db, user.ID)
	mustCreateGroupEgressKey(t, db, group.ID)

	t.Setenv("SSH_CLIENT", "")

	accesses, err := accessFilter(db, user, "deploy", "myserver", "22", "ssh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(accesses) == 0 {
		t.Fatal("expected at least one access")
	}
	if accesses[0].Type != "self" {
		t.Errorf("self-exact should beat group-exact: got type=%q source=%q", accesses[0].Type, accesses[0].Source)
	}
}

// TestAccessFilter_GroupExactBeforeSelfWildcard verifies group-exact (3) > self-wildcard (2).
func TestAccessFilter_GroupExactBeforeSelfWildcard(t *testing.T) {
	db := newTestDB(t)
	user := mustCreateUser(t, db, "bob", models.RoleUser)
	group := mustCreateGroup(t, db, "ops")
	mustAddUserToGroup(t, db, user.ID, group.ID, "member")

	mustCreateSelfAccess(t, db, user.ID, "*", "myserver", 22)        // wildcard
	mustCreateGroupAccess(t, db, group.ID, "deploy", "myserver", 22) // exact
	mustCreateSelfEgressKey(t, db, user.ID)
	mustCreateGroupEgressKey(t, db, group.ID)

	t.Setenv("SSH_CLIENT", "")

	accesses, err := accessFilter(db, user, "deploy", "myserver", "22", "ssh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(accesses) == 0 {
		t.Fatal("expected at least one access")
	}
	if accesses[0].Type != "group" {
		t.Errorf("group-exact should beat self-wildcard: got type=%q", accesses[0].Type)
	}
}

// TestAccessFilter_SelfWildcardBeforeGroupWildcard verifies self-wildcard (2) > group-wildcard (1).
func TestAccessFilter_SelfWildcardBeforeGroupWildcard(t *testing.T) {
	db := newTestDB(t)
	user := mustCreateUser(t, db, "carol", models.RoleUser)
	group := mustCreateGroup(t, db, "dev")
	mustAddUserToGroup(t, db, user.ID, group.ID, "member")

	mustCreateSelfAccess(t, db, user.ID, "*", "myserver", 22)
	mustCreateGroupAccess(t, db, group.ID, "*", "myserver", 22)
	mustCreateSelfEgressKey(t, db, user.ID)
	mustCreateGroupEgressKey(t, db, group.ID)

	t.Setenv("SSH_CLIENT", "")

	accesses, err := accessFilter(db, user, "deploy", "myserver", "22", "ssh")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(accesses) == 0 {
		t.Fatal("expected at least one access")
	}
	if accesses[0].Type != "self" {
		t.Errorf("self-wildcard should beat group-wildcard: got type=%q", accesses[0].Type)
	}
}

// TestAccessFilter_NoAccess verifies an error is returned when no access entry exists.
func TestAccessFilter_NoAccess(t *testing.T) {
	db := newTestDB(t)
	user := mustCreateUser(t, db, "dave", models.RoleUser)
	t.Setenv("SSH_CLIENT", "")

	_, err := accessFilter(db, user, "deploy", "noserver", "22", "ssh")
	if err == nil {
		t.Fatal("expected error when no access found, got nil")
	}
}

// TestAccessFilter_AdminOverride verifies admin can use any group access entry
// even if they don't have their own access (admin override, score 0).
func TestAccessFilter_AdminOverride(t *testing.T) {
	db := newTestDB(t)
	admin := mustCreateUser(t, db, "superadmin", models.RoleAdmin)
	group := mustCreateGroup(t, db, "infra")
	mustCreateGroupAccess(t, db, group.ID, "deploy", "targetserver", 22)
	mustCreateGroupEgressKey(t, db, group.ID)

	t.Setenv("SSH_CLIENT", "")

	accesses, err := accessFilter(db, admin, "deploy", "targetserver", "22", "ssh")
	if err != nil {
		t.Fatalf("expected admin override to succeed: %v", err)
	}
	if len(accesses) != 1 {
		t.Fatalf("expected 1 access, got %d", len(accesses))
	}
	if accesses[0].Type != "group" {
		t.Errorf("expected group access via admin override, got type=%q", accesses[0].Type)
	}
}

// TestAccessFilter_IPBlocked verifies IP-restricted access returns an actionable error.
func TestAccessFilter_IPBlocked(t *testing.T) {
	db := newTestDB(t)
	user := mustCreateUser(t, db, "eve", models.RoleUser)
	mustCreateRestrictedSelfAccess(t, db, user.ID, "10.0.0.0/8")

	// Client IP outside the allowed range
	t.Setenv("SSH_CLIENT", "203.0.113.5 12345 22")

	_, err := accessFilter(db, user, "deploy", "myserver", "22", "ssh")
	if err == nil {
		t.Fatal("expected IP-blocked error, got nil")
	}
	if !strings.Contains(err.Error(), "203.0.113.5") {
		t.Errorf("error should mention the client IP, got: %v", err)
	}
}

// TestAccessFilter_ExpiredAccessIgnored verifies expired access entries are not used.
func TestAccessFilter_ExpiredAccessIgnored(t *testing.T) {
	db := newTestDB(t)
	user := mustCreateUser(t, db, "frank", models.RoleUser)

	expired := time.Now().Add(-24 * time.Hour)
	sa := models.SelfAccess{
		UserID: user.ID, Username: "deploy", Server: "myserver",
		Port: 22, Protocol: "ssh", ExpiresAt: &expired,
	}
	if err := db.Create(&sa).Error; err != nil {
		t.Fatalf("create expired access: %v", err)
	}
	t.Setenv("SSH_CLIENT", "")

	_, err := accessFilter(db, user, "deploy", "myserver", "22", "ssh")
	if err == nil {
		t.Fatal("expected error for expired access, got nil")
	}
}

// --- inferSSHUsername tests ---

// TestInferSSHUsername_NoFallbackToRoot verifies no silent "root" fallback.
func TestInferSSHUsername_NoFallbackToRoot(t *testing.T) {
	db := newTestDB(t)
	user := mustCreateUser(t, db, "grace", models.RoleUser)

	resolved, ok := inferSSHUsername(db, user, "unknownserver", 22)
	if ok {
		t.Errorf("expected no resolution for unknown server, got %q", resolved)
	}
}

// TestInferSSHUsername_ExactBeforeWildcard verifies exact username entries
// take priority over wildcard entries within self accesses.
func TestInferSSHUsername_ExactBeforeWildcard(t *testing.T) {
	db := newTestDB(t)
	user := mustCreateUser(t, db, "heidi", models.RoleUser)

	// Insert wildcard first, then exact — DB order should not matter.
	mustCreateSelfAccess(t, db, user.ID, "*", "myserver", 22)
	mustCreateSelfAccess(t, db, user.ID, "operator", "myserver", 22)

	resolved, ok := inferSSHUsername(db, user, "myserver", 22)
	if !ok {
		t.Fatal("expected resolution, got false")
	}
	if resolved != "operator" {
		t.Errorf("expected exact 'operator', got %q", resolved)
	}
}

// --- normalizeWildcardUsername tests ---

func TestNormalizeWildcardUsername(t *testing.T) {
	tests := []struct {
		name      string
		stored    string
		requested string
		want      string
	}{
		{"wildcard with requested username", "*", "deploy", "deploy"},
		{"wildcard without requested username defaults to root", "*", "", "root"},
		{"exact stored is never overridden", "admin", "deploy", "admin"},
		{"exact stored with empty requested", "operator", "", "operator"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeWildcardUsername(tc.stored, tc.requested)
			if got != tc.want {
				t.Errorf("normalizeWildcardUsername(%q, %q) = %q, want %q",
					tc.stored, tc.requested, got, tc.want)
			}
		})
	}
}

// --- parseSSHCommand tests ---

func TestParseSSHCommand(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantUser   string
		wantHost   string
		wantPort   string
		wantCmd    string
		wantErrStr string
	}{
		{"user@host", "deploy@myserver", "deploy", "myserver", "22", "", ""},
		{"user@host:port", "deploy@myserver:2222", "deploy", "myserver", "2222", "", ""},
		{"host only", "myserver", "", "myserver", "22", "", ""},
		{"host -p port", "myserver -p 2222", "", "myserver", "2222", "", ""},
		{"user@host with cmd", "deploy@myserver ls -la", "deploy", "myserver", "22", "ls -la", ""},
		{"empty input", "", "", "", "", "", "empty command"},
		{"missing host", "@", "", "", "", "", "missing host"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, h, p, cmd, err := parseSSHCommand(tc.input)
			if tc.wantErrStr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErrStr) {
					t.Errorf("expected error containing %q, got %v", tc.wantErrStr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if u != tc.wantUser {
				t.Errorf("user: got %q, want %q", u, tc.wantUser)
			}
			if h != tc.wantHost {
				t.Errorf("host: got %q, want %q", h, tc.wantHost)
			}
			if p != tc.wantPort {
				t.Errorf("port: got %q, want %q", p, tc.wantPort)
			}
			if cmd != tc.wantCmd {
				t.Errorf("cmd: got %q, want %q", cmd, tc.wantCmd)
			}
		})
	}
}

// --- ipAllowed tests ---

func TestIPAllowed(t *testing.T) {
	tests := []struct {
		name        string
		clientIP    string
		allowedFrom string
		want        bool
	}{
		{"empty allowedFrom means unrestricted", "1.2.3.4", "", true},
		{"empty client IP with restriction is denied", "", "10.0.0.0/8", false},
		{"IP inside CIDR", "10.1.2.3", "10.0.0.0/8", true},
		{"IP outside CIDR", "192.168.1.1", "10.0.0.0/8", false},
		{"multiple CIDRs, first match", "172.16.0.5", "10.0.0.0/8,172.16.0.0/12", true},
		{"multiple CIDRs, second match", "192.168.1.1", "10.0.0.0/8,192.168.0.0/16", true},
		{"multiple CIDRs, no match", "8.8.8.8", "10.0.0.0/8,172.16.0.0/12", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ipAllowed(tc.clientIP, tc.allowedFrom)
			if got != tc.want {
				t.Errorf("ipAllowed(%q, %q) = %v, want %v", tc.clientIP, tc.allowedFrom, got, tc.want)
			}
		})
	}
}

// --- detectProtocol tests ---

func TestDetectProtocol(t *testing.T) {
	tests := []struct {
		remoteCmd string
		want      string
	}{
		{"", "ssh"},
		{"scp -t /tmp/file", "scpupload"},
		{"scp -f /tmp/file", "scpdownload"},
		{"sftp-server -e", "sftp"},
		{"rsync --server --daemon .", "rsync"},
		{"ls -la", "ssh"},
	}
	for _, tc := range tests {
		t.Run(tc.remoteCmd, func(t *testing.T) {
			got := detectProtocol(tc.remoteCmd)
			if got != tc.want {
				t.Errorf("detectProtocol(%q) = %q, want %q", tc.remoteCmd, got, tc.want)
			}
		})
	}
}

// Suppress SSH_CLIENT env var between tests that don't set it.
func init() {
	if err := os.Unsetenv("SSH_CLIENT"); err != nil {
		log.Printf("warning: unable to unset SSH_CLIENT in test init: %v", err)
	}
}
