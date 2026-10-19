package self

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"gorm.io/gorm"
)

func catalogTestConfig(t *testing.T) {
	t.Helper()
	_ = config.Load()
	config.SetForTesting(config.DefaultConfig())
	t.Cleanup(config.ResetForTesting)
	t.Setenv("SSH_CLIENT", "192.0.2.1 12345 22")
}

func catalogCreate(t *testing.T, db *gorm.DB, value any) {
	t.Helper()
	if err := db.Create(value).Error; err != nil {
		t.Fatal(err)
	}
}

func catalogOutput(t *testing.T, db *gorm.DB, user *models.User, args ...string) (string, error) {
	t.Helper()
	old := os.Stdout
	file, err := os.CreateTemp(t.TempDir(), "catalog-output")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = file
	defer func() { os.Stdout = old; _ = file.Close() }()
	runErr := ListAllAccesses(db, user, args)
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(file)
	if err != nil {
		t.Fatal(err)
	}
	return string(data), runErr
}

func TestAccessCatalogPersonalAndGroupScope(t *testing.T) {
	catalogTestConfig(t)
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	other := newRegularUser(t, db, "bob")
	group := models.Group{Name: "prod", MFARequired: true}
	catalogCreate(t, db, &group)
	catalogCreate(t, db, &models.UserGroup{UserID: user.ID, GroupID: group.ID, Role: models.GroupRoleMember})
	catalogCreate(t, db, &models.SelfAccess{UserID: user.ID, Server: "[2001:db8::10]", Port: 22, Username: "deploy"})
	catalogCreate(t, db, &models.GroupAccess{GroupID: group.ID, Server: "srv-prod", Port: 2222, Username: "ops"})
	catalogCreate(t, db, &models.SelfDBAccess{UserID: user.ID, Host: "db-self", Port: 5432,
		Protocol: "postgres", Username: "reader", Password: "secret-personal-password"})
	catalogCreate(t, db, &models.GroupDBAccess{GroupID: group.ID, Host: "db-prod", Port: 3306,
		Protocol: "mysql", Username: "reader", Password: "secret-group-password"})
	catalogCreate(t, db, &models.SelfAccess{UserID: other.ID, Server: "other-user-target", Port: 22, Username: "root"})
	catalogCreate(t, db, &models.SelfEgressKey{UserID: user.ID, PrivKey: "secret-personal-key"})
	catalogCreate(t, db, &models.GroupEgressKey{GroupID: group.ID, PrivKey: "secret-group-key"})
	catalogCreate(t, db, &models.Aliases{UserID: &user.ID, ResolveFrom: "web", Host: "2001:db8::10"})
	catalogCreate(t, db, &models.Aliases{GroupID: &group.ID, ResolveFrom: "app", Host: "srv-prod"})
	catalogCreate(t, db, &models.DatabaseAlias{GroupID: &group.ID, ResolveFrom: "sql", Host: "db-prod", Port: 3306, Protocol: "mysql"})
	unrelated := models.Group{Name: "unrelated"}
	catalogCreate(t, db, &unrelated)
	catalogCreate(t, db, &models.GroupAccess{GroupID: unrelated.ID, Server: "other-group-target", Port: 22, Username: "root"})

	// Even administrators see their own assignments, not everyone's inventory.
	for _, role := range []string{models.RoleUser, models.RoleAdmin} {
		user.Role = role
		out, err := catalogOutput(t, db, user, "--details")
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"4 access assignment(s)", "deploy@[2001:db8::10]:22", "prod-app", "prod-sql",
			"db-self", "db-prod", "MFA: Required", "Egress key: Present", "ssh -t BASTION -- 'deploy@[2001:db8::10]:22'"} {
			if !strings.Contains(out, want) {
				t.Errorf("role %s: missing %q in output:\n%s", role, want, out)
			}
		}
		for _, hidden := range []string{"other-user-target", "other-group-target", "secret-personal-password",
			"secret-group-password", "secret-personal-key", "secret-group-key"} {
			if strings.Contains(out, hidden) {
				t.Errorf("catalog exposed %q", hidden)
			}
		}
	}
}

func TestAccessCatalogGuestGrantsIntersectSSHAndRestrictDB(t *testing.T) {
	catalogTestConfig(t)
	db := newTestDB(t)
	user := newRegularUser(t, db, "guest")
	other := newRegularUser(t, db, "other")
	group := models.Group{Name: "partners"}
	catalogCreate(t, db, &group)
	catalogCreate(t, db, &models.UserGroup{UserID: user.ID, GroupID: group.ID, Role: models.GroupRoleGuest})
	catalogCreate(t, db, &models.GroupAccess{GroupID: group.ID, Server: "[2001:db8::1]", Port: 22,
		Username: "*", Protocol: "ssh", AllowedFrom: "192.0.2.0/24"})
	catalogCreate(t, db, &models.GroupGuestAccess{GroupID: group.ID, UserID: user.ID, Server: "2001:db8::1",
		Port: 22, Username: "vendor", Protocol: "sftp", AllowedFrom: "198.51.100.0/24"})
	catalogCreate(t, db, &models.GroupAccess{GroupID: group.ID, Server: "hidden-broad", Port: 22, Username: "root"})
	catalogCreate(t, db, &models.GroupGuestAccess{GroupID: group.ID, UserID: other.ID, Server: "hidden-broad", Port: 22, Username: "root"})
	catalogCreate(t, db, &models.GroupGuestAccess{GroupID: group.ID, UserID: user.ID, Server: "orphan-grant", Port: 22, Username: "root"})
	catalogCreate(t, db, &models.GroupDBAccess{GroupID: group.ID, Host: "hidden-group-db", Port: 3306, Protocol: "mysql", Username: "root"})
	catalogCreate(t, db, &models.GroupGuestDBAccess{GroupID: group.ID, UserID: user.ID, Host: "vendor-db",
		Port: 5432, Protocol: "postgres", Username: "reader"})
	catalogCreate(t, db, &models.GroupGuestDBAccess{GroupID: group.ID, UserID: other.ID, Host: "other-guest-db",
		Port: 5432, Protocol: "postgres", Username: "reader"})
	out, err := catalogOutput(t, db, user, "--details")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"2 access assignment(s)", "SFTP", "vendor@[2001:db8::1]:22", "vendor-db", "guest:partners",
		"192.0.2.0/24 AND 198.51.100.0/24", "Source IP blocked"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
	for _, hidden := range []string{"hidden-broad", "orphan-grant", "hidden-group-db", "other-guest-db"} {
		if strings.Contains(out, hidden) {
			t.Errorf("guest can see %q", hidden)
		}
	}
}

func TestAccessCatalogFiltersExpiryAndDeletedScopes(t *testing.T) {
	catalogTestConfig(t)
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	past := time.Now().Add(-time.Hour)
	catalogCreate(t, db, &models.SelfAccess{UserID: user.ID, Server: "expired-host", Port: 22, Username: "deploy", ExpiresAt: &past})
	catalogCreate(t, db, &models.SelfAccess{UserID: user.ID, Server: "live-host", Port: 22, Username: "deploy", Comment: "Production web service"})
	catalogCreate(t, db, &models.SelfDBAccess{UserID: user.ID, Host: "live-db", Port: 6379, Protocol: "redis", Username: "default"})
	for _, groupName := range []string{"active", "deleted", "left"} {
		g := models.Group{Name: groupName}
		catalogCreate(t, db, &g)
		membership := models.UserGroup{UserID: user.ID, GroupID: g.ID, Role: models.GroupRoleMember}
		catalogCreate(t, db, &membership)
		catalogCreate(t, db, &models.GroupAccess{GroupID: g.ID, Server: groupName + "-target", Port: 22, Username: "deploy"})
		if groupName == "deleted" {
			if err := db.Delete(&g).Error; err != nil {
				t.Fatal(err)
			}
		}
		if groupName == "left" {
			if err := db.Delete(&membership).Error; err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, tc := range []struct {
		args          []string
		want, exclude string
	}{
		{nil, "live-host", "expired-host"},
		{[]string{"--all"}, "expired-host", "deleted-target"},
		{[]string{"--search", "PRODUCTION"}, "live-host", "live-db"},
		{[]string{"--group", "active"}, "active-target", "live-host"},
		{[]string{"--type", "db"}, "live-db", "live-host"},
		{[]string{"--type", "ssh"}, "live-host", "live-db"},
		{[]string{"--search", "no-such-target"}, "No matching accesses found.", "live-host"},
	} {
		out, err := catalogOutput(t, db, user, tc.args...)
		if err != nil || !strings.Contains(out, tc.want) || strings.Contains(out, tc.exclude) || strings.Contains(out, "left-target") {
			t.Errorf("args=%v: err=%v output:\n%s", tc.args, err, out)
		}
	}
	for _, args := range [][]string{{"--type", "mysql"}, {"--search"}, {"unexpected"}, {"--user", "other"}, {"--interactive"}} {
		if _, err := catalogOutput(t, db, user, args...); err == nil {
			t.Errorf("expected invalid arguments error for %v", args)
		}
	}
}

func TestAccessCatalogDoesNotNeedDatabaseFeature(t *testing.T) {
	catalogTestConfig(t)
	cfg := config.DefaultConfig()
	cfg.Database.Enabled = false
	config.SetForTesting(cfg)
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	catalogCreate(t, db, &models.SelfAccess{UserID: user.ID, Server: "ssh-target", Port: 22, Username: "deploy"})
	if err := db.Migrator().DropTable(&models.SelfDBAccess{}, &models.GroupDBAccess{}, &models.GroupGuestDBAccess{}, &models.DatabaseAlias{}); err != nil {
		t.Fatal(err)
	}
	out, err := catalogOutput(t, db, user)
	if err != nil || !strings.Contains(out, "ssh-target") {
		t.Fatalf("SSH catalog should work with databases disabled: output=%s err=%v", out, err)
	}
}

func TestAccessCatalogGuestProtocolAndExpiry(t *testing.T) {
	catalogTestConfig(t)
	db := newTestDB(t)
	user := newRegularUser(t, db, "guest")
	group := models.Group{Name: "vendor"}
	catalogCreate(t, db, &group)
	catalogCreate(t, db, &models.UserGroup{UserID: user.ID, GroupID: group.ID, Role: models.GroupRoleGuest})
	past, future := time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	for _, tc := range []struct {
		host, baseProtocol, grantProtocol string
		baseExpiry, grantExpiry           *time.Time
	}{
		{"allowed", "sftp", "ssh", nil, nil},
		{"mismatched-protocol", "rsync", "sftp", nil, nil},
		{"expired-base", "ssh", "ssh", &past, &future},
		{"expired-grant", "ssh", "ssh", &future, &past},
	} {
		catalogCreate(t, db, &models.GroupAccess{GroupID: group.ID, Server: tc.host, Port: 22,
			Username: "vendor", Protocol: tc.baseProtocol, ExpiresAt: tc.baseExpiry})
		catalogCreate(t, db, &models.GroupGuestAccess{GroupID: group.ID, UserID: user.ID, Server: tc.host,
			Port: 22, Username: "vendor", Protocol: tc.grantProtocol, ExpiresAt: tc.grantExpiry})
	}
	out, err := catalogOutput(t, db, user)
	if err != nil || !strings.Contains(out, "1 access assignment(s)") || !strings.Contains(out, "SFTP") ||
		strings.Contains(out, "mismatched-protocol") || strings.Contains(out, "expired-") {
		t.Fatalf("guest intersection: err=%v output=%s", err, out)
	}
	out, err = catalogOutput(t, db, user, "--all")
	if err != nil || !strings.Contains(out, "3 access assignment(s)") || !strings.Contains(out, "expired-base") ||
		!strings.Contains(out, "expired-grant") || !strings.Contains(out, "Expired") || strings.Contains(out, "mismatched-protocol") {
		t.Fatalf("guest expired assignments: err=%v output=%s", err, out)
	}
}

func TestAccessCatalogAliasSearchAndTerminalOutput(t *testing.T) {
	catalogTestConfig(t)
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	catalogCreate(t, db, &models.SelfAccess{UserID: user.ID, Server: "[2001:db8::10]", Port: 2222,
		Username: "*", Comment: "Production\nweb\tservice\x1b[31m"})
	catalogCreate(t, db, &models.Aliases{UserID: &user.ID, Host: "2001:db8::10", ResolveFrom: "WEB-ALIAS"})
	out, err := catalogOutput(t, db, user, "--search", "web-alias", "--details")
	if err != nil || !strings.Contains(out, "1 access assignment(s)") || !strings.Contains(out, "WEB-ALIAS") ||
		!strings.Contains(out, "'root@[2001:db8::10]:2222'") || !strings.Contains(out, "Production web service [31m") {
		t.Fatalf("alias search: err=%v output=%s", err, out)
	}
	if strings.Contains(out, "\x1b[31m") || strings.Contains(out, "\nweb\t") {
		t.Fatalf("raw terminal controls in comment: %q", out)
	}
}

func TestAccessCatalogRespectsGroupVisibility(t *testing.T) {
	catalogTestConfig(t)
	models.SetGroupVisibilityMode(models.GroupVisibilityManagers)
	t.Cleanup(func() { models.SetGroupVisibilityMode(models.GroupVisibilityOpen) })
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	group := models.Group{Name: "restricted"}
	catalogCreate(t, db, &group)
	membership := models.UserGroup{UserID: user.ID, GroupID: group.ID, Role: models.GroupRoleMember}
	catalogCreate(t, db, &membership)
	catalogCreate(t, db, &models.SelfAccess{UserID: user.ID, Server: "personal-target", Port: 22, Username: "deploy"})
	catalogCreate(t, db, &models.GroupAccess{GroupID: group.ID, Server: "restricted-target", Port: 22, Username: "deploy"})
	catalogCreate(t, db, &models.Aliases{GroupID: &group.ID, Host: "personal-target", ResolveFrom: "hidden-alias"})
	out, err := catalogOutput(t, db, user)
	if err != nil || !strings.Contains(out, "personal-target") || strings.Contains(out, "restricted-target") || strings.Contains(out, "hidden-alias") {
		t.Fatalf("member visibility: err=%v output=%s", err, out)
	}
	if err := db.Model(&membership).Update("role", models.GroupRoleOwner).Error; err != nil {
		t.Fatal(err)
	}
	out, err = catalogOutput(t, db, user)
	if err != nil || !strings.Contains(out, "restricted-target") || !strings.Contains(out, "restricted-hidden-alias") {
		t.Fatalf("owner visibility: err=%v output=%s", err, out)
	}
}

func TestAccessCatalogKeepsAliasesWhenManagementIsDisabled(t *testing.T) {
	catalogTestConfig(t)
	cfg := config.DefaultConfig()
	cfg.AliasSelf.Enabled = false
	cfg.AliasGroup.Enabled = false
	config.SetForTesting(cfg)
	db := newTestDB(t)
	user := newRegularUser(t, db, "alice")
	group := models.Group{Name: "infra"}
	catalogCreate(t, db, &group)
	catalogCreate(t, db, &models.UserGroup{UserID: user.ID, GroupID: group.ID, Role: models.GroupRoleMember})
	catalogCreate(t, db, &models.SelfAccess{UserID: user.ID, Server: "2001:db8::10", Port: 2222, Username: "deploy"})
	catalogCreate(t, db, &models.Aliases{UserID: &user.ID, Host: "[2001:db8::10]", ResolveFrom: "web"})
	catalogCreate(t, db, &models.Aliases{GroupID: &group.ID, Host: "2001:db8::10", ResolveFrom: "web"})
	for _, search := range []string{"web", "infra-web", "deploy@[2001:db8::10]:2222"} {
		out, err := catalogOutput(t, db, user, "--search", search)
		if err != nil || !strings.Contains(out, "1 access assignment(s)") || !strings.Contains(out, "infra-web") {
			t.Fatalf("search %q: err=%v output=%s", search, err, out)
		}
	}
}
