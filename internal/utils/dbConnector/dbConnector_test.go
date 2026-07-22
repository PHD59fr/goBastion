package dbConnector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestConnectWrapsDBClientWithTTYRec(t *testing.T) {
	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	ttyrecDir := filepath.Join(tmpDir, "ttyrec")
	ttyrecLog := filepath.Join(tmpDir, "ttyrec.args")
	clientLog := filepath.Join(tmpDir, "client.args")

	for _, dir := range []string{binDir, ttyrecDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}

	ttyrecScript := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > \"" + ttyrecLog + "\"\n" +
		"file=''\n" +
		"if [ \"$1\" = '-f' ]; then\n" +
		"  file=\"$2\"\n" +
		"  shift 2\n" +
		"fi\n" +
		"if [ \"$1\" = '--' ]; then\n" +
		"  shift\n" +
		"fi\n" +
		"printf 'ttyrec output' > \"$file\"\n" +
		"exec \"$@\"\n"
	if err := os.WriteFile(filepath.Join(binDir, "ttyrec"), []byte(ttyrecScript), 0o755); err != nil {
		t.Fatalf("write ttyrec stub: %v", err)
	}

	clientScript := "#!/bin/sh\n" +
		"printf '%s\\n' \"$@\" > \"" + clientLog + "\"\n"
	if err := os.WriteFile(filepath.Join(binDir, "mariadb"), []byte(clientScript), 0o755); err != nil {
		t.Fatalf("write mariadb stub: %v", err)
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+":"+origPath)

	cfg := config.DefaultConfig()
	cfg.TTYRec.Enabled = true
	cfg.Paths.TtyrecDir = ttyrecDir
	_ = config.Load()
	config.SetForTesting(cfg)
	defer config.ResetForTesting()

	access := models.DBAccessRight{
		Host:     "db.example.internal",
		Port:     3306,
		Protocol: "mysql",
		Username: "dbuser",
		Password: "secret",
		Database: "appdb",
	}
	user := models.User{Username: "alice"}

	if err := Connect(nil, user, access); err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}

	ttyrecArgs, err := os.ReadFile(ttyrecLog)
	if err != nil {
		t.Fatalf("read ttyrec log: %v", err)
	}
	if !strings.Contains(string(ttyrecArgs), "mariadb") {
		t.Fatalf("ttyrec did not receive mariadb client command, args=%q", string(ttyrecArgs))
	}

	clientArgs, err := os.ReadFile(clientLog)
	if err != nil {
		t.Fatalf("read client log: %v", err)
	}
	clientArgsStr := string(clientArgs)
	for _, want := range []string{"-h", "db.example.internal", "-P", "3306", "-u", "dbuser", "--protocol=tcp", "-psecret", "appdb"} {
		if !strings.Contains(clientArgsStr, want) {
			t.Fatalf("mariadb client args missing %q, args=%q", want, clientArgsStr)
		}
	}

	recordings, err := filepath.Glob(filepath.Join(ttyrecDir, "alice", "db.example.internal", "dbuser.db.example.internal:3306_*_mysql_appdb.ttyrec.gz"))
	if err != nil {
		t.Fatalf("glob ttyrec recordings: %v", err)
	}
	if len(recordings) != 1 {
		t.Fatalf("expected one ttyrec gzip recording, got %d (%v)", len(recordings), recordings)
	}
}

func TestResolveDBAliasErrorsOnAmbiguousGroupAlias(t *testing.T) {
	db := newAliasTestDB(t)
	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	groupA := models.Group{Name: "group-a"}
	groupB := models.Group{Name: "group-b"}
	if err := db.Create(&groupA).Error; err != nil {
		t.Fatalf("create groupA: %v", err)
	}
	if err := db.Create(&groupB).Error; err != nil {
		t.Fatalf("create groupB: %v", err)
	}
	for _, group := range []models.Group{groupA, groupB} {
		membership := models.UserGroup{UserID: user.ID, GroupID: group.ID, Role: models.GroupRoleMember}
		if err := db.Create(&membership).Error; err != nil {
			t.Fatalf("create membership: %v", err)
		}
	}

	for _, group := range []models.Group{groupA, groupB} {
		groupID := group.ID
		alias := models.DatabaseAlias{
			ResolveFrom: "shared-db",
			Host:        group.Name + ".db.internal",
			Port:        5432,
			Protocol:    "postgres",
			GroupID:     &groupID,
		}
		if err := db.Create(&alias).Error; err != nil {
			t.Fatalf("create db alias: %v", err)
		}
	}

	_, err := resolveDBAlias(db, user, "shared-db")
	if err == nil || !strings.Contains(err.Error(), "ambiguous across groups") {
		t.Fatalf("expected ambiguous alias error, got %v", err)
	}
}

func newAliasTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	if err := db.AutoMigrate(&models.User{}, &models.Group{}, &models.UserGroup{}, &models.DatabaseAlias{}, &models.GroupDBAccess{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.AutoMigrate(&models.SelfDBAccess{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db
}

func TestResolveTargetFindsGroupDBAccessByHost(t *testing.T) {
	db := newAliasTestDB(t)

	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	group := models.Group{Name: "group-main"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	membership := models.UserGroup{UserID: user.ID, GroupID: group.ID, Role: models.GroupRoleOwner}
	if err := db.Create(&membership).Error; err != nil {
		t.Fatalf("create membership: %v", err)
	}
	access := models.GroupDBAccess{
		GroupID:  group.ID,
		Host:     "db-main.internal",
		Port:     3306,
		Protocol: "mysql",
		Username: "dbuser",
		Database: "appdb",
	}
	if err := db.Create(&access).Error; err != nil {
		t.Fatalf("create group db access: %v", err)
	}

	got, err := ResolveTarget(db, user, "db-main.internal")
	if err != nil {
		t.Fatalf("ResolveTarget returned error: %v", err)
	}
	if got.Host != access.Host || got.Protocol != access.Protocol || got.Username != access.Username {
		t.Fatalf("unexpected resolved access: %+v", got)
	}
}

func TestResolveTargetKeepsPlaintextStoredPassword(t *testing.T) {
	db := newAliasTestDB(t)

	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	group := models.Group{Name: "group-main"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	membership := models.UserGroup{UserID: user.ID, GroupID: group.ID, Role: models.GroupRoleOwner}
	if err := db.Create(&membership).Error; err != nil {
		t.Fatalf("create membership: %v", err)
	}
	access := models.GroupDBAccess{
		GroupID:  group.ID,
		Host:     "db-main.internal",
		Port:     3306,
		Protocol: "mysql",
		Username: "dbuser",
		Password: "123456",
		Database: "appdb",
	}
	if err := db.Create(&access).Error; err != nil {
		t.Fatalf("create group db access: %v", err)
	}

	got, err := ResolveTarget(db, user, "dbuser@db-main.internal")
	if err != nil {
		t.Fatalf("ResolveTarget returned error: %v", err)
	}
	if got.Password != "123456" {
		t.Fatalf("expected plaintext password passthrough, got %q", got.Password)
	}
}

func TestResolveTargetResolvesBareDatabaseAliasBeforeHostParsing(t *testing.T) {
	db := newAliasTestDB(t)

	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	group := models.Group{Name: "group-main"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	membership := models.UserGroup{UserID: user.ID, GroupID: group.ID, Role: models.GroupRoleOwner}
	if err := db.Create(&membership).Error; err != nil {
		t.Fatalf("create membership: %v", err)
	}

	access := models.GroupDBAccess{
		GroupID:  group.ID,
		Host:     "db-main.internal",
		Port:     3306,
		Protocol: "mysql",
		Username: "dbuser",
		Database: "appdb",
	}
	if err := db.Create(&access).Error; err != nil {
		t.Fatalf("create group db access: %v", err)
	}

	alias := models.DatabaseAlias{
		ResolveFrom: "APPDB",
		Host:        access.Host,
		Port:        access.Port,
		Protocol:    access.Protocol,
		GroupID:     &group.ID,
	}
	if err := db.Create(&alias).Error; err != nil {
		t.Fatalf("create group db alias: %v", err)
	}

	got, err := ResolveTarget(db, user, "APPDB")
	if err != nil {
		t.Fatalf("ResolveTarget returned error: %v", err)
	}
	if got.Host != access.Host || got.Port != access.Port || got.Protocol != access.Protocol {
		t.Fatalf("unexpected resolved access from alias: %+v", got)
	}
}

func TestConnectUpdatesLastConnectionForSelfDBAccess(t *testing.T) {
	db := newAliasTestDB(t)

	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	access := models.SelfDBAccess{
		UserID:   user.ID,
		Host:     "db-main.internal",
		Port:     3306,
		Protocol: "mysql",
		Username: "dbuser",
		Database: "appdb",
	}
	if err := db.Create(&access).Error; err != nil {
		t.Fatalf("create self db access: %v", err)
	}

	stubClientBinary(t, "mariadb")

	cfg := config.DefaultConfig()
	cfg.TTYRec.Enabled = false
	_ = config.Load()
	config.SetForTesting(cfg)
	defer config.ResetForTesting()

	err := Connect(db, user, models.DBAccessRight{
		ID:       access.ID,
		Source:   "account-" + user.Username,
		Host:     access.Host,
		Port:     access.Port,
		Protocol: access.Protocol,
		Username: access.Username,
		Database: access.Database,
	})
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}

	var got models.SelfDBAccess
	if err := db.First(&got, "id = ?", access.ID).Error; err != nil {
		t.Fatalf("reload self db access: %v", err)
	}
	if got.LastConnection.IsZero() {
		t.Fatal("expected last_connection to be updated for self db access")
	}
}

func TestConnectUpdatesLastConnectionForGroupDBAccess(t *testing.T) {
	db := newAliasTestDB(t)

	user := models.User{Username: "alice", Role: models.RoleUser, Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	group := models.Group{Name: "group-main"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	access := models.GroupDBAccess{
		GroupID:  group.ID,
		Host:     "db-main.internal",
		Port:     3306,
		Protocol: "mysql",
		Username: "dbuser",
		Database: "appdb",
	}
	if err := db.Create(&access).Error; err != nil {
		t.Fatalf("create group db access: %v", err)
	}

	stubClientBinary(t, "mariadb")

	cfg := config.DefaultConfig()
	cfg.TTYRec.Enabled = false
	_ = config.Load()
	config.SetForTesting(cfg)
	defer config.ResetForTesting()

	err := Connect(db, user, models.DBAccessRight{
		ID:       access.ID,
		Source:   "group-" + group.Name,
		Host:     access.Host,
		Port:     access.Port,
		Protocol: access.Protocol,
		Username: access.Username,
		Database: access.Database,
	})
	if err != nil {
		t.Fatalf("Connect returned error: %v", err)
	}

	var got models.GroupDBAccess
	if err := db.First(&got, "id = ?", access.ID).Error; err != nil {
		t.Fatalf("reload group db access: %v", err)
	}
	if got.LastConnection.IsZero() {
		t.Fatal("expected last_connection to be updated for group db access")
	}
}

func stubClientBinary(t *testing.T, name string) {
	t.Helper()

	tmpDir := t.TempDir()
	binDir := filepath.Join(tmpDir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", binDir, err)
	}

	clientScript := "#!/bin/sh\n" +
		"sleep 0.01\n"
	if err := os.WriteFile(filepath.Join(binDir, name), []byte(clientScript), 0o755); err != nil {
		t.Fatalf("write %s stub: %v", name, err)
	}

	origPath := os.Getenv("PATH")
	t.Setenv("PATH", binDir+":"+origPath)
}
