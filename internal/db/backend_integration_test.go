package db

import (
	"bytes"
	"os"
	"testing"
	"time"

	"goBastion/internal/models"
)

// TestBackendIntegration exercises real backend migrations and a complete
// encrypted export/import round trip. It is opt-in so the regular unit suite
// remains self-contained; CI or release checks can provide isolated source and
// target databases through the variables below.
func TestBackendIntegration(t *testing.T) {
	driver := os.Getenv("GOB_INTEGRATION_DB_DRIVER")
	targetDriver := os.Getenv("GOB_INTEGRATION_TARGET_DB_DRIVER")
	if targetDriver == "" {
		targetDriver = driver
	}
	sourceDSN := os.Getenv("GOB_INTEGRATION_SOURCE_DSN")
	targetDSN := os.Getenv("GOB_INTEGRATION_TARGET_DSN")
	if driver == "" || sourceDSN == "" || targetDSN == "" {
		t.Skip("real database integration environment is not configured")
	}

	t.Setenv("DB_EXPORT_KEY", "0123456789abcdef0123456789abcdef")
	t.Setenv("DB_DRIVER", driver)
	t.Setenv("DB_DSN", sourceDSN)
	source, err := Init(nil, true)
	if err != nil {
		t.Fatalf("initialize %s source: %v", driver, err)
	}

	now := time.Date(2026, time.January, 2, 3, 4, 5, 123000000, time.UTC)
	expires := now.Add(24 * time.Hour)
	user := models.User{
		Username: "integration-user", Role: models.RoleUser, Enabled: true,
		OSHOnly: true, SuperOwner: true, LastLoginFrom: "192.0.2.10", LastLoginAt: now,
		TOTPSecret: "totp-secret", TOTPEnabled: true, PasswordHash: "password-hash", BackupCodes: `["backup"]`,
	}
	if err := source.Create(&user).Error; err != nil {
		t.Fatalf("seed source user: %v", err)
	}
	group := models.Group{Name: "integration-group", MFARequired: true}
	if err := source.Create(&group).Error; err != nil {
		t.Fatalf("seed source group: %v", err)
	}
	if err := source.Create(&models.UserGroup{
		UserID: user.ID, GroupID: group.ID, Role: models.GroupRoleMember,
	}).Error; err != nil {
		t.Fatalf("seed source membership: %v", err)
	}

	representativeRows := []any{
		&models.BastionInstance{InstanceID: "integration-instance", Role: "slave", Config: `{"test":true}`},
		&models.ActiveSession{SessionID: "integration-session", InstanceID: "integration-instance", Username: user.Username, PID: 4242, Kind: "ssh"},
		&models.SshHostKey{Type: "integration-ed25519", PrivateKey: []byte{0, 1, 2, 255}, PublicKey: []byte("public-key")},
		&models.IngressKey{UserID: user.ID, Key: "ssh-ed25519 AAAA", Type: "ssh-ed25519", Size: 256, Fingerprint: "SHA256:ingress", Comment: "clé intégration", ExpiresAt: &expires, PIVAttested: true},
		&models.SelfEgressKey{UserID: user.ID, PubKey: "self-public", PrivKey: "self-private", Type: "ed25519", Size: 256, Fingerprint: "SHA256:self"},
		&models.GroupEgressKey{GroupID: group.ID, PubKey: "group-public", PrivKey: "group-private", Type: "ed25519", Size: 256, Fingerprint: "SHA256:group"},
		&models.SelfAccess{UserID: user.ID, Username: "deploy", Server: "ssh.example", Port: 2222, Protocol: "sftp", Comment: "self access", AllowedFrom: "192.0.2.0/24", ExpiresAt: &expires, LastConnection: now},
		&models.GroupAccess{GroupID: group.ID, Username: "operator", Server: "group-ssh.example", Port: 22, Protocol: "ssh", Comment: "group access", AllowedFrom: "198.51.100.0/24", ExpiresAt: &expires, LastConnection: now},
		&models.GroupGuestAccess{GroupID: group.ID, UserID: user.ID, Username: "guest", Server: "guest-ssh.example", Port: 2022, Protocol: "scpdownload", Comment: "guest access", AllowedFrom: "203.0.113.0/24", ExpiresAt: &expires},
		&models.Aliases{ResolveFrom: "integration-alias", Host: "ssh.example", UserID: &user.ID},
		&models.KnownHostsEntry{UserID: user.ID, Entry: "ssh.example ssh-ed25519 AAAA"},
		&models.PIVTrustAnchor{Name: "integration-ca", CertPEM: "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----", AddedByID: user.ID},
		&models.Realm{Name: "integration-realm", BastionHost: "realm.example", BastionPort: 2200, AllowedFrom: "10.0.0.0/8", PublicKey: "ssh-ed25519 REALM", Enabled: true, CreatedByID: user.ID},
		&models.RestrictedCommandGrant{UserID: user.ID, Command: "realmList", GrantedByID: user.ID},
		&models.SelfDBAccess{UserID: user.ID, Host: "self-db.example", Port: 5432, Protocol: "postgres", Username: "dbuser", Password: "self-password", Database: "app", Comment: "self db", AllowedFrom: "192.0.2.0/24", ExpiresAt: &expires, LastConnection: now},
		&models.GroupDBAccess{GroupID: group.ID, Host: "group-db.example", Port: 3306, Protocol: "mysql", Username: "groupdb", Password: "group-password", Database: "groupapp", Comment: "group db", AllowedFrom: "198.51.100.0/24", ExpiresAt: &expires, LastConnection: now},
		&models.GroupGuestDBAccess{GroupID: group.ID, UserID: user.ID, Host: "guest-db.example", Port: 6379, Protocol: "redis", Username: "default", Password: "guest-password", Database: "2", Comment: "guest db", AllowedFrom: "203.0.113.0/24", ExpiresAt: &expires},
		&models.DatabaseAlias{ResolveFrom: "integration-db", Host: "self-db.example", Port: 5432, Protocol: "postgres", UserID: &user.ID},
	}
	for _, row := range representativeRows {
		if err := source.Create(row).Error; err != nil {
			t.Fatalf("seed representative row %T: %v", row, err)
		}
	}

	var dump bytes.Buffer
	if err := Export(source, &dump, nil); err != nil {
		t.Fatalf("export %s source: %v", driver, err)
	}

	t.Setenv("DB_DRIVER", targetDriver)
	t.Setenv("DB_DSN", targetDSN)
	target, err := Init(nil, true)
	if err != nil {
		t.Fatalf("initialize %s target: %v", targetDriver, err)
	}
	if err := Import(target, bytes.NewReader(dump.Bytes()), nil); err != nil {
		t.Fatalf("import into %s target: %v", targetDriver, err)
	}

	var importedUser models.User
	if err := target.Where("username = ?", user.Username).First(&importedUser).Error; err != nil {
		t.Fatalf("read imported user: %v", err)
	}
	if importedUser.ID != user.ID || importedUser.Role != user.Role || !importedUser.Enabled {
		t.Fatalf("imported user mismatch: got %+v want ID=%s role=%s enabled=true", importedUser, user.ID, user.Role)
	}
	var membershipCount int64
	if err := target.Model(&models.UserGroup{}).
		Where("user_id = ? AND group_id = ?", user.ID, group.ID).
		Count(&membershipCount).Error; err != nil {
		t.Fatalf("count imported membership: %v", err)
	}
	if membershipCount != 1 {
		t.Fatalf("imported membership count = %d, want 1", membershipCount)
	}
	for _, model := range ManagedModelsInDependencyOrder() {
		var sourceCount, targetCount int64
		if err := source.Unscoped().Model(model).Count(&sourceCount).Error; err != nil {
			t.Fatalf("count source model %T: %v", model, err)
		}
		if err := target.Unscoped().Model(model).Count(&targetCount).Error; err != nil {
			t.Fatalf("count target model %T: %v", model, err)
		}
		if targetCount != sourceCount {
			t.Fatalf("row count mismatch for %T: source=%d target=%d", model, sourceCount, targetCount)
		}
	}
}
