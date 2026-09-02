package realm

import (
	"testing"

	"goBastion/internal/models"
)

const testRealmPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGT0i7K7nM5j9l9M5HqY9v9M0N4k8m2JQ4VnV8z0V6hK test@example"

func TestRealmCreate_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	err := Create(db, admin, []string{
		"--realm", "remote-bastion",
		"--bastion", "bastion.example.com",
		"--port", "22",
		"--from", "10.0.0.0/8",
		"--public-key", testRealmPublicKey,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var r models.Realm
	if err := db.Where("name = ?", "remote-bastion").First(&r).Error; err != nil {
		t.Fatalf("realm not found in DB: %v", err)
	}
	if r.BastionHost != "bastion.example.com" {
		t.Fatalf("expected bastion host bastion.example.com, got %s", r.BastionHost)
	}
}

func TestRealmCreate_PermissionDenied(t *testing.T) {
	db := newTestDB(t)
	regular := newRegularUser(t, db, "regular")

	// The realmCreate permission requires admin, super_owner, or a grant.
	if regular.CanDo(db, "realmCreate", "") {
		t.Fatal("expected regular user to lack realmCreate permission")
	}
}

func TestRealmCreate_MissingArgs(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	err := Create(db, admin, []string{"--realm", "myrealm"})
	if err == nil {
		t.Fatal("expected usage error")
	}

	var count int64
	db.Model(&models.Realm{}).Count(&count)
	if count != 0 {
		t.Fatalf("expected no realm created, got %d", count)
	}
}

func TestRealmCreate_InvalidPublicKey(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	err := Create(db, admin, []string{
		"--realm", "remote-bastion",
		"--bastion", "bastion.example.com",
		"--port", "22",
		"--from", "10.0.0.0/8",
		"--public-key", "ssh-ed25519 not-a-real-key",
	})
	if err == nil {
		t.Fatal("expected invalid public key error")
	}
}

func TestRealmCreate_ValidationErrors(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	tests := []struct {
		name  string
		field string
		value string
	}{
		{name: "name", field: "--realm", value: "Invalid Name"},
		{name: "host", field: "--bastion", value: "invalid host"},
		{name: "port", field: "--port", value: "0"},
		{name: "CIDRs", field: "--from", value: "not-a-cidr"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			args := []string{
				"--realm", "remote-bastion",
				"--bastion", "bastion.example.com",
				"--port", "22",
				"--from", "10.0.0.0/8",
				"--public-key", testRealmPublicKey,
			}
			for i := 0; i < len(args); i += 2 {
				if args[i] == test.field {
					args[i+1] = test.value
				}
			}
			if err := Create(db, admin, args); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestRealmCreate_ExistingRealmIsIdempotent(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	args := []string{
		"--realm", "remote-bastion",
		"--bastion", "bastion.example.com",
		"--from", "10.0.0.0/8",
		"--public-key", testRealmPublicKey,
	}

	if err := Create(db, admin, args); err != nil {
		t.Fatalf("create realm: %v", err)
	}
	if err := Create(db, admin, args); err != nil {
		t.Fatalf("expected idempotent success, got %v", err)
	}
}
