package mfa

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/cryptokey"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestTOTPDoesNotUndoConcurrentRevocation(t *testing.T) {
	for _, change := range []string{"role", "enabled", "deleted"} {
		t.Run(change, func(t *testing.T) {
			db, e := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			if e != nil {
				t.Fatal(e)
			}
			if e = db.AutoMigrate(&models.User{}, &models.UserGroup{}); e != nil {
				t.Fatal(e)
			}
			u := models.User{Username: "test", Role: models.RoleAdmin, Enabled: true}
			if err := db.Create(&u).Error; err != nil {
				t.Fatal(err)
			}
			snapshot := u
			snapshot.TOTPSecret = "new"
			snapshot.TOTPEnabled = true
			switch change {
			case "role":
				db.Model(&u).Update("role", models.RoleUser)
			case "enabled":
				db.Model(&u).Update("enabled", false)
			case "deleted":
				db.Delete(&u)
			}
			result := UpdateTOTP(db, &snapshot)
			if change != "role" && result.Error == nil {
				t.Fatal("revoked account accepted update")
			}
			var fresh models.User
			if err := db.Unscoped().First(&fresh, "id = ?", u.ID).Error; err != nil {
				t.Fatal(err)
			}
			decrypted, decryptErr := cryptokey.Decrypt(fresh.TOTPSecret)
			if snapshot.TOTPSecret != "new" {
				t.Fatal("caller secret mutated")
			}
			if change == "role" && (result.Error != nil || !fresh.TOTPEnabled || decryptErr != nil || decrypted != "new" || fresh.TOTPSecret == "new") {
				t.Fatalf("MFA fields not persisted: %v", result.Error)
			}
			if change == "role" && fresh.Role != models.RoleUser {
				t.Fatal("role restored")
			}
			if change == "enabled" && fresh.Enabled {
				t.Fatal("account re-enabled")
			}
			if change == "deleted" && !fresh.DeletedAt.Valid {
				t.Fatal("account resurrected")
			}
		})
	}
}

// Encryption configuration is initialized once, so use a fresh process to
// exercise missing-key behavior after the other tests configure a valid key.
func TestUpdateTOTPFailsClosedWithoutKey(t *testing.T) {
	if os.Getenv("GOB_MFA_TEST_MISSING_KEY") != "1" {
		command := exec.Command(os.Args[0], "-test.run=^TestUpdateTOTPFailsClosedWithoutKey$")
		command.Env = append(os.Environ(), "GOB_MFA_TEST_MISSING_KEY=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("missing-key child failed: %v\n%s", err, output)
		}
		return
	}
	config.Get().Paths.DbConfFile = filepath.Join(t.TempDir(), "absent.conf")
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatal(err)
	}
	user := models.User{Username: "missing-key", Enabled: true}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	user.TOTPSecret = "enrollment-secret"
	user.TOTPEnabled = true
	if result := UpdateTOTP(db, &user); result.Error == nil || result.RowsAffected != 0 {
		t.Fatal("unencrypted persistence succeeded")
	}
	if db.Error != nil {
		t.Fatal("encryption error contaminated shared database handle")
	}
	var fresh models.User
	if err := db.First(&fresh, "id = ?", user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if fresh.TOTPSecret != "" || fresh.TOTPEnabled {
		t.Fatal("MFA fields changed after encryption failure")
	}
	if user.TOTPSecret != "enrollment-secret" {
		t.Fatal("enrollment secret mutated")
	}
}

func TestUpdateTOTPPreservesAuthenticatedStoredSecret(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := cryptokey.Encrypt("JBSWY3DPEHPK3PXP")
	if err != nil {
		t.Fatal(err)
	}
	user := models.User{Username: "persisted", Enabled: true, TOTPEnabled: true, TOTPSecret: ciphertext}
	if err := db.Create(&user).Error; err != nil {
		t.Fatal(err)
	}
	if err := UpdateTOTP(db, &user).Error; err != nil {
		t.Fatal(err)
	}
	var fresh models.User
	if err := db.First(&fresh, "id = ?", user.ID).Error; err != nil {
		t.Fatal(err)
	}
	plaintext, err := cryptokey.Decrypt(fresh.TOTPSecret)
	if err != nil || plaintext != "JBSWY3DPEHPK3PXP" {
		t.Fatal("stored secret was double encrypted")
	}
	if fresh.TOTPSecret != ciphertext || user.TOTPSecret != ciphertext {
		t.Fatal("current authenticated ciphertext changed")
	}
	user.TOTPSecret = "gob:v2:default:invalid"
	if err := UpdateTOTP(db, &user).Error; err == nil {
		t.Fatal("invalid marked ciphertext accepted")
	}
	if err := db.First(&fresh, "id = ?", user.ID).Error; err != nil {
		t.Fatal(err)
	}
	if fresh.TOTPSecret != ciphertext {
		t.Fatal("invalid ciphertext changed persisted secret")
	}
}
