package mfa

import (
	"testing"

	"goBastion/internal/models"

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
			if change == "role" && (result.Error != nil || !fresh.TOTPEnabled || fresh.TOTPSecret != "new") {
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
