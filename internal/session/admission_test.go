package session

import (
	"github.com/glebarez/sqlite"
	"goBastion/internal/config"
	"goBastion/internal/models"
	"gorm.io/gorm"
	"testing"
)

func TestAdmissionUsesCurrentAccountAndAuthenticationFactors(t *testing.T) {
	for _, tc := range []struct {
		name    string
		updates map[string]any
		denied  bool
	}{
		{"demotion", map[string]any{"role": models.RoleUser}, false},
		{"OSH restriction", map[string]any{"osh_only": true}, true},
		{"disabled", map[string]any{"enabled": false}, true},
		{"password replaced", map[string]any{"password_hash": "new hash"}, true},
		{"TOTP enabled", map[string]any{"totp_enabled": true, "totp_secret": "new secret"}, true},
		{"system account", map[string]any{"system_user": true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config.ResetForTesting()
			_ = config.Load()
			defer config.ResetForTesting()
			db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
			if err != nil {
				t.Fatal(err)
			}
			if err := db.AutoMigrate(&models.User{}); err != nil {
				t.Fatal(err)
			}
			actor := models.User{Username: "alice", Enabled: true, Role: models.RoleAdmin}
			if err := db.Create(&actor).Error; err != nil {
				t.Fatal(err)
			}
			if err := db.Model(&models.User{}).Where("id = ?", actor.ID).Updates(tc.updates).Error; err != nil {
				t.Fatal(err)
			}
			err = validateSessionAdmission(db, &actor, "deploy@fixture", nil)
			if (err != nil) != tc.denied {
				t.Fatalf("admission error=%v, denied=%t", err, tc.denied)
			}
			if tc.name == "demotion" && actor.Role != models.RoleUser {
				t.Fatal("old admin role retained")
			}
		})
	}
}
