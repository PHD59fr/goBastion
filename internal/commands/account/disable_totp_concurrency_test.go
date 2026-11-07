package account

import (
	"goBastion/internal/models"
	"gorm.io/gorm"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdminMFAResetPreservesConcurrentRevocation(t *testing.T) {
	for _, change := range []string{"demotion", "disable", "delete"} {
		t.Run(change, func(t *testing.T) {
			db := newTestDB(t)
			actor := newAdminUser(t, db, "operator")
			target := newAdminUser(t, db, "target")
			var fired atomic.Bool
			if err := db.Callback().Query().After("gorm:query").Register("review:concurrent-revoke", func(tx *gorm.DB) {
				found, ok := tx.Statement.Dest.(*models.User)
				if !ok || found.ID != target.ID || !fired.CompareAndSwap(false, true) {
					return
				}
				updates := map[string]any{}
				switch change {
				case "demotion":
					updates["role"] = models.RoleUser
				case "disable":
					updates["enabled"] = false
				case "delete":
					updates["deleted_at"] = time.Now()
				}
				if err := db.Session(&gorm.Session{NewDB: true}).Model(&models.User{}).Where("id = ?", target.ID).Updates(updates).Error; err != nil {
					t.Fatal(err)
				}
			}); err != nil {
				t.Fatal(err)
			}
			if err := DisableTOTP(db, actor, slog.New(slog.NewTextHandler(io.Discard, nil)), []string{"--user", "target"}); (err != nil) != (change == "delete") {
				t.Fatalf("reset error: %v", err)
			}
			var after models.User
			if err := db.Unscoped().First(&after, "id = ?", target.ID).Error; err != nil {
				t.Fatal(err)
			}
			if !fired.Load() {
				t.Fatal("reproduction callback did not run")
			}
			if change == "demotion" && after.Role != models.RoleUser || change == "disable" && after.Enabled || change == "delete" && !after.DeletedAt.Valid {
				t.Fatalf("MFA reset undid concurrent %s: role=%s enabled=%t deleted=%t", change, after.Role, after.Enabled, after.DeletedAt.Valid)
			}
		})
	}
}
