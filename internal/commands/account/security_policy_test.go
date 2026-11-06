package account

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func TestFailedDeletePreservesRevokedMembership(t *testing.T) {
	db := newTestDB(t)
	u := newRegularUser(t, db, "audit")
	g := models.Group{Name: "revoked"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatal(err)
	}
	ug := models.UserGroup{UserID: u.ID, GroupID: g.ID, Role: models.GroupRoleOwner}
	if err := db.Create(&ug).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Delete(&ug).Error; err != nil {
		t.Fatal(err)
	}
	mock := osadapter.NewMockAdapter()
	mock.ErrDeleteUser = errors.New("simulated OS error")
	if err := DeleteUser(db, mock, "audit"); err == nil {
		t.Fatal("expected deletion failure")
	}
	var n int64
	if err := db.Model(&models.UserGroup{}).Where("id = ?", ug.ID).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("revoked membership restored: active memberships=%d", n)
	}

}

func TestDeleteProtectsSelfAndLastUsableAdmin(t *testing.T) {
	for _, tc := range []struct {
		name                string
		self, disabledOther bool
	}{
		{name: "last admin"}, {name: "only disabled alternative", disabledOther: true}, {name: "self", self: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestDB(t)
			target := newAdminUser(t, db, "target")
			if !tc.self {
				caller := newAdminUser(t, db, "caller")
				if err := db.Model(caller).Update("enabled", false).Error; err != nil {
					t.Fatal(err)
				}
				// The guard must work even for a call from the root recovery path.
				if !tc.disabledOther {
					if err := db.Delete(caller).Error; err != nil {
						t.Fatal(err)
					}
				}
			} else {
				newAdminUser(t, db, "other")
			}
			mock := osadapter.NewMockAdapter()
			var err error
			if tc.self {
				err = Delete(db, mock, target, []string{"--user", "target"})
			} else {
				err = DeleteUser(db, mock, "target")
			}
			if err == nil {
				t.Fatal("unsafe administrator deletion succeeded")
			}
			if len(mock.DeletedUsers) != 0 {
				t.Fatal("blocked deletion reached OS")
			}
			var fresh models.User
			if err := db.First(&fresh, "id = ?", target.ID).Error; err != nil {
				t.Fatalf("blocked account was deleted: %v", err)
			}
		})
	}
}

func TestFailedDeleteRestoresActiveMemberships(t *testing.T) {
	db := newTestDB(t)
	u := newRegularUser(t, db, "alice")
	g := models.Group{Name: "active"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatal(err)
	}
	ug := models.UserGroup{UserID: u.ID, GroupID: g.ID, Role: models.GroupRoleMember}
	if err := db.Create(&ug).Error; err != nil {
		t.Fatal(err)
	}
	mock := osadapter.NewMockAdapter()
	mock.ErrDeleteUser = errors.New("OS deletion failed")
	if err := DeleteUser(db, mock, u.Username); err == nil {
		t.Fatal("expected failure")
	}
	if err := db.First(&models.User{}, "id = ?", u.ID).Error; err != nil {
		t.Fatal(err)
	}
	if err := db.First(&models.UserGroup{}, "id = ?", ug.ID).Error; err != nil {
		t.Fatal(err)
	}
}

func TestDeleteAdminWhenAnotherUsableAdminExists(t *testing.T) {
	db := newTestDB(t)
	caller := newAdminUser(t, db, "caller")
	newAdminUser(t, db, "target")
	mock := osadapter.NewMockAdapter()
	if err := Delete(db, mock, caller, []string{"--user", "target"}); err != nil {
		t.Fatal(err)
	}
	if len(mock.DeletedUsers) != 1 || mock.DeletedUsers[0] != "target" {
		t.Fatal("OS deletion missing")
	}
}

func TestConcurrentAdminDeletionKeepsUsableAdministrator(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "accounts.db")+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err = db.AutoMigrate(&models.User{}, &models.UserGroup{}); err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 3; attempt++ {
		names := []string{fmt.Sprintf("admin-a-%d", attempt), fmt.Sprintf("admin-b-%d", attempt)}
		// Retire earlier fixtures so every round starts with exactly two admins.
		if err = db.Session(&gorm.Session{AllowGlobalUpdate: true}).Model(&models.User{}).Update("role", models.RoleUser).Error; err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			newAdminUser(t, db, name)
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		for _, name := range names {
			wg.Go(func() { <-start; _ = DeleteUser(db, osadapter.NewMockAdapter(), name) })
		}
		close(start)
		wg.Wait()
		var count int64
		if err = db.Model(&models.User{}).Where("role = ? AND enabled = ?", models.RoleAdmin, true).Count(&count).Error; err != nil {
			t.Fatal(err)
		}
		if count < 1 {
			t.Fatal("concurrent deletions removed all administrators")
		}
	}
}
