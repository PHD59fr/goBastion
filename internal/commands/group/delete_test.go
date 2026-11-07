package group

import (
	"fmt"
	"testing"

	"goBastion/internal/models"
	"gorm.io/gorm"
)

func TestDelete_Success(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	// Create group first
	g := models.Group{Name: "todelete"}
	if err := db.Create(&g).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}

	err := Delete(db, admin, []string{"--group", "todelete"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var count int64
	db.Model(&models.Group{}).Where("name = ?", "todelete").Count(&count)
	if count != 0 {
		t.Fatalf("expected group to be soft-deleted, count=%d", count)
	}
}

func TestDelete_NotFound(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")

	// Deleting non-existent group should not return error (GORM soft-delete on 0 rows)
	_ = Delete(db, admin, []string{"--group", "nonexistent"})
}

func TestDeleteRevokesAllAssociatedRowsAndRollsBackOnFailure(t *testing.T) {
	for _, reject := range []bool{false, true} {
		t.Run(fmt.Sprint("reject=", reject), func(t *testing.T) {
			db := newTestDB(t)
			admin := newAdminUser(t, db, "admin")
			u := newRegularUser(t, db, "alice")
			g := models.Group{Name: "private", MFARequired: true}
			if err := db.Create(&g).Error; err != nil {
				t.Fatal(err)
			}
			rows := []any{
				&models.UserGroup{UserID: u.ID, GroupID: g.ID, Role: models.GroupRoleGuest},
				&models.GroupAccess{GroupID: g.ID, Server: "fixture", Username: "reader", Port: 22, Protocol: "ssh"},
				&models.GroupGuestAccess{GroupID: g.ID, UserID: u.ID, Server: "fixture", Username: "reader", Port: 22, Protocol: "ssh"},
				&models.GroupDBAccess{GroupID: g.ID, Host: "fixture", Username: "reader", Port: 3306, Protocol: "mysql"},
				&models.GroupGuestDBAccess{GroupID: g.ID, UserID: u.ID, Host: "fixture", Username: "reader", Port: 3306, Protocol: "mysql"},
				&models.GroupEgressKey{GroupID: g.ID, PrivKey: "fixture", PubKey: "fixture"},
				&models.Aliases{GroupID: &g.ID, ResolveFrom: "fixture", Host: "fixture"},
				&models.DatabaseAlias{GroupID: &g.ID, ResolveFrom: "fixture", Host: "fixture", Port: 3306, Protocol: "mysql"},
			}
			for _, row := range rows {
				if err := db.Create(row).Error; err != nil {
					t.Fatal(err)
				}
			}
			if reject {
				if err := db.Callback().Delete().Before("gorm:delete").Register("fixture:reject", func(tx *gorm.DB) {
					if tx.Statement.Table == "group_db_accesses" {
						_ = tx.AddError(fmt.Errorf("fixture failure"))
					}
				}); err != nil {
					t.Fatal(err)
				}
			}
			err := Delete(db, admin, []string{"--group", "private"})
			if (err != nil) != reject {
				t.Fatalf("unexpected deletion result: %v", err)
			}
			want := int64(0)
			if reject {
				want = 1
			}
			for _, row := range append(rows, &g) {
				var count int64
				if err := db.Model(row).Count(&count).Error; err != nil || count != want {
					t.Fatalf("active row count for %T: %d, want %d, error %v", row, count, want, err)
				}
				if err := db.Unscoped().Model(row).Count(&count).Error; err != nil || count != 1 {
					t.Fatalf("history lost for %T: %d %v", row, count, err)
				}
			}
		})
	}
}
