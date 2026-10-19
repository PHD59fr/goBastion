package ssh

import (
	"strings"
	"testing"

	cmdaccount "goBastion/internal/commands/account"
	cmdgroup "goBastion/internal/commands/group"
	cmdself "goBastion/internal/commands/self"
	"goBastion/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

func TestIPv6DuplicateAccessCommands(t *testing.T) {
	tests := []struct {
		name string
		seed func(uuid.UUID, uuid.UUID, string) any
		run  func(*gorm.DB, *models.User, *models.User, string) error
	}{
		{"self SSH", func(user, group uuid.UUID, host string) any {
			return &models.SelfAccess{UserID: user, Server: host, Port: 22, Username: "deploy"}
		}, func(db *gorm.DB, admin, user *models.User, host string) error {
			return cmdself.AddAccess(db, user, []string{"--server", host, "--username", "deploy", "--force"})
		}},
		{"account SSH", func(user, group uuid.UUID, host string) any {
			return &models.SelfAccess{UserID: user, Server: host, Port: 22, Username: "deploy"}
		}, func(db *gorm.DB, admin, user *models.User, host string) error {
			return cmdaccount.AddAccess(db, admin, []string{"--user", "alice", "--server", host, "--username", "deploy"})
		}},
		{"group SSH", func(user, group uuid.UUID, host string) any {
			return &models.GroupAccess{GroupID: group, Server: host, Port: 22, Username: "deploy"}
		}, func(db *gorm.DB, admin, user *models.User, host string) error {
			return cmdgroup.AddAccess(db, admin, []string{"--group", "prod", "--server", host, "--username", "deploy", "--force"})
		}},
		{"guest SSH", func(user, group uuid.UUID, host string) any {
			return &models.GroupGuestAccess{UserID: user, GroupID: group, Server: host, Port: 22, Username: "deploy"}
		}, func(db *gorm.DB, admin, user *models.User, host string) error {
			return cmdgroup.AddGuestAccess(db, admin, []string{"--group", "prod", "--account", "alice", "--host", host, "--user", "deploy"})
		}},
		{"self DB", func(user, group uuid.UUID, host string) any {
			return &models.SelfDBAccess{UserID: user, Host: host, Port: 5432, Username: "deploy", Protocol: "postgres"}
		}, func(db *gorm.DB, admin, user *models.User, host string) error {
			return cmdself.AddDBAccess(db, user, []string{"--host", host, "--user", "deploy", "--protocol", "postgres"})
		}},
		{"group DB", func(user, group uuid.UUID, host string) any {
			return &models.GroupDBAccess{GroupID: group, Host: host, Port: 5432, Username: "deploy", Protocol: "postgres"}
		}, func(db *gorm.DB, admin, user *models.User, host string) error {
			return cmdgroup.AddDBAccess(db, admin, []string{"--group", "prod", "--host", host, "--user", "deploy", "--protocol", "postgres"})
		}},
		{"guest DB", func(user, group uuid.UUID, host string) any {
			return &models.GroupGuestDBAccess{UserID: user, GroupID: group, Host: host, Port: 5432, Username: "deploy", Protocol: "postgres"}
		}, func(db *gorm.DB, admin, user *models.User, host string) error {
			return cmdgroup.AddGuestDBAccess(db, admin, []string{"--group", "prod", "--account", "alice", "--host", host, "--user", "deploy", "--protocol", "postgres"})
		}},
	}
	for _, tc := range tests {
		for _, stored := range []string{"2001:db8::10", "[2001:db8::10]"} {
			t.Run(tc.name+"/"+stored, func(t *testing.T) {
				db := newTestDB(t)
				if err := db.AutoMigrate(&models.SelfDBAccess{}, &models.GroupDBAccess{}, &models.GroupGuestDBAccess{}); err != nil {
					t.Fatal(err)
				}
				user := mustCreateUser(t, db, "alice", models.RoleUser)
				admin := mustCreateUser(t, db, "admin", models.RoleAdmin)
				group := mustCreateGroup(t, db, "prod")
				mustAddUserToGroup(t, db, user.ID, group.ID, models.GroupRoleGuest)
				seed := tc.seed(user.ID, group.ID, stored)
				if err := db.Create(seed).Error; err != nil {
					t.Fatal(err)
				}
				alternate := "[2001:db8::10]"
				if stored == alternate {
					alternate = "2001:db8::10"
				}
				if err := tc.run(db, &admin, &user, alternate); err == nil && tc.name != "guest DB" || err != nil && !strings.Contains(err.Error(), "already exists") {
					t.Fatalf("expected duplicate error, got %v", err)
				}
				var count int64
				if err := db.Model(tc.seed(uuid.Nil, uuid.Nil, "")).Count(&count).Error; err != nil || count != 1 {
					t.Fatalf("duplicate command changed stored rows: count=%d err=%v", count, err)
				}
			})
		}
	}
}
