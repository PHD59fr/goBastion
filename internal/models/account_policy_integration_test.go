package models

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/google/uuid"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// Dedicated throwaway databases are created by scripts/test-db-isolation.sh.
func TestConcurrentAdministratorRemoval(t *testing.T) {
	if os.Getenv("GOB_POLICY_INTEGRATION") != "1" {
		t.Skip("requires dedicated database fixtures")
	}
	for name, dialector := range map[string]gorm.Dialector{
		"postgres": postgres.Open("host=127.0.0.1 port=55432 user=postgres dbname=policytest sslmode=disable"),
		"mariadb":  mysql.Open("root@tcp(127.0.0.1:53306)/policytest?parseTime=true"),
	} {
		t.Run(name, func(t *testing.T) {
			db, err := gorm.Open(dialector, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
			if err != nil {
				t.Fatal(err)
			}
			sqlDB, err := db.DB()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = sqlDB.Close() }()
			column := db.Statement.Quote("system_user")
			if err := db.Exec("CREATE TABLE users (id VARCHAR(36) PRIMARY KEY, username VARCHAR(64), role VARCHAR(16), enabled BOOLEAN, " + column + " BOOLEAN, deleted_at TIMESTAMP NULL, updated_at TIMESTAMP NULL)").Error; err != nil {
				t.Fatal(err)
			}
			defer db.Exec("DROP TABLE users")
			for round := 0; round < 10; round++ {
				if err := db.Exec("DELETE FROM users").Error; err != nil {
					t.Fatal(err)
				}
				ids := []uuid.UUID{uuid.New(), uuid.New()}
				for i, id := range ids {
					if err := db.Exec("INSERT INTO users (id, username, role, enabled, "+column+") VALUES (?, ?, ?, true, false)", id, fmt.Sprint("admin", i), RoleAdmin).Error; err != nil {
						t.Fatal(err)
					}
				}
				var wg sync.WaitGroup
				start := make(chan struct{})
				for _, id := range ids {
					wg.Add(1)
					go func(id uuid.UUID) {
						defer wg.Done()
						<-start
						// A serialization/deadlock error is a safe rejection; callers can retry.
						_ = WithAccountChange(db, func(tx *gorm.DB) error {
							var u User
							if err := tx.First(&u, "id = ?", id).Error; err != nil {
								return err
							}
							if err := RequireOtherAdmin(tx, &u); err != nil {
								return err
							}
							return tx.Model(&User{}).Where("id = ?", id).Update("enabled", false).Error
						})
					}(id)
				}
				close(start)
				wg.Wait()
				var count int64
				if err := db.Model(&User{}).Where(map[string]any{"role": RoleAdmin, "enabled": true, "system_user": false}).Count(&count).Error; err != nil {
					t.Fatal(err)
				}
				if count != 1 {
					t.Fatalf("round %d: usable admins = %d, want 1", round, count)
				}
			}
		})
	}
}
