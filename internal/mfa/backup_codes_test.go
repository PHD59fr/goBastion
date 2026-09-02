package mfa

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"goBastion/internal/models"
	"goBastion/internal/utils/totp"
)

func TestVerifyAndConsumeBackupCodeConcurrentSameCode(t *testing.T) {
	db, user := newBackupCodeTestUser(t, "CODEONE")
	users := []*models.User{cloneUser(user), cloneUser(user)}

	results, errs := consumeConcurrently(db, users, []string{"CODEONE", "CODEONE"})
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("concurrent consumption errors: %v, %v", errs[0], errs[1])
	}
	if results[0] == results[1] {
		t.Fatalf("same code results = %v, want exactly one success", results)
	}
	for i, u := range users {
		if got := totp.CountBackupCodes(u.BackupCodes); got != 0 {
			t.Errorf("user copy %d has %d backup codes, want 0", i, got)
		}
	}
	assertStoredBackupCodeCount(t, db, user.ID, 0)
}

func TestVerifyAndConsumeBackupCodeConcurrentDifferentCodes(t *testing.T) {
	db, user := newBackupCodeTestUser(t, "CODEONE", "CODETWO")
	users := []*models.User{cloneUser(user), cloneUser(user)}

	results, errs := consumeConcurrently(db, users, []string{"CODEONE", "CODETWO"})
	for i := range errs {
		if errs[i] != nil {
			t.Fatalf("consume code %d: %v", i, errs[i])
		}
		if !results[i] {
			t.Fatalf("code %d was not consumed", i)
		}
	}
	assertStoredBackupCodeCount(t, db, user.ID, 0)
}

func newBackupCodeTestUser(t *testing.T, codes ...string) (*gorm.DB, *models.User) {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)", filepath.Join(t.TempDir(), "mfa.db"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open test DB: %v", err)
	}
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatalf("migrate test DB: %v", err)
	}

	hashes := make([]string, len(codes))
	for i, code := range codes {
		hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.MinCost)
		if err != nil {
			t.Fatalf("hash backup code: %v", err)
		}
		hashes[i] = string(hash)
	}
	stored, err := json.Marshal(hashes)
	if err != nil {
		t.Fatalf("marshal backup codes: %v", err)
	}

	user := &models.User{
		Username:    "mfa-user",
		Role:        models.RoleUser,
		Enabled:     true,
		BackupCodes: string(stored),
	}
	if err := db.Create(user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return db, user
}

func cloneUser(user *models.User) *models.User {
	copy := *user
	return &copy
}

func consumeConcurrently(db *gorm.DB, users []*models.User, codes []string) ([2]bool, [2]error) {
	var results [2]bool
	var errs [2]error
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range users {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results[i], errs[i] = VerifyAndConsumeBackupCode(db, users[i], codes[i])
		}()
	}
	close(start)
	wg.Wait()
	return results, errs
}

func assertStoredBackupCodeCount(t *testing.T, db *gorm.DB, userID any, want int) {
	t.Helper()
	var user models.User
	if err := db.Select("backup_codes").First(&user, "id = ?", userID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if got := totp.CountBackupCodes(user.BackupCodes); got != want {
		t.Fatalf("stored backup code count = %d, want %d", got, want)
	}
}
