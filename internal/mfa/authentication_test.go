package mfa

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"goBastion/internal/models"
	"goBastion/internal/utils/cryptokey"
	"goBastion/internal/utils/totp"
)

func TestTOTPConsumedOnceAcrossConnections(t *testing.T) {
	db, user := newBackupCodeTestUser(t)
	const secret = "JBSWY3DPEHPK3PXP"
	user.TOTPSecret = encryptedTOTP(t, secret)
	user.TOTPEnabled = true
	if err := db.Save(user).Error; err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	other := independentConnection(t, db)
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, connection := range []*gorm.DB{db, other} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			ok, err := verifyAndConsumeTOTPAt(connection, cloneUser(user), code, now)
			if err != nil {
				t.Errorf("consume: %v", err)
			}
			if ok {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("accepted %d copies of one code", successes.Load())
	}
	// A previous step remains invalid even when the tolerance window accepts it.
	previous, _ := totp.GenerateCode(secret, now.Add(-30*time.Second))
	if ok, err := verifyAndConsumeTOTPAt(db, user, previous, now); err != nil || ok {
		t.Fatalf("previous step accepted=%v err=%v", ok, err)
	}
	next, _ := totp.GenerateCode(secret, now.Add(30*time.Second))
	if ok, err := verifyAndConsumeTOTPAt(db, user, next, now.Add(30*time.Second)); err != nil || !ok {
		t.Fatalf("next step accepted=%v err=%v", ok, err)
	}
}

func TestTOTPRejectsRevokedOrReplacedProfile(t *testing.T) {
	for _, updates := range []map[string]any{{"enabled": false}, {"totp_enabled": false}, {"totp_secret": "replaced"}} {
		db, user := newBackupCodeTestUser(t)
		user.TOTPEnabled = true
		user.TOTPSecret = encryptedTOTP(t, "JBSWY3DPEHPK3PXP")
		if err := db.Save(user).Error; err != nil {
			t.Fatal(err)
		}
		now := time.Unix(1800000000, 0)
		code, _ := totp.GenerateCode("JBSWY3DPEHPK3PXP", now)
		if err := db.Model(&models.User{}).Where("id = ?", user.ID).Updates(updates).Error; err != nil {
			t.Fatal(err)
		}
		if ok, err := verifyAndConsumeTOTPAt(db, user, code, now); err != nil || ok {
			t.Fatalf("revoked code accepted=%v err=%v", ok, err)
		}
	}
}

func TestSharedAttemptBudgetConcurrentAndBounded(t *testing.T) {
	db, user := newBackupCodeTestUser(t)
	other := independentConnection(t, db)
	now := time.Unix(1800000000, 0)
	var successes atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range 12 {
		connection := []*gorm.DB{db, other}[i%2]
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := ReserveAttempt(connection, user, 3, now)
			if err == nil {
				successes.Add(1)
			} else if !errors.Is(err, ErrAttemptLimit) {
				t.Errorf("reserve: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes.Load() != 3 {
		t.Fatalf("accepted %d attempts, want 3", successes.Load())
	}
	if _, err := ReserveAttempt(other, user, 3, now.Add(AttemptWindow-time.Second)); !errors.Is(err, ErrAttemptLimit) {
		t.Fatalf("budget reset early: %v", err)
	}
	if _, err := ReserveAttempt(other, user, 3, now.Add(AttemptWindow)); err != nil {
		t.Fatalf("budget did not recover: %v", err)
	}
	if err := db.Model(user).Update("enabled", false).Error; err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveAttempt(db, user, 3, now.Add(2*AttemptWindow)); err == nil {
		t.Fatal("disabled account received attempt")
	}
}

func TestAuthenticationFailsClosedWithoutDatabase(t *testing.T) {
	u := &models.User{}
	if _, err := ReserveAttempt(nil, u, 3, time.Now()); err == nil {
		t.Fatal("nil DB accepted attempt")
	}
	if ok, err := VerifyAndConsumeTOTP(nil, u, "123456"); err == nil || ok {
		t.Fatal("nil DB accepted code")
	}
}

func TestSuccessfulReservationDoesNotResetConcurrentFailures(t *testing.T) {
	db, user := newBackupCodeTestUser(t)
	now := time.Unix(1800000000, 0)
	successful, err := ReserveAttempt(db, user, 3, now)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := ReserveAttempt(db, user, 3, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := successful.Success(); err != nil {
		t.Fatal(err)
	}
	if err := successful.Success(); err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveAttempt(db, user, 3, now); err != nil {
		t.Fatal(err)
	}
	if _, err := ReserveAttempt(db, user, 3, now); !errors.Is(err, ErrAttemptLimit) {
		t.Fatalf("successful login cleared other failures: %v", err)
	}
}

func TestMFAMigrationDefaultsPreserveLegacyAccount(t *testing.T) {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("CREATE TABLE users (id text PRIMARY KEY, username text, role text, enabled numeric, totp_secret text, totp_enabled numeric)").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.Exec("INSERT INTO users (id,username,role,enabled,totp_secret,totp_enabled) VALUES ('11111111-1111-1111-1111-111111111111','legacy','user',1,'',0)").Error; err != nil {
		t.Fatal(err)
	}
	if err := db.AutoMigrate(&models.User{}); err != nil {
		t.Fatal(err)
	}
	var user models.User
	if err := db.First(&user, "username = ?", "legacy").Error; err != nil {
		t.Fatal(err)
	}
	if user.TOTPLastStep != 0 || user.MFAWindowStart != 0 || user.MFAWindowAttempts != 0 || !user.Enabled {
		t.Fatalf("unexpected migrated account: %#v", user)
	}
	if _, err := ReserveAttempt(db, &user, 3, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func independentConnection(t *testing.T, db *gorm.DB) *gorm.DB {
	t.Helper()
	var path string
	if err := db.Raw("SELECT file FROM pragma_database_list WHERE name = 'main'").Scan(&path).Error; err != nil {
		t.Fatal(err)
	}
	other, err := gorm.Open(sqlite.Open("file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatal(err)
	}
	sqlDB, err := other.DB()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sqlDB.Close() })
	return other
}

func encryptedTOTP(t *testing.T, secret string) string {
	t.Helper()
	value, err := cryptokey.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
