package mfa

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"goBastion/internal/config"
	internaldb "goBastion/internal/db"
	"goBastion/internal/models"
	"goBastion/internal/utils/totp"
)

// TestTOTPBackendIntegration runs locally with SQLite. The disposable backend
// runner supplies a dedicated empty MySQL/PostgreSQL database through the opt-in
// environment below. Only the first connection migrates, as at root startup;
// the independent authentication connections explicitly skip migration.
func TestTOTPBackendIntegration(t *testing.T) {
	driver := os.Getenv("GOB_MFA_INTEGRATION_DRIVER")
	dsn := os.Getenv("GOB_MFA_INTEGRATION_DSN")
	if driver == "" {
		driver = "sqlite"
		dsn = filepath.Join(t.TempDir(), "mfa-backend.db")
	} else {
		if os.Getenv("GOB_MFA_INTEGRATION_DISPOSABLE") != "1" || dsn == "" {
			t.Fatal("explicit MFA backend checks require a disposable database and DSN")
		}
		if driver != "sqlite" && driver != "mysql" && driver != "postgres" {
			t.Fatal("MFA integration driver must be sqlite, mysql or postgres")
		}
	}
	t.Setenv("DB_DRIVER", driver)
	t.Setenv("DB_DSN", dsn)
	config.ResetForTesting()
	t.Cleanup(config.ResetForTesting)

	open := func(migrate bool) *gorm.DB {
		database, err := internaldb.Init(nil, migrate)
		if err != nil {
			// A supplied DSN can contain credentials; keep connection diagnostics
			// out of test output and leave service diagnosis to the runner.
			t.Fatalf("initialize %s MFA database failed (%T)", driver, err)
		}
		pool, err := database.DB()
		if err != nil {
			t.Fatal("read MFA database pool")
		}
		t.Cleanup(func() { _ = pool.Close() })
		return database
	}
	database := open(true)
	connections := []*gorm.DB{open(false), open(false), open(false)}
	now := time.Unix(1800000000, 0)
	const seed = "JBSWY3DPEHPK3PXP"

	newUser := func(t *testing.T) *models.User {
		t.Helper()
		user := &models.User{
			Username: "mfa-backend-" + uuid.NewString(), Role: models.RoleUser,
			Enabled: true, TOTPEnabled: true, TOTPSecret: encryptedTOTP(t, seed),
		}
		if err := database.Create(user).Error; err != nil {
			t.Fatalf("create MFA fixture: %v", err)
		}
		return user
	}
	codeAt := func(t *testing.T, secret string, at time.Time) string {
		t.Helper()
		code, err := totp.GenerateCode(secret, at)
		if err != nil {
			t.Fatal("generate MFA fixture code")
		}
		return code
	}
	readUser := func(t *testing.T, user *models.User) *models.User {
		t.Helper()
		var fresh models.User
		if err := database.First(&fresh, "id = ?", user.ID).Error; err != nil {
			t.Fatalf("read MFA fixture: %v", err)
		}
		return &fresh
	}

	t.Run("one consumption across independent connections", func(t *testing.T) {
		user := newUser(t)
		code := codeAt(t, seed, now)
		var accepted atomic.Int32
		var workers sync.WaitGroup
		start := make(chan struct{})
		for i := range 12 {
			workers.Add(1)
			go func(connection *gorm.DB) {
				defer workers.Done()
				<-start
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				ok, err := verifyAndConsumeTOTPAt(connection.WithContext(ctx), cloneUser(user), code, now)
				if err != nil {
					t.Errorf("consume MFA fixture: %v", err)
				}
				if ok {
					accepted.Add(1)
				}
			}(connections[i%len(connections)])
		}
		close(start)
		workers.Wait()
		if accepted.Load() != 1 {
			t.Fatalf("one step accepted %d times", accepted.Load())
		}
		if readUser(t, user).TOTPLastStep != now.Unix()/30 {
			t.Fatal("successful authentication did not persist the consumed step")
		}
		for _, at := range []time.Time{now, now.Add(-30 * time.Second)} {
			if ok, err := verifyAndConsumeTOTPAt(connections[0], cloneUser(user), codeAt(t, seed, at), now); err != nil || ok {
				t.Fatalf("replayed or older step accepted=%t error=%v", ok, err)
			}
		}
		next := now.Add(30 * time.Second)
		if ok, err := verifyAndConsumeTOTPAt(connections[1], cloneUser(user), codeAt(t, seed, next), next); err != nil || !ok {
			t.Fatalf("fresh next step accepted=%t error=%v", ok, err)
		}
	})

	t.Run("stale and invalid profiles fail closed", func(t *testing.T) {
		for _, change := range []string{"disabled", "system account", "factor disabled", "seed replaced", "soft deleted"} {
			t.Run(change, func(t *testing.T) {
				user := newUser(t)
				updates := map[string]any{}
				switch change {
				case "disabled":
					updates["enabled"] = false
				case "system account":
					updates["system_user"] = true
				case "factor disabled":
					updates["totp_enabled"] = false
				case "seed replaced":
					updates["totp_secret"] = encryptedTOTP(t, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
				case "soft deleted":
					updates["deleted_at"] = now
				}
				if err := database.Model(&models.User{}).Where("id = ?", user.ID).UpdateColumns(updates).Error; err != nil {
					t.Fatalf("revoke MFA fixture: %v", err)
				}
				if ok, err := verifyAndConsumeTOTPAt(connections[0], user, codeAt(t, seed, now), now); err != nil || ok {
					t.Fatalf("stale profile accepted=%t error=%v", ok, err)
				}
				var fresh models.User
				if err := database.Unscoped().First(&fresh, "id = ?", user.ID).Error; err != nil || fresh.TOTPLastStep != 0 {
					t.Fatal("rejected stale profile consumed a step")
				}
			})
		}
		for _, stored := range []string{"", seed, "gob:v2:default:invalid"} {
			user := newUser(t)
			user.TOTPSecret = stored
			if ok, err := verifyAndConsumeTOTPAt(connections[0], user, codeAt(t, seed, now), now); err == nil || ok {
				t.Fatal("unauthenticated profile accepted")
			}
		}
	})

	t.Run("revocation commits between verification and consumption", func(t *testing.T) {
		user := newUser(t)
		connection := open(false)
		entered, release := make(chan struct{}), make(chan struct{})
		var enteredOnce, releaseOnce sync.Once
		t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
		if err := connection.Callback().Update().Before("gorm:update").Register("test:mfa_revoke_before_consumption", func(tx *gorm.DB) {
			enteredOnce.Do(func() {
				close(entered)
				select {
				case <-release:
				case <-tx.Statement.Context.Done():
				}
			})
		}); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		type result struct {
			accepted bool
			err      error
		}
		done := make(chan result, 1)
		code := codeAt(t, seed, now)
		go func() {
			ok, err := verifyAndConsumeTOTPAt(connection.WithContext(ctx), user, code, now)
			done <- result{ok, err}
		}()
		select {
		case <-entered:
		case <-ctx.Done():
			t.Fatal("authentication did not reach the consumption update")
		}
		if err := database.Model(&models.User{}).Where("id = ?", user.ID).Update("enabled", false).Error; err != nil {
			t.Fatalf("concurrent account revocation: %v", err)
		}
		if ctx.Err() != nil {
			t.Fatal("revocation did not commit before the authentication deadline")
		}
		releaseOnce.Do(func() { close(release) })
		select {
		case got := <-done:
			if got.err != nil || got.accepted {
				t.Fatalf("concurrently revoked profile accepted=%t error=%v", got.accepted, got.err)
			}
		case <-ctx.Done():
			t.Fatal("authentication update did not finish")
		}
		if readUser(t, user).TOTPLastStep != 0 {
			t.Fatal("concurrent revocation consumed a step")
		}
	})

	t.Run("database failure does not accept or consume", func(t *testing.T) {
		user := newUser(t)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		code := codeAt(t, seed, now)
		if ok, err := verifyAndConsumeTOTPAt(connections[0].WithContext(ctx), user, code, now); err == nil || ok {
			t.Fatal("canceled database request accepted a code")
		}
		closed := open(false)
		pool, _ := closed.DB()
		if err := pool.Close(); err != nil {
			t.Fatal(err)
		}
		if ok, err := verifyAndConsumeTOTPAt(closed, user, code, now); err == nil || ok {
			t.Fatal("closed database accepted a code")
		}
		if readUser(t, user).TOTPLastStep != 0 {
			t.Fatal("database failure consumed a step")
		}
		if ok, err := verifyAndConsumeTOTPAt(connections[1], user, code, now); err != nil || !ok {
			t.Fatalf("unused code after database recovery accepted=%t error=%v", ok, err)
		}
	})

	t.Run("reencryption preserves replay state and new enrollment resets it", func(t *testing.T) {
		user := newUser(t)
		code := codeAt(t, seed, now)
		if ok, err := verifyAndConsumeTOTPAt(connections[0], user, code, now); err != nil || !ok {
			t.Fatal("initial enrollment code was not accepted")
		}
		fresh := readUser(t, user)
		fresh.TOTPSecret = seed
		if err := UpdateTOTP(database, fresh).Error; err != nil {
			t.Fatalf("reencrypt unchanged seed: %v", err)
		}
		fresh = readUser(t, user)
		if fresh.TOTPLastStep != now.Unix()/30 {
			t.Fatal("reencryption cleared consumed step")
		}
		if ok, err := verifyAndConsumeTOTPAt(connections[1], fresh, code, now); err != nil || ok {
			t.Fatal("reencryption enabled replay")
		}
		const replacement = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
		fresh.TOTPSecret = replacement
		if err := UpdateTOTP(database, fresh).Error; err != nil {
			t.Fatalf("replace enrolled seed: %v", err)
		}
		fresh = readUser(t, user)
		if fresh.TOTPLastStep != 0 {
			t.Fatal("new enrollment retained previous seed's replay state")
		}
		if ok, err := verifyAndConsumeTOTPAt(connections[2], fresh, codeAt(t, replacement, now), now); err != nil || !ok {
			t.Fatal("replacement enrollment code was not accepted")
		}
	})

	t.Run("attempt budget is shared across connections", func(t *testing.T) {
		user := newUser(t)
		var accepted atomic.Int32
		var workers sync.WaitGroup
		start := make(chan struct{})
		for i := range 12 {
			workers.Add(1)
			go func(connection *gorm.DB) {
				defer workers.Done()
				<-start
				_, err := ReserveAttempt(connection, user, 3, now)
				if err == nil {
					accepted.Add(1)
				} else if !errors.Is(err, ErrAttemptLimit) {
					t.Errorf("reserve shared attempt: %v", err)
				}
			}(connections[i%len(connections)])
		}
		close(start)
		workers.Wait()
		if accepted.Load() != 3 || readUser(t, user).MFAWindowAttempts != 3 {
			t.Fatal("shared attempt budget did not permit exactly its configured limit")
		}
	})
}
