package mfa

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/utils/cryptokey"
	"goBastion/internal/utils/totp"
)

// AttemptWindow bounds the account-wide cooldown. Rejected requests never
// extend it, so retries cannot indefinitely lock an account.
const AttemptWindow = time.Minute

var ErrAttemptLimit = errors.New("MFA attempt limit reached; retry after the account window expires")

// ReserveAttempt charges an attempt before reading or verifying a factor. All
// processes and instances sharing the database use the same account budget.
// Successful verification refunds only its own reservation in the same window.
func ReserveAttempt(db *gorm.DB, user *models.User, maximum int, now time.Time) (*Attempt, error) {
	if db == nil || user == nil || maximum <= 0 {
		return nil, errors.New("MFA attempt reservation requires database, account and positive limit")
	}
	for range 16 {
		var fresh models.User
		if err := db.Select("id", "mfa_window_start", "mfa_window_attempts").Where("id = ? AND enabled = ? AND system_user = ?", user.ID, true, false).First(&fresh).Error; err != nil {
			return nil, fmt.Errorf("MFA attempt reservation: %w", err)
		}
		start, attempts := fresh.MFAWindowStart, fresh.MFAWindowAttempts
		if start == 0 || now.Unix()-start >= int64(AttemptWindow/time.Second) {
			start, attempts = now.Unix(), 0
		}
		if now.Unix() < start || attempts >= maximum {
			return nil, ErrAttemptLimit
		}
		result := db.Model(&models.User{}).
			Where("id = ? AND enabled = ? AND system_user = ? AND mfa_window_start = ? AND mfa_window_attempts = ?", user.ID, true, false, fresh.MFAWindowStart, fresh.MFAWindowAttempts).
			Updates(map[string]any{"mfa_window_start": start, "mfa_window_attempts": attempts + 1})
		if result.Error != nil {
			return nil, fmt.Errorf("MFA attempt reservation: %w", result.Error)
		}
		if result.RowsAffected == 1 {
			return &Attempt{db: db, user: user, start: start}, nil
		}
	}
	return nil, errors.New("MFA attempt reservation: concurrent update limit exceeded")
}

// Attempt identifies one budget reservation. Call Success once only after all
// required factors succeed. Its guarded decrement never resets other attempts.
type Attempt struct {
	mu        sync.Mutex
	db        *gorm.DB
	user      *models.User
	start     int64
	completed bool
}

// Valid refuses prompts left pending beyond their original reservation window.
// Check immediately before verifying a factor, after reading its input.
func (a *Attempt) Valid(now time.Time) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return !a.completed && now.Unix() >= a.start && now.Unix()-a.start < int64(AttemptWindow/time.Second)
}

func (a *Attempt) Success() error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.completed {
		return nil
	}
	result := a.db.Model(&models.User{}).Where("id = ? AND mfa_window_start = ? AND mfa_window_attempts > 0", a.user.ID, a.start).UpdateColumn("mfa_window_attempts", gorm.Expr("mfa_window_attempts - 1"))
	if result.Error != nil {
		return fmt.Errorf("MFA attempt completion: %w", result.Error)
	}
	a.completed = true
	return nil
}

// VerifyAndConsumeTOTP accepts a code only once, including concurrent callers.
// The current enabled account, TOTPEnabled state and encrypted profile must
// still match. JIT group MFA can legitimately use a stored seed while global
// account TOTP is disabled; callers must first enforce the relevant MFA policy.
func VerifyAndConsumeTOTP(db *gorm.DB, user *models.User, code string) (bool, error) {
	return verifyAndConsumeTOTPAt(db, user, code, time.Now())
}

func verifyAndConsumeTOTPAt(db *gorm.DB, user *models.User, code string, now time.Time) (bool, error) {
	if db == nil || user == nil {
		return false, errors.New("TOTP consumption requires database and account")
	}
	secret, err := cryptokey.Decrypt(user.TOTPSecret)
	if err != nil || secret == "" {
		return false, errors.New("TOTP profile cannot be decrypted")
	}
	step, matched := totp.MatchingStep(secret, code, now)
	if !matched {
		return false, nil
	}
	result := db.Model(&models.User{}).
		Where("id = ? AND enabled = ? AND system_user = ? AND totp_enabled = ? AND totp_secret = ? AND totp_last_step < ?", user.ID, true, false, user.TOTPEnabled, user.TOTPSecret, step).
		Update("totp_last_step", step)
	if result.Error != nil {
		return false, fmt.Errorf("TOTP consumption: %w", result.Error)
	}
	return result.RowsAffected == 1, nil
}
