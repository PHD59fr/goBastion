package session

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/mfa"
	"goBastion/internal/models"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"gorm.io/gorm"
)

func enrollmentRequest(args []string) bool {
	if len(args) == 1 {
		tokens, err := parseCommandLine(args[0])
		return err == nil && len(tokens) == 2 && tokens[0] == "-osh" && tokens[1] == "selfSetupTOTP"
	}
	return len(args) == 2 && args[0] == "-osh" && args[1] == "selfSetupTOTP"
}

func checkMFAForRequest(db *gorm.DB, u *models.User, log *slog.Logger, args []string) bool {
	if config.Get().RequireMFA.Enabled && !u.TOTPEnabled && enrollmentRequest(args) {
		// Preserve the independent password factor; only the missing TOTP check is waived.
		return checkPasswordMFA(db, u, log)
	}
	return checkMFA(db, u, log)
}

func checkPasswordMFA(db *gorm.DB, u *models.User, log *slog.Logger) bool {
	if u.PasswordHash == "" {
		return true
	}
	reservation, err := mfa.ReserveAttempt(db, u, config.Get().MFA.MaxAttempts, time.Now())
	if err != nil {
		log.Warn("enrollment_password_mfa_denied", "user", u.Username, "reason", "attempt_budget_unavailable")
		fmt.Fprintln(os.Stderr, "Password MFA unavailable or attempt limit reached.")
		return false
	}
	fmt.Print("Enter password: ")
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	defer clear(password)
	fmt.Println()
	ok := err == nil && reservation.Valid(time.Now()) && bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), password) == nil
	if !ok {
		fmt.Fprintln(os.Stderr, "Password MFA verification failed.")
		log.Warn("enrollment_password_mfa_denied", "user", u.Username)
		return false
	}
	if err := reservation.Success(); err != nil {
		log.Warn("enrollment_password_mfa_denied", "user", u.Username, "reason", "attempt_completion_failed")
		return false
	}
	return true
}
