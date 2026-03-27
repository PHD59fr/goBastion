package session

import (
	"fmt"
	"os"
	"time"

	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/system"

	"log/slog"

	"gorm.io/gorm"
)

// preConnectionCheck displays the personalized welcome message and validates the
// user's account status. Returns false if the session should be terminated.
func preConnectionCheck(db *gorm.DB, currentUser models.User, log *slog.Logger) bool {
	if os.Getuid() == 0 {
		fmt.Println("You cannot run this program as root.")
		os.Exit(1)
	}

	ip := system.ClientIPFromEnv()

	if currentUser.SystemUser {
		log.Warn("login rejected", slog.String("user", currentUser.Username), slog.String("from", ip), slog.String("reason", "system user"))
		fmt.Printf("User %s is a system user. System users are not allowed to use goBastion.\n", currentUser.Username)
		return false
	}

	if !currentUser.IsEnabled() {
		log.Warn("login rejected", slog.String("user", currentUser.Username), slog.String("from", ip), slog.String("reason", "account disabled"))
		fmt.Println(utils.FgRedB("Your account is disabled, please contact your administrator."))
		return false
	}

	fmt.Println(utils.FgYellow(logo))

	fmt.Print(utils.FgGreenB("▶") + " Welcome to goBastion, " + utils.FgYellowB(currentUser.Username) + "!\n")

	if !currentUser.LastLoginAt.IsZero() {
		msg := "Last login: " + currentUser.LastLoginAt.Format("Mon Jan 2 15:04:05 2006")
		if currentUser.LastLoginFrom != "" {
			msg += " from " + currentUser.LastLoginFrom
		}
		fmt.Println(msg)
	}

	now := time.Now()
	if err := db.Model(&currentUser).Updates(map[string]any{
		"last_login_at":   now,
		"last_login_from": ip,
	}).Error; err != nil {
		log.Warn("last_login_update_failed", slog.String("user", currentUser.Username), slog.String("error", err.Error()))
	}

	log.Info("login", slog.String("user", currentUser.Username), slog.String("from", ip), slog.String("role", currentUser.Role))

	return true
}

const logo = "                 .,,.      .,,.\n" +
	"                 | '|,,,,,,| '|\n" +
	"                 |' | '__  |' |\n" +
	"┌────────────────|__._/##\\_.__|─────────────────┐\n" +
	"│             ____            _   _             │\n" +
	"│  __ _  ___ | __ )  __ _ ___| |_(_) ___  _ __  │\n" +
	"│ / _` |/ _ \\|  _ \\ / _` / __| __| |/ _ \\| '_ \\ │\n" +
	"│| (_| | (_) | |_) | (_| \\__ \\ |_| | (_) | | | |│\n" +
	"│ \\__, |\\___/|____/ \\__,_|___/\\__|_|\\___/|_| |_|│\n" +
	"│ |___/                                         │\n" +
	"└───────────────────────────────────────────────┘"
