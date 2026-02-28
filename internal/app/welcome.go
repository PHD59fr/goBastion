package app

import (
	"fmt"
	"os"
	"strings"
	"time"

	"goBastion/models"
	"goBastion/utils"

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

	ip := strings.Split(os.Getenv("SSH_CLIENT"), " ")[0]

	if currentUser.SystemUser {
		log.Warn("system user login rejected", slog.String("user", currentUser.Username), slog.String("ip", ip))
		fmt.Printf("User %s is a system user. System users are not allowed to use goBastion.\n", currentUser.Username)
		return false
	}

	if !currentUser.IsEnabled() {
		log.Warn("disabled user login rejected", slog.String("user", currentUser.Username), slog.String("ip", ip))
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

	currentUser.LastLoginAt = time.Now()
	currentUser.LastLoginFrom = ip
	db.Save(&currentUser)

	log.Info("user login", slog.String("user", currentUser.Username), slog.String("ip", ip), slog.String("role", currentUser.Role))

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
