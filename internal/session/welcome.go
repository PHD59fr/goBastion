package session

import (
	"fmt"
	"os"
	"strings"
	"time"

	"goBastion/internal/config"
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
		return false
	}

	ip := system.ClientIPFromEnv()

	if currentUser.SystemUser {
		log.Warn("login_rejected", slog.String("user", currentUser.Username), slog.String("from", ip), slog.String("reason", "system user"))
		fmt.Printf("User %s is a system user. System users are not allowed to use goBastion.\n", currentUser.Username)
		return false
	}

	if !currentUser.IsEnabled() {
		log.Warn("login_rejected", slog.String("user", currentUser.Username), slog.String("from", ip), slog.String("reason", "account disabled"))
		fmt.Println(utils.FgRedB("Your account is disabled, please contact your administrator."))
		return false
	}

	mode := welcomeSSH
	if len(os.Args) == 1 || strings.TrimSpace(os.Args[1]) == "" || os.Args[1] == "--" || isOSHCommand(os.Args[1]) {
		mode = welcomeInteractive
	}
	displayWelcome(currentUser, mode)

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

type welcomeMode int

const (
	welcomeSSH welcomeMode = iota
	welcomeDB
	welcomeInteractive
)

// displayWelcome renders the same greeting for SSH and DB sessions. Account
// checks and login updates belong to each caller, including the root DB supervisor.
func displayWelcome(currentUser models.User, mode welcomeMode) {
	displaySplash(mode)
	fmt.Print(utils.FgGreenB("▶") + " Welcome to goBastion, " + utils.FgYellowB(currentUser.Username) + "!\n")
	if !currentUser.LastLoginAt.IsZero() {
		msg := "Last login: " + currentUser.LastLoginAt.Format("Mon Jan 2 15:04:05 2006")
		if currentUser.LastLoginFrom != "" {
			msg += " from " + currentUser.LastLoginFrom
		}
		fmt.Println(msg)
	}
}

func displaySplash(mode welcomeMode) {
	cfg := config.Get().Splash
	enabled := (mode == welcomeSSH && cfg.SSHEnabled) || (mode == welcomeDB && cfg.DBEnabled) || (mode == welcomeInteractive && cfg.InteractiveEnabled)
	if !cfg.Enabled || !enabled {
		return
	}
	fmt.Println(utils.FgYellow(logo))
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
