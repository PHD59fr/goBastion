package session

import (
	"fmt"
	"strings"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"gorm.io/gorm"
)

func isOSHCommand(command string) bool {
	command = strings.TrimSpace(command)
	return command == "-osh" || strings.HasPrefix(command, "-osh ")
}

func interactiveBlockMessage(user *models.User) string {
	if user.OSHOnly || config.Get().ForceOSHOnly.Enabled {
		return "⛔ This account is limited to -osh commands only. Interactive mode is disabled."
	}
	if !config.Get().Interactive.Enabled {
		return "⛔ Interactive shell is disabled by configuration."
	}
	return ""
}

// Refresh before dispatch: a session must not retain a cached administrative
// role, superowner flag or enabled state after an administrator revokes it.
func refreshSessionUser(db *gorm.DB, user *models.User) error {
	if user == nil {
		return fmt.Errorf("missing session account")
	}
	var fresh models.User
	if err := db.First(&fresh, "id = ?", user.ID).Error; err != nil {
		return err
	}
	if !fresh.Enabled || fresh.SystemUser {
		return fmt.Errorf("account disabled")
	}
	*user = fresh
	return nil
}
