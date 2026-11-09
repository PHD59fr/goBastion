package session

import (
	"context"
	"fmt"
	"goBastion/internal/telemetry"
	"log/slog"
	"strings"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/mfa"
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

// Authentication was performed against this snapshot. Role changes take effect
// immediately; changes to the factors themselves require a fresh authentication.
func refreshAuthenticatedUser(db *gorm.DB, u *models.User) error {
	before := *u
	if err := refreshSessionUser(db, u); err != nil {
		return err
	}
	if before.PasswordHash != u.PasswordHash || before.TOTPEnabled != u.TOTPEnabled || before.TOTPSecret != u.TOTPSecret {
		return fmt.Errorf("authentication factors changed; reconnect")
	}
	return nil
}
func validateSessionAdmission(db *gorm.DB, u *models.User, command string, args []string) (resultErr error) {
	ctx, span := telemetry.Start(context.Background(), "session.authorization", telemetry.Component("session"))
	started := time.Now()
	defer func() {
		actor := ""
		if u != nil {
			actor = u.Username
		}
		decision := "allow"
		if resultErr != nil {
			decision = "deny"
		}
		slog.InfoContext(ctx, "authorization_result", "actor", actor, "decision", decision, "duration", time.Since(started))
		if resultErr != nil {
			span.Failure()
		} else {
			span.Success()
		}
		span.End()
	}()

	if u == nil {
		return fmt.Errorf("missing session account")
	}
	if err := refreshAuthenticatedUser(db, u); err != nil {
		return err
	}
	cfg := config.Get()
	if cfg.Maintenance.Enabled && !u.IsAdmin() {
		return fmt.Errorf("bastion under maintenance")
	}
	interactive := command == "" || command == "--"
	if interactive {
		if msg := interactiveBlockMessage(u); msg != "" {
			return fmt.Errorf("%s", msg)
		}
	} else if (u.OSHOnly || cfg.ForceOSHOnly.Enabled) && !isOSHCommand(command) {
		return fmt.Errorf("account is limited to -osh commands")
	}
	if _, _, ok := parseTCPProxyRequest(command, args); ok {
		if msg := tcpProxyMFABlockMessage(*u); msg != "" {
			return fmt.Errorf("%s", msg)
		}
	}
	if strings.HasPrefix(command, "sftp-session") {
		return mfa.OpaqueTransportError(*u, "SFTP proxy")
	}
	return nil
}
