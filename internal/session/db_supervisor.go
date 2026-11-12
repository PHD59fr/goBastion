package session

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"os/user"
	"strconv"
	"syscall"

	"goBastion/internal/commands/ssh"
	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/dbConnector"
	"goBastion/internal/utils/validation"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RunDBSupervisor authenticates sudo's actor independently of the unprivileged frontend.
func RunDBSupervisor(db *gorm.DB, log *slog.Logger, args []string) int {
	name := os.Getenv("SUDO_USER")
	uid := os.Getenv("SUDO_UID")
	actor, err := user.Lookup(name)
	if os.Geteuid() != 0 || err != nil || !validation.IsValidUsername(name) || actor.Uid != uid || name == "root" {
		return 1
	}
	numeric, err := strconv.Atoi(uid)
	if err != nil || numeric < 1000 {
		return 1
	}
	var u models.User
	if err = db.Where(map[string]any{"username": name, "enabled": true, "system_user": false}).First(&u).Error; err != nil {
		return 1
	}
	if !config.Get().Database.Enabled || u.OSHOnly || config.Get().ForceOSHOnly.Enabled || (config.Get().Maintenance.Enabled && !u.IsAdmin()) {
		return 1
	}
	if len(args) < 1 {
		return 2
	}
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--mysql", "--pg", "--redis":
		case "--dbname":
			i++
			if i >= len(args) {
				return 2
			}
		default:
			return 2
		}
	}
	if !checkMFA(db, &u, log) {
		return 1
	}
	access, _, err := dbConnector.ResolveTargetDetailed(db, u, args[0], args[1:]...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err = refreshAuthenticatedUser(db, &u); err != nil {
		return 1
	}
	if u.OSHOnly || config.Get().ForceOSHOnly.Enabled || (config.Get().Maintenance.Enabled && !u.IsAdmin()) {
		return 1
	}
	// Re-resolve after authentication so a concurrent demotion/ACL removal cannot
	// leave an administrative override cached across the MFA prompt.
	access, _, err = dbConnector.ResolveTargetDetailed(db, u, args[0], args[1:]...)
	if err != nil {
		return 1
	}
	if access.MFARequired && (!u.TOTPEnabled || u.TOTPSecret == "") {
		if !ssh.CheckJITMFA(db, &u, log) {
			return 1
		}
		if err = refreshAuthenticatedUser(db, &u); err != nil || u.OSHOnly || (config.Get().Maintenance.Enabled && !u.IsAdmin()) {
			return 1
		}
		access, _, err = dbConnector.ResolveTargetDetailed(db, u, args[0], args[1:]...)
		if err != nil {
			return 1
		}
	}
	id := uuid.NewString()
	_ = os.Setenv("GOB_SESSION_ID", id)
	release, err := registerActiveSession(db, &u, id, "db")
	if err != nil {
		return 1
	}
	defer release()
	if !recordAuthenticatedLogin(db, u, log) {
		return 1
	}
	displayWelcome(u, welcomeDB)
	// The controller is root, so UID-based sync termination alone cannot revoke it.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT)
	defer cancel()
	monitor := startDBActorMonitor(ctx, db, u.ID, cancel, dbSessionAuthorizationCheck(u, args[0], args[1:], access))
	defer monitor.stop()
	log = log.With("session_id", id, "user", u.Username, "target", access.Host, "access_source", access.Source)
	log.Info("db_session_start")
	err = dbConnector.ConnectContext(ctx, db, u, access)
	err = monitor.finish(ctx, err)
	log.Info("db_session_end", "error", err, "revoked", monitor.revoked.Load())
	if err != nil {
		return 1
	}
	return 0
}
