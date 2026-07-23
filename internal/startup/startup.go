package startup

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	cmdaccount "goBastion/internal/commands/account"
	internaldb "goBastion/internal/db"
	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/utils/sshHostKey"
	gosync "goBastion/internal/utils/sync"
	"goBastion/internal/utils/validation"
)

// Run processes root-only CLI flags.
// With no flags: auto-restores from DB then ensures an admin user exists.
// Returns an exit code: 0 = success, 1 = fatal error, 2 = usage error, 3 = no admin configured.
func Run(db *gorm.DB, log *slog.Logger, adapter osadapter.SystemAdapter) int {
	regenerateSSHHostKeysFlag := flag.Bool("regenerateSSHHostKeys", false, "Force-regenerate SSH host keys")
	regenerateSFTPProxyHostKeyFlag := flag.Bool("regenerateSFTPProxyHostKey", false, "Force-regenerate the stable SFTP proxy host key")
	firstInstallFlag := flag.Bool("firstInstall", false, "Bootstrap first admin user")
	syncFlag := flag.Bool("sync", false, "Sync DB state to OS (DB is source of truth)")
	dbExportFlag := flag.Bool("dbExport", false, "Export the database as an encrypted JSON envelope to stdout")
	dbImportFlag := flag.Bool("dbImport", false, "Import an encrypted JSON envelope from stdin into an empty database")
	disableTOTPUser := flag.String("disableTOTP", "", "Disable TOTP + backup codes for a user (recovery)")
	disablePasswordUser := flag.String("disablePassword", "", "Disable password MFA for a user (recovery)")
	syncUserFlag := flag.String("syncUser", "", "Sync one DB user to the OS (privileged helper)")
	flag.Parse()

	syncer := gosync.New(db, adapter, *log)

	switch {
	case *regenerateSSHHostKeysFlag:
		if err := sshHostKey.GenerateSSHHostKeys(db, true); err != nil {
			log.Error("startup_failed", slog.String("reason", "regenerate_ssh_host_keys"), slog.Any("error", err))
			return 1
		}

	case *regenerateSFTPProxyHostKeyFlag:
		if _, _, _, err := sshHostKey.EnsureSFTPProxyHostKey(db, true); err != nil {
			log.Error("startup_failed", slog.String("reason", "regenerate_sftp_proxy_host_key"), slog.Any("error", err))
			return 1
		}
		fmt.Fprintln(os.Stderr, "✅ SFTP proxy host key regenerated.")

	case *firstInstallFlag:
		if err := createFirstAdminUser(db, log, syncer, adapter); err != nil {
			log.Error("startup_failed", slog.String("reason", "first_install"), slog.Any("error", err))
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			return 1
		}

	case *disableTOTPUser != "":
		return runDisableTOTP(db, log, *disableTOTPUser)

	case *disablePasswordUser != "":
		return runDisablePassword(db, log, *disablePasswordUser)

	case *syncFlag:
		fmt.Fprintln(os.Stderr, "Syncing database state to OS...")
		if err := syncer.EnforceFromDB(); err != nil {
			log.Error("sync_failed", slog.Any("error", err))
			fmt.Fprintf(os.Stderr, "Sync failed: %v\n", err)
			return 1
		}
		fmt.Fprintln(os.Stderr, "✅ Sync complete.")

	case *syncUserFlag != "":
		return runSyncUser(db, syncer, *syncUserFlag)

	case *dbExportFlag:
		return runDBExport(db, log)

	case *dbImportFlag:
		return runDBImport(db, log)

	default:
		return runStartup(db, log, syncer)
	}
	return 0
}

// runDBExport exports the current database as an encrypted envelope to stdout.
func runDBExport(db *gorm.DB, log *slog.Logger) int {
	fmt.Fprintln(os.Stderr, "Exporting database...")
	if err := internaldb.Export(db, os.Stdout, log); err != nil {
		log.Error("db_export_failed", slog.Any("error", err))
		fmt.Fprintf(os.Stderr, "Export failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "✅ Export complete.")
	return 0
}

// runDBImport reads an encrypted database export from stdin and restores it into an empty database.
func runDBImport(db *gorm.DB, log *slog.Logger) int {
	fmt.Fprintln(os.Stderr, "Importing database from stdin...")
	if err := internaldb.Import(db, os.Stdin, log); err != nil {
		log.Error("db_import_failed", slog.Any("error", err))
		fmt.Fprintf(os.Stderr, "Import failed: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "✅ Import complete.")
	return 0
}

// runStartup is the automatic startup sequence:
//  1. Sync DB → OS if data already exists (container restart).
//  2. Return 0 if an admin user exists, return 3 otherwise.
func runStartup(db *gorm.DB, log *slog.Logger, syncer *gosync.Syncer) int {
	var userCount int64
	if err := db.Model(&models.User{}).Count(&userCount).Error; err != nil {
		log.Error("startup_count_users_failed", slog.Any("error", err))
		return 1
	}
	if userCount > 0 {
		log.Info("startup_sync_state")
		if err := syncer.EnforceFromDB(); err != nil {
			log.Error("startup_failed", slog.Any("error", err))
			fmt.Fprintf(os.Stderr, "Startup sync failed: %v\n", err)
			return 1
		}
	}

	var adminCount int64
	expr := internaldb.BoolFalseExpr(db, "system_user") + " AND role = ?"
	if err := db.Model(&models.User{}).Where(expr, models.RoleAdmin).Count(&adminCount).Error; err != nil {
		log.Error("startup_count_admins_failed",
			slog.String("reason", "admin_count_error"),
			slog.Any("error", err),
		)
		return 1
	}
	if adminCount > 0 {
		log.Info("startup_ready")
		return 0
	}

	log.Warn("startup_no_admin_configured")
	// Exit code 3 is reserved for the recoverable first-install state. The
	// entrypoint must not confuse database/configuration failures with this.
	return 3
}

func runSyncUser(db *gorm.DB, syncer *gosync.Syncer, username string) int {
	username = strings.ToLower(strings.TrimSpace(username))
	if !validation.IsValidUsername(username) {
		fmt.Fprintln(os.Stderr, "Invalid username.")
		return 2
	}
	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		fmt.Fprintf(os.Stderr, "User %q not found: %v\n", username, err)
		return 1
	}
	if err := syncer.CreateUserFromDB(u); err != nil {
		fmt.Fprintf(os.Stderr, "User sync failed: %v\n", err)
		return 1
	}
	return 0
}

// createFirstAdminUser bootstraps the very first administrator account interactively.
func createFirstAdminUser(db *gorm.DB, log *slog.Logger, syncer *gosync.Syncer, adapter osadapter.SystemAdapter) error {
	var userCount int64
	if err := db.Model(&models.User{}).Where(internaldb.BoolFalseExpr(db, "system_user")).Count(&userCount).Error; err != nil {
		return fmt.Errorf("error counting users: %w", err)
	}
	if userCount > 0 {
		log.Warn("startup_first_install_aborted")
		fmt.Fprintln(os.Stderr, "⚠️  --firstInstall aborted: users already exist in the database.")
		return nil
	}

	reader := bufio.NewReader(os.Stdin)

	fmt.Print("Enter username: ")
	username, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading username: %w", err)
	}
	username = strings.TrimSpace(username)
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if !validation.IsValidUsername(username) {
		return fmt.Errorf("invalid username: use only letters, digits, dots, hyphens, and underscores (max 32 chars)")
	}

	fmt.Print("Enter the complete public SSH key: ")
	pubKey, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("error reading public key: %w", err)
	}
	pubKey = strings.TrimSpace(pubKey)
	if pubKey == "" {
		return fmt.Errorf("public key cannot be empty")
	}

	// Validate the SSH key BEFORE touching the database.
	if _, _, _, _, err = ssh.ParseAuthorizedKey([]byte(pubKey)); err != nil {
		return fmt.Errorf("invalid SSH public key: %w", err)
	}

	if err = syncer.CreateSystemUsersFromSystemToDb(); err != nil {
		return fmt.Errorf("error syncing system users: %w", err)
	}

	if err = cmdaccount.CreateUser(db, adapter, username, pubKey); err != nil {
		return fmt.Errorf("error creating user: %w", err)
	}
	if err = switchToAdmin(db, adapter, username); err != nil {
		return fmt.Errorf("error promoting user to admin: %w", err)
	}

	log.Info("startup_first_admin_created", slog.String("user", username))
	fmt.Printf("✅ User %s created successfully as administrator.\n", username)
	return nil
}

// switchToAdmin toggles the user's role to admin and updates sudoers.
func switchToAdmin(db *gorm.DB, adapter osadapter.SystemAdapter, username string) error {
	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	u.Role = models.RoleAdmin
	u.SuperOwner = true
	if err := db.Save(&u).Error; err != nil {
		return fmt.Errorf("error updating role: %w", err)
	}
	return adapter.UpdateSudoers(&u)
}

// runDisableTOTP disables TOTP and clears backup codes for the given username.
// This is a recovery mechanism when an admin loses access to their authenticator app.
func runDisableTOTP(db *gorm.DB, log *slog.Logger, username string) int {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		fmt.Fprintln(os.Stderr, "Usage: --disableTOTP <username>")
		return 1
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		fmt.Fprintf(os.Stderr, "Error: user '%s' not found.\n", username)
		return 1
	}

	if !u.TOTPEnabled && u.TOTPSecret == "" && u.BackupCodes == "" {
		fmt.Fprintf(os.Stderr, "User '%s' has no TOTP or backup codes configured. Nothing to do.\n", username)
		return 0
	}

	u.TOTPSecret = ""
	u.TOTPEnabled = false
	u.BackupCodes = ""
	if err := db.Save(&u).Error; err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to update user: %v\n", err)
		return 1
	}

	log.Info("disable_totp", slog.String("user", username))
	fmt.Printf("✅ TOTP, password MFA, and backup codes disabled for user '%s'.\n", username)
	return 0
}

// runDisablePassword disables password MFA for the given username.
// This is a recovery mechanism when an admin loses access to their password MFA.
func runDisablePassword(db *gorm.DB, log *slog.Logger, username string) int {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		fmt.Fprintln(os.Stderr, "Usage: --disablePassword <username>")
		return 1
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		fmt.Fprintf(os.Stderr, "Error: user '%s' not found.\n", username)
		return 1
	}

	if u.PasswordHash == "" {
		fmt.Fprintf(os.Stderr, "User '%s' has no password MFA configured. Nothing to do.\n", username)
		return 0
	}

	u.PasswordHash = ""
	if err := db.Save(&u).Error; err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to update user: %v\n", err)
		return 1
	}

	log.Info("disable_password", slog.String("user", username))
	fmt.Printf("✅ Password MFA disabled for user '%s'.\n", username)
	return 0
}
