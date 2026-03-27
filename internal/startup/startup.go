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
)

// Run processes root-only CLI flags.
// With no flags: auto-restores from DB then ensures an admin user exists.
func Run(db *gorm.DB, log *slog.Logger, adapter osadapter.SystemAdapter) {
	regenerateSSHHostKeysFlag := flag.Bool("regenerateSSHHostKeys", false, "Force-regenerate SSH host keys")
	firstInstallFlag := flag.Bool("firstInstall", false, "Bootstrap first admin user")
	syncFlag := flag.Bool("sync", false, "Sync DB state to OS (DB is source of truth)")
	dbExportFlag := flag.Bool("dbExport", false, "Export the database as an encrypted JSON envelope to stdout")
	dbImportFlag := flag.Bool("dbImport", false, "Import an encrypted JSON envelope from stdin into an empty database")
	disableTOTPUser := flag.String("disableTOTP", "", "Disable TOTP + backup codes for a user (recovery)")
	flag.Parse()

	syncer := gosync.New(db, adapter, *log)

	switch {
	case *regenerateSSHHostKeysFlag:
		if err := sshHostKey.GenerateSSHHostKeys(db, true); err != nil {
			log.Error("startup", slog.String("event", "startup"), slog.String("reason", "regenerate_ssh_host_keys"), slog.Any("error", err))
		}

	case *firstInstallFlag:
		if err := createFirstAdminUser(db, log, syncer, adapter); err != nil {
			log.Error("startup", slog.String("event", "startup"), slog.String("reason", "first_install"), slog.Any("error", err))
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case *disableTOTPUser != "":
		runDisableTOTP(db, log, *disableTOTPUser)

	case *syncFlag:
		fmt.Fprintln(os.Stderr, "Syncing database state to OS...")
		if err := syncer.EnforceFromDB(); err != nil {
			log.Error("sync", slog.String("event", "sync"), slog.Any("error", err))
			fmt.Fprintf(os.Stderr, "Sync failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintln(os.Stderr, "✅ Sync complete.")

	case *dbExportFlag:
		runDBExport(db, log)

	case *dbImportFlag:
		runDBImport(db, log)

	default:
		runStartup(db, log, syncer)
	}
}

// runDBExport exports the current database as an encrypted envelope to stdout.
func runDBExport(db *gorm.DB, log *slog.Logger) {
	fmt.Fprintln(os.Stderr, "Exporting database...")
	if err := internaldb.Export(db, os.Stdout, log); err != nil {
		log.Error("db_export", slog.String("event", "db_export"), slog.Any("error", err))
		fmt.Fprintf(os.Stderr, "Export failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "✅ Export complete.")
}

// runDBImport reads an encrypted database export from stdin and restores it into an empty database.
func runDBImport(db *gorm.DB, log *slog.Logger) {
	fmt.Fprintln(os.Stderr, "Importing database from stdin...")
	if err := internaldb.Import(db, os.Stdin, log); err != nil {
		log.Error("db_import", slog.String("event", "db_import"), slog.Any("error", err))
		fmt.Fprintf(os.Stderr, "Import failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stderr, "✅ Import complete.")
}

// runStartup is the automatic startup sequence:
//  1. Sync DB → OS if data already exists (container restart).
//  2. Exit 0 if an admin user exists, exit 1 otherwise.
func runStartup(db *gorm.DB, log *slog.Logger, syncer *gosync.Syncer) {
	var userCount int64
	db.Model(&models.User{}).Count(&userCount)
	if userCount > 0 {
		log.Info("startup", slog.String("event", "startup"), slog.String("reason", "sync_state"))
		if err := syncer.EnforceFromDB(); err != nil {
			log.Error("startup", slog.String("event", "startup"), slog.Any("error", err))
		}
	}

	var adminCount int64
	expr := internaldb.BoolFalseExpr(db, "system_user") + " AND role = ?"
	if err := db.Model(&models.User{}).Where(expr, models.RoleAdmin).Count(&adminCount).Error; err != nil {
		log.Error("startup: error counting admin users",
			slog.String("event", "startup"),
			slog.String("reason", "admin_count_error"),
			slog.Any("error", err),
		)
		os.Exit(1)
	}
	if adminCount > 0 {
		log.Info("startup", slog.String("event", "startup"), slog.String("reason", "ready"))
		return
	}

	log.Warn("No admin user configured. Run: docker exec -it <container> goBastion --firstInstall",
		slog.String("event", "startup"),
		slog.String("reason", "no_admin_configured"),
	)
	os.Exit(1)
}

// createFirstAdminUser bootstraps the very first administrator account interactively.
func createFirstAdminUser(db *gorm.DB, log *slog.Logger, syncer *gosync.Syncer, adapter osadapter.SystemAdapter) error {
	var userCount int64
	if err := db.Model(&models.User{}).Where(internaldb.BoolFalseExpr(db, "system_user")).Count(&userCount).Error; err != nil {
		return fmt.Errorf("error counting users: %w", err)
	}
	if userCount > 0 {
		log.Warn("startup", slog.String("event", "startup"), slog.String("reason", "first_install_aborted"))
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

	log.Info("startup", slog.String("event", "startup"), slog.String("reason", "first_admin_created"), slog.String("user", username))
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
	if err := db.Save(&u).Error; err != nil {
		return fmt.Errorf("error updating role: %w", err)
	}
	return adapter.UpdateSudoers(&u)
}

// runDisableTOTP disables TOTP and clears backup codes for the given username.
// This is a recovery mechanism when an admin loses access to their authenticator app.
func runDisableTOTP(db *gorm.DB, log *slog.Logger, username string) {
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		fmt.Fprintln(os.Stderr, "Usage: --disableTOTP <username>")
		os.Exit(1)
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		fmt.Fprintf(os.Stderr, "Error: user '%s' not found.\n", username)
		os.Exit(1)
	}

	if !u.TOTPEnabled && u.PasswordHash == "" && u.BackupCodes == "" {
		fmt.Fprintf(os.Stderr, "User '%s' has no MFA configured. Nothing to do.\n", username)
		return
	}

	u.TOTPSecret = ""
	u.TOTPEnabled = false
	u.PasswordHash = ""
	u.BackupCodes = ""
	if err := db.Save(&u).Error; err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to update user: %v\n", err)
		os.Exit(1)
	}

	log.Info("startup", slog.String("event", "disable_totp"), slog.String("user", username))
	fmt.Printf("✅ TOTP, password MFA, and backup codes disabled for user '%s'.\n", username)
}
