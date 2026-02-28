package main

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"goBastion/commands"
	internalApp "goBastion/internal/app"
	internalDB "goBastion/internal/db"
	"goBastion/models"
	"goBastion/utils/logger"
	"goBastion/utils/sshHostKey"
	"goBastion/utils/sync"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// main is the binary entry point; routes to admin flags, startup or user session.
func main() {
	log := logger.NewLogger()

	db, err := internalDB.Init(log)
	if err != nil {
		log.Error("Failed to initialize database", slog.Any("error", err))
		return
	}

	if isRootNonSSH() {
		handleAdminFlags(db, log)
		return
	}

	internalApp.Run(db, log)
}

// isRootNonSSH returns true when running as root outside an SSH session.
func isRootNonSSH() bool {
	if os.Getuid() != 0 {
		return false
	}
	for _, env := range []string{"SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY"} {
		if _, exists := os.LookupEnv(env); exists {
			return false
		}
	}
	return true
}

// handleAdminFlags processes root-only CLI flags.
// With no flags: auto-restores from DB then ensures an admin user exists.
func handleAdminFlags(db *gorm.DB, log *slog.Logger) {
	regenerateSSHHostKeysFlag := flag.Bool("regenerateSSHHostKeys", false, "Force-regenerate SSH host keys")
	firstInstallFlag := flag.Bool("firstInstall", false, "Bootstrap first admin user")
	flag.Parse()

	switch {
	case *regenerateSSHHostKeysFlag:
		if err := sshHostKey.GenerateSSHHostKeys(db, true); err != nil {
			log.Error("Error regenerating SSH host keys", slog.Any("error", err))
		}

	case *firstInstallFlag:
		if err := createFirstAdminUser(db); err != nil {
			log.Error("Error creating first admin user", slog.Any("error", err))
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	default:
		runStartup(db, log)
	}
}

// runStartup is the automatic startup sequence:
//  1. Restore system state from DB if data already exists (container restart).
//  2. Exit 0 if an admin user exists, exit 1 otherwise.
//     When no admin is found, print a one-time instruction and let entrypoint retry.
func runStartup(db *gorm.DB, log *slog.Logger) {
	var userCount int64
	db.Model(&models.User{}).Count(&userCount)
	if userCount > 0 {
		fmt.Println("[goBastion] Existing database found, restoring state...")
		if err := sync.RestoreBastionSSHHostKeys(db); err != nil {
			log.Error("Error restoring SSH host keys", slog.Any("error", err))
		}
		if err := sync.CreateSystemUsersFromSystemToDb(db); err != nil {
			log.Error("Error syncing system users", slog.Any("error", err))
		}
		if err := sync.CreateUsersFromDB(db, *log); err != nil {
			log.Error("Error restoring users from DB", slog.Any("error", err))
		}
	}

	var adminCount int64
	db.Model(&models.User{}).Where("system_user = ? AND role = ?", false, models.RoleAdmin).Count(&adminCount)
	if adminCount > 0 {
		fmt.Println("[goBastion] Admin user confirmed. Ready.")
		return
	}

	fmt.Println("[goBastion] No admin user configured.")
	fmt.Println("[goBastion] Run: docker exec -it <container> /app/goBastion --firstInstall")
	os.Exit(1)
}

// createFirstAdminUser bootstraps the very first administrator account interactively.
// The SSH public key is validated before any database write to avoid leaving orphan records.
func createFirstAdminUser(db *gorm.DB) error {
	var userCount int64
	if err := db.Model(&models.User{}).Where("system_user = ?", false).Count(&userCount).Error; err != nil {
		return fmt.Errorf("error counting users: %w", err)
	}
	if userCount > 0 {
		fmt.Println("Cannot run --firstInstall: there are already users in the database.")
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

	if err = sync.CreateSystemUsersFromSystemToDb(db); err != nil {
		return fmt.Errorf("error syncing system users: %w", err)
	}
	if err = commands.CreateUser(db, username, pubKey); err != nil {
		return fmt.Errorf("error creating user: %w", err)
	}
	if err = commands.SwitchSysRoleUser(db, username); err != nil {
		return fmt.Errorf("error promoting user to admin: %w", err)
	}

	fmt.Printf("User %s created successfully as administrator.\n", username)
	return nil
}
