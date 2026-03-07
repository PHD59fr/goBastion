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
	flag.Parse()

	syncer := gosync.New(db, adapter, *log)

	switch {
	case *regenerateSSHHostKeysFlag:
		if err := sshHostKey.GenerateSSHHostKeys(db, true); err != nil {
			log.Error("Error regenerating SSH host keys", slog.Any("error", err))
		}

	case *firstInstallFlag:
		if err := createFirstAdminUser(db, log, syncer, adapter); err != nil {
			log.Error("Error creating first admin user", slog.Any("error", err))
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}

	case *syncFlag:
		if err := syncer.EnforceFromDB(); err != nil {
			log.Error("Error during sync", slog.Any("error", err))
			os.Exit(1)
		}

	default:
		runStartup(db, log, syncer)
	}
}

// runStartup is the automatic startup sequence:
//  1. Sync DB → OS if data already exists (container restart).
//  2. Exit 0 if an admin user exists, exit 1 otherwise.
func runStartup(db *gorm.DB, log *slog.Logger, syncer *gosync.Syncer) {
	var userCount int64
	db.Model(&models.User{}).Count(&userCount)
	if userCount > 0 {
		fmt.Println("[goBastion] Existing database found, syncing state...")
		if err := syncer.EnforceFromDB(); err != nil {
			log.Error("Error during startup sync", slog.Any("error", err))
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
func createFirstAdminUser(db *gorm.DB, log *slog.Logger, syncer *gosync.Syncer, adapter osadapter.SystemAdapter) error {
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

	if err = syncer.CreateSystemUsersFromSystemToDb(); err != nil {
		return fmt.Errorf("error syncing system users: %w", err)
	}

	// CreateUser and SwitchSysRoleUser are imported from the account package
	// once the commands migration is complete. For now we call them directly.
	if err = createUser(db, adapter, syncer, username, pubKey); err != nil {
		return fmt.Errorf("error creating user: %w", err)
	}
	if err = switchToAdmin(db, adapter, username); err != nil {
		return fmt.Errorf("error promoting user to admin: %w", err)
	}

	log.Info("first admin user created", slog.String("username", username))
	fmt.Printf("User %s created successfully as administrator.\n", username)
	return nil
}

// createUser creates the DB record, registers the ingress key, and creates the OS user.
func createUser(db *gorm.DB, adapter osadapter.SystemAdapter, syncer *gosync.Syncer, username, pubKey string) error {
	username = strings.ToLower(strings.TrimSpace(username))

	var count int64
	if err := db.Model(&models.User{}).Where("username = ? AND deleted_at IS NULL", username).Count(&count).Error; err != nil {
		return fmt.Errorf("error querying database: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("user '%s' already exists", username)
	}

	newUser := models.User{Username: username, Role: models.RoleUser, Enabled: true}
	if err := db.Create(&newUser).Error; err != nil {
		return err
	}
	if err := createDBIngressKey(db, &newUser, pubKey); err != nil {
		return err
	}
	return syncer.CreateUserFromDB(newUser)
}

// createDBIngressKey validates and persists an SSH ingress public key.
func createDBIngressKey(db *gorm.DB, user *models.User, pubKeyStr string) error {
	pubKeyStr = strings.TrimSpace(pubKeyStr)
	if pubKeyStr == "" {
		return fmt.Errorf("public SSH key cannot be empty")
	}
	parsedKey, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(pubKeyStr))
	if err != nil || parsedKey == nil {
		return fmt.Errorf("invalid SSH key: %w", err)
	}
	key := models.IngressKey{
		UserID:  user.ID,
		Type:    parsedKey.Type(),
		Key:     pubKeyStr,
		Comment: comment,
	}
	return db.Create(&key).Error
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
