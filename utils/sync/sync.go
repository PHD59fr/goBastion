package sync

import (
	"bufio"
	"fmt"
	"goBastion/models"
	"goBastion/utils"
	"goBastion/utils/sshHostKey"
	"goBastion/utils/system"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// CreateUserFromDB creates the OS system user and writes its authorized_keys from DB.
func CreateUserFromDB(db *gorm.DB, user models.User) error {
	userDir := filepath.Join("/home", utils.NormalizeUsername(user.Username))
	_, err := os.Stat(userDir)
	if os.IsNotExist(err) {
		if err = system.CreateUser(user.Username); err != nil {
			return fmt.Errorf("error creating system user for %s: %w", user.Username, err)
		}

		if err = IngressKeyFromDB(db, user); err != nil {
			return fmt.Errorf("error syncing ingress keys for %s: %w", user.Username, err)
		}

	} else {
		return fmt.Errorf("user %s already exists", user.Username)
	}
	return nil
}

// CreateUsersFromDB syncs all DB users to the OS, creating missing system accounts.
func CreateUsersFromDB(db *gorm.DB, logger slog.Logger) error {
	// Only on fresh installation
	homeFiles, err := os.ReadDir("/home")
	if err != nil {
		return fmt.Errorf("error reading HOME directory: %w", err)
	}
	if len(homeFiles) > 0 {
		return nil
	}

	var users []models.User
	if err := db.Where("system_user = ?", false).Find(&users).Error; err != nil {
		return fmt.Errorf("error retrieving users: %w", err)
	}

	if len(users) == 0 {
		return nil
	}

	for _, u := range users {
		logger.Info("Syncing user " + u.Username)
		if err = system.CreateUser(u.Username); err != nil {
			return fmt.Errorf("error creating system user for %s: %w", u.Username, err)
		}
		if err = IngressKeyFromDB(db, u); err != nil {
			return fmt.Errorf("error syncing ingress keys for %s: %w", u.Username, err)
		}

		if err = KnownHostsFromDB(db, &u); err != nil {
			return fmt.Errorf("error syncing known_hosts for %s: %w", u.Username, err)
		}

		if err = system.UpdateSudoers(&u); err != nil {
			return fmt.Errorf("error updating sudoers: %w", err)
		}
	}

	return nil
}

// CreateSystemUsersFromSystemToDb imports existing OS users into the database.
func CreateSystemUsersFromSystemToDb(db *gorm.DB) error {
	// Only on fresh installation
	var userCount int64
	if err := db.Model(&models.User{}).Where("system_user = ?", true).Count(&userCount).Error; err != nil {
		return fmt.Errorf("error counting users: %w", err)
	}
	if userCount > 0 {
		return nil
	}

	output, err := system.ExecCommand("getent", "passwd")
	if err != nil {
		return fmt.Errorf("error listing users: %w, output: %s", err, output)
	}

	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		username := parts[0]
		uid, err := strconv.Atoi(parts[2])
		if err != nil || uid > 1000 && uid < 65000 {
			continue
		}

		user := models.User{
			Username:   username,
			Role:       models.RoleUser,
			Enabled:    false,
			SystemUser: true,
		}
		if err := db.Create(&user).Error; err != nil {
			return fmt.Errorf("error adding user %s: %w", username, err)
		}
	}
	return nil
}

// IngressKeyFromDB writes the user's ingress keys to their authorized_keys file.
func IngressKeyFromDB(db *gorm.DB, user models.User) error {
	var keys []models.IngressKey
	if err := db.Where("user_id = ?", user.ID).Find(&keys).Error; err != nil {
		return fmt.Errorf("error retrieving keys for %s: %w", user.Username, err)
	}

	sshDir := filepath.Join("/home", utils.NormalizeUsername(user.Username), ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")

	existingKeys := make(map[string]string)
	if file, err := os.Open(authorizedKeysPath); err == nil {
		defer func(file *os.File) {
			_ = file.Close()
		}(file)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			keyParts := strings.Split(line, " #ID:")
			if len(keyParts) > 0 {
				existingKeys[keyParts[0]] = line
			}
		}
	}

	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("error creating .ssh directory: %w", err)
	}

	file, err := os.OpenFile(authorizedKeysPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("error opening authorized_keys file: %w", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	for _, key := range keys {
		keyEntry := key.Key
		if _, exists := existingKeys[keyEntry]; !exists {
			newKeyLine := fmt.Sprintf("%s #ID:%s\n", keyEntry, key.ID.String())
			if _, err := file.WriteString(newKeyLine); err != nil {
				return fmt.Errorf("error writing key to authorized_keys: %w", err)
			}
		} else {
			if _, err := file.WriteString(existingKeys[keyEntry] + "\n"); err != nil {
				return fmt.Errorf("error writing existing key to authorized_keys: %w", err)
			}
			delete(existingKeys, keyEntry)
		}
	}
	if err = system.ChownDir(user, sshDir); err != nil {
		return fmt.Errorf("error changing ownership of %s: %w", sshDir, err)
	}
	return nil
}

// KnownHostsFromDB writes the user's known_hosts entries from the database to disk.
func KnownHostsFromDB(db *gorm.DB, user *models.User) error {
	sshDir := filepath.Join("/home", utils.NormalizeUsername(user.Username), ".ssh")
	knownHostsPath := filepath.Join(sshDir, "known_hosts")

	var entries []models.KnownHostsEntry
	if err := db.Where("user_id = ?", user.ID).Find(&entries).Error; err != nil {
		return fmt.Errorf("failed to retrieve known_hosts entries from DB: %v", err)
	}

	if len(entries) == 0 {
		if err := os.Remove(knownHostsPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove known_hosts file: %v", err)
		}
		return nil
	}

	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create SSH directory: %v", err)
	}

	var lines []string
	for _, entry := range entries {
		lines = append(lines, entry.Entry)
	}
	knownHostsContent := strings.Join(lines, "\n") + "\n"

	if err := os.WriteFile(knownHostsPath, []byte(knownHostsContent), 0600); err != nil {
		return fmt.Errorf("failed to write known_hosts file: %v", err)
	}
	return nil
}

// KnownHostsEntriesFromSystemToDb imports known_hosts file entries into the database.
func KnownHostsEntriesFromSystemToDb(db *gorm.DB, user *models.User) error {

	sshDir := filepath.Join("/home", utils.NormalizeUsername(user.Username), ".ssh")
	knownHostsPath := filepath.Join(sshDir, "known_hosts")

	file, err := os.Open(knownHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return db.Where("user_id = ?", user.ID).Delete(&models.KnownHostsEntry{}).Error
		}
		return fmt.Errorf("failed to open known_hosts: %v", err)
	}
	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	existingEntries := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		existingEntries[line] = true
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading known_hosts file: %v", err)
	}

	var dbEntries []models.KnownHostsEntry
	if err := db.Where("user_id = ?", user.ID).Find(&dbEntries).Error; err != nil {
		return fmt.Errorf("failed to fetch known_hosts entries from DB: %v", err)
	}

	var entriesToInsert []models.KnownHostsEntry
	dbEntriesMap := make(map[string]uuid.UUID)

	for _, entry := range dbEntries {
		dbEntriesMap[entry.Entry] = entry.ID
	}

	for entry := range existingEntries {
		if _, exists := dbEntriesMap[entry]; !exists {
			entriesToInsert = append(entriesToInsert, models.KnownHostsEntry{
				ID:        uuid.New(),
				UserID:    user.ID,
				Entry:     entry,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			})
		}
	}

	var entriesToDelete []uuid.UUID
	for entry, id := range dbEntriesMap {
		if _, exists := existingEntries[entry]; !exists {
			entriesToDelete = append(entriesToDelete, id)
		}
	}

	if len(entriesToInsert) > 0 {
		if err := db.Create(&entriesToInsert).Error; err != nil {
			return fmt.Errorf("failed to insert known_hosts entries: %v", err)
		}
	}

	if len(entriesToDelete) > 0 {
		if err := db.Where("id IN (?)", entriesToDelete).Delete(&models.KnownHostsEntry{}).Error; err != nil {
			return fmt.Errorf("failed to delete old known_hosts entries: %v", err)
		}
	}

	return nil
}

// RestoreBastionSSHHostKeys restores SSH host keys from DB and regenerates sshd host key files.
func RestoreBastionSSHHostKeys(db *gorm.DB) error {
	if err := sshHostKey.RestoreSSHHostKeys(db); err != nil {
		return err
	}

	if err := sshHostKey.GenerateSSHHostKeys(db, false); err != nil {
		return err
	}
	return nil
}
