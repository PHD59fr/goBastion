package sync

import (
	"bufio"
	"fmt"
	"goBastion/utils"
	"goBastion/utils/system"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"goBastion/models"

	"gorm.io/gorm"
)

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

func CreateUsersFromDB(db *gorm.DB, logger slog.Logger) error {
	// Only on fresh install
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
		if err = system.UpdateSudoers(&u); err != nil {
			return fmt.Errorf("error updating sudoers: %w", err)
		}
	}

	return nil
}

func AddSystemUsersFromSystemToDb(db *gorm.DB) error {
	// Only on fresh install
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
