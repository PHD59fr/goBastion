package sync

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"

	"goBastion/internal/config"
	internaldb "goBastion/internal/db"
	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/utils"
	"goBastion/internal/utils/sshHostKey"
)

// Syncer handles DB → OS synchronisation operations.
type Syncer struct {
	db  *gorm.DB
	os  osadapter.SystemAdapter
	log slog.Logger
}

// New returns a Syncer backed by the given adapter (use osadapter.NewLinuxAdapter() in production).
func New(db *gorm.DB, os osadapter.SystemAdapter, log slog.Logger) *Syncer {
	return &Syncer{db: db, os: os, log: log}
}

// CreateUserFromDB creates the OS system user and writes its authorized_keys from DB.
func (s *Syncer) CreateUserFromDB(user models.User) error {
	if s.os.UserHomeExists(user.Username) {
		return fmt.Errorf("user %s already exists", user.Username)
	}
	if err := s.os.CreateUser(user.Username); err != nil {
		return fmt.Errorf("error creating system user for %s: %w", user.Username, err)
	}
	if err := s.IngressKeyFromDB(user); err != nil {
		return fmt.Errorf("error syncing ingress keys for %s: %w", user.Username, err)
	}
	return nil
}

// CreateUsersFromDB syncs all DB users to the OS, creating missing system accounts.
// Only runs on fresh installation (empty /home).
func (s *Syncer) CreateUsersFromDB() error {
	homeFiles, err := os.ReadDir(config.Get().Paths.HomeBaseDir)
	if err != nil {
		return fmt.Errorf("error reading HOME directory: %w", err)
	}
	if len(homeFiles) > 0 {
		return nil
	}

	var users []models.User
	if err := s.db.Where(internaldb.BoolFalseExpr(s.db, "system_user")).Find(&users).Error; err != nil {
		return fmt.Errorf("error retrieving users: %w", err)
	}
	for _, u := range users {
		s.log.Info("sync_user", slog.String("user", u.Username))
		if err = s.os.CreateUser(u.Username); err != nil {
			return fmt.Errorf("error creating system user for %s: %w", u.Username, err)
		}
		if err = s.IngressKeyFromDB(u); err != nil {
			return fmt.Errorf("error syncing ingress keys for %s: %w", u.Username, err)
		}
		if err = s.KnownHostsFromDB(&u); err != nil {
			return fmt.Errorf("error syncing known_hosts for %s: %w", u.Username, err)
		}
		if err = s.os.UpdateSudoers(&u); err != nil {
			return fmt.Errorf("error updating sudoers: %w", err)
		}
	}
	return nil
}

// CreateSystemUsersFromSystemToDb imports existing OS users into the database.
func (s *Syncer) CreateSystemUsersFromSystemToDb() error {
	var userCount int64
	if err := s.db.Model(&models.User{}).Where(internaldb.BoolTrueExpr(s.db, "system_user")).Count(&userCount).Error; err != nil {
		return fmt.Errorf("error counting users: %w", err)
	}
	if userCount > 0 {
		return nil
	}

	output, err := s.os.ExecCommand("getent", "passwd")
	if err != nil {
		return fmt.Errorf("error listing users: %w, output: %s", err, output)
	}

	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) < 7 {
			continue
		}
		uid, err := strconv.Atoi(parts[2])
		if err != nil || (uid > 1000 && uid < 65000) {
			continue
		}
		user := models.User{
			Username:   parts[0],
			Role:       models.RoleUser,
			Enabled:    false,
			SystemUser: true,
		}
		if err := s.db.Create(&user).Error; err != nil {
			return fmt.Errorf("error adding user %s: %w", parts[0], err)
		}
	}
	return nil
}

// IngressKeyFromDB writes the user's ingress keys to their authorized_keys file.
func (s *Syncer) IngressKeyFromDB(user models.User) error {
	var keys []models.IngressKey
	if err := s.db.Where("user_id = ? AND (expires_at IS NULL OR expires_at > ?)", user.ID, time.Now()).Find(&keys).Error; err != nil {
		return fmt.Errorf("error retrieving keys for %s: %w", user.Username, err)
	}

	sshDir := filepath.Join(config.Get().Paths.HomeBaseDir, utils.NormalizeUsername(user.Username), ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")

	existingKeys := make(map[string]string)
	if file, err := os.Open(authorizedKeysPath); err == nil {
		defer func(f *os.File) { _ = f.Close() }(file)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if parts := strings.Split(line, " #ID:"); len(parts) > 1 {
				existingKeys[parts[0]] = line
			}
		}
	}

	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("error creating .ssh directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(sshDir, "authorized_keys.tmp")
	if err != nil {
		return fmt.Errorf("error creating temp authorized_keys: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err = tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("error setting permissions on temp file: %w", err)
	}

	for _, key := range keys {
		var line string
		if existing, exists := existingKeys[key.Key]; exists {
			line = existing + "\n"
			delete(existingKeys, key.Key)
		} else {
			line = fmt.Sprintf("%s #ID:%s\n", key.Key, key.ID.String())
		}
		if _, err := tmpFile.WriteString(line); err != nil {
			_ = tmpFile.Close()
			return fmt.Errorf("error writing key to temp file: %w", err)
		}
	}

	if err = tmpFile.Close(); err != nil {
		return fmt.Errorf("error closing temp file: %w", err)
	}
	if err = os.Rename(tmpPath, authorizedKeysPath); err != nil {
		return fmt.Errorf("error replacing authorized_keys: %w", err)
	}
	if err = s.os.ChownDir(user, sshDir); err != nil {
		return fmt.Errorf("error changing ownership of %s: %w", sshDir, err)
	}
	return nil
}

// KnownHostsFromDB writes the user's known_hosts entries from the database to disk.
func (s *Syncer) KnownHostsFromDB(user *models.User) error {
	sshDir := filepath.Join(config.Get().Paths.HomeBaseDir, utils.NormalizeUsername(user.Username), ".ssh")
	knownHostsPath := filepath.Join(sshDir, "known_hosts")

	var entries []models.KnownHostsEntry
	if err := s.db.Where("user_id = ?", user.ID).Find(&entries).Error; err != nil {
		return fmt.Errorf("failed to retrieve known_hosts entries from DB: %w", err)
	}

	if len(entries) == 0 {
		if err := os.Remove(knownHostsPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove known_hosts file: %w", err)
		}
		return nil
	}

	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create SSH directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(sshDir, "known_hosts.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp known_hosts: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() { _ = os.Remove(tmpPath) }()

	if err = tmpFile.Chmod(0600); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to set permissions on temp known_hosts: %w", err)
	}
	for _, entry := range entries {
		if _, err := fmt.Fprintln(tmpFile, entry.Entry); err != nil {
			_ = tmpFile.Close()
			return fmt.Errorf("failed to write known_hosts entry: %w", err)
		}
	}
	if err = tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp known_hosts: %w", err)
	}
	if err = os.Rename(tmpPath, knownHostsPath); err != nil {
		return fmt.Errorf("failed to replace known_hosts: %w", err)
	}
	return nil
}

// KnownHostsEntriesFromSystemToDb imports known_hosts file entries into the database.
func (s *Syncer) KnownHostsEntriesFromSystemToDb(user *models.User) error {
	sshDir := filepath.Join(config.Get().Paths.HomeBaseDir, utils.NormalizeUsername(user.Username), ".ssh")
	knownHostsPath := filepath.Join(sshDir, "known_hosts")

	file, err := os.Open(knownHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return s.db.Where("user_id = ?", user.ID).Delete(&models.KnownHostsEntry{}).Error
		}
		return fmt.Errorf("failed to open known_hosts: %w", err)
	}
	defer func(f *os.File) { _ = f.Close() }(file)

	existingEntries := make(map[string]bool)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if line := scanner.Text(); line != "" {
			existingEntries[line] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading known_hosts file: %w", err)
	}

	var dbEntries []models.KnownHostsEntry
	if err := s.db.Where("user_id = ?", user.ID).Find(&dbEntries).Error; err != nil {
		return fmt.Errorf("failed to fetch known_hosts entries from DB: %w", err)
	}

	dbEntriesMap := make(map[string]uuid.UUID)
	for _, entry := range dbEntries {
		dbEntriesMap[entry.Entry] = entry.ID
	}

	var toInsert []models.KnownHostsEntry
	for entry := range existingEntries {
		if _, exists := dbEntriesMap[entry]; !exists {
			toInsert = append(toInsert, models.KnownHostsEntry{
				ID:        uuid.New(),
				UserID:    user.ID,
				Entry:     entry,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			})
		}
	}

	var toDelete []uuid.UUID
	for entry, id := range dbEntriesMap {
		if _, exists := existingEntries[entry]; !exists {
			toDelete = append(toDelete, id)
		}
	}

	if len(toInsert) > 0 {
		if err := s.db.Create(&toInsert).Error; err != nil {
			return fmt.Errorf("failed to insert known_hosts entries: %w", err)
		}
	}
	if len(toDelete) > 0 {
		if err := s.db.Where("id IN (?)", toDelete).Delete(&models.KnownHostsEntry{}).Error; err != nil {
			return fmt.Errorf("failed to delete old known_hosts entries: %w", err)
		}
	}
	return nil
}

// RestoreBastionSSHHostKeys restores SSH host keys from DB and regenerates sshd host key files.
func (s *Syncer) RestoreBastionSSHHostKeys() error {
	if err := sshHostKey.RestoreSSHHostKeys(s.db); err != nil {
		return err
	}
	return sshHostKey.GenerateSSHHostKeys(s.db, false)
}

// EnforceFromDB is the authoritative DB → OS sync.
func (s *Syncer) EnforceFromDB() error {
	s.log.Info("sync_start")

	// Reload config from DB to pick up admin changes.
	config.Reload(s.db)

	if err := s.RestoreBastionSSHHostKeys(); err != nil {
		s.log.Error("sync_ssh_host_keys_failed", slog.Any("error", err))
	}

	if err := s.disableInactiveUsers(); err != nil {
		s.log.Error("sync_disable_inactive_failed", slog.Any("error", err))
	}

	var dbUsers []models.User
	if err := s.db.Where(internaldb.BoolFalseExpr(s.db, "system_user")).Find(&dbUsers).Error; err != nil {
		return fmt.Errorf("[sync] error querying DB users: %w", err)
	}

	dbUsernames := make(map[string]bool)
	for _, u := range dbUsers {
		dbUsernames[utils.NormalizeUsername(u.Username)] = true
	}

	for _, u := range dbUsers {
		if !s.os.UserHomeExists(u.Username) {
			s.log.Warn("sync_os_user_missing", slog.String("user", u.Username))
			if err := s.os.CreateUser(u.Username); err != nil {
				s.log.Error("sync_os_user_create_failed", slog.String("user", u.Username), slog.Any("error", err))
				continue
			}
		}
		if err := s.IngressKeyFromDB(u); err != nil {
			s.log.Error("sync_authorized_keys_failed", slog.String("user", u.Username), slog.Any("error", err))
		}
		if err := s.KnownHostsFromDB(&u); err != nil {
			s.log.Error("sync_known_hosts_failed", slog.String("user", u.Username), slog.Any("error", err))
		}
		if err := s.os.UpdateSudoers(&u); err != nil {
			s.log.Error("sync_sudoers_failed", slog.String("user", u.Username), slog.Any("error", err))
		}
	}

	homeEntries, err := os.ReadDir(config.Get().Paths.HomeBaseDir)
	if err != nil {
		return fmt.Errorf("[sync] error reading %s: %w", config.Get().Paths.HomeBaseDir, err)
	}
	for _, entry := range homeEntries {
		if !entry.IsDir() {
			continue
		}
		osUser := entry.Name()
		if dbUsernames[osUser] {
			continue
		}
		// Use "--" to prevent osUser from being interpreted as a flag.
		out, pErr := exec.Command("pgrep", "-u", "--", osUser).Output()
		if pErr == nil && len(strings.TrimSpace(string(out))) > 0 {
			s.log.Warn("sync_rogue_user_session_active", slog.String("user", osUser))
			continue
		}
		s.log.Warn("sync_rogue_user_removing", slog.String("user", osUser))
		if err := s.os.DeleteUser(osUser); err != nil {
			s.log.Error("sync_rogue_user_remove_failed", slog.String("user", osUser), slog.Any("error", err))
		}
	}

	s.log.Info("sync_complete")
	return nil
}

// disableInactiveUsers disables accounts that haven't logged in within the
// configured MaxInactiveDays window. Accounts that have never logged in
// (zero LastLoginAt) are excluded.
func (s *Syncer) disableInactiveUsers() error {
	maxDays := config.Get().Account.MaxInactiveDays
	if maxDays <= 0 {
		return nil
	}

	cutoff := time.Now().AddDate(0, 0, -maxDays)
	result := s.db.Model(&models.User{}).
		Where(internaldb.BoolFalseExpr(s.db, "system_user")).
		Where("enabled = ?", true).
		Where("last_login_at != ?", time.Time{}).
		Where("last_login_at < ?", cutoff).
		Where("deleted_at IS NULL").
		Update("enabled", false)
	if result.Error != nil {
		return fmt.Errorf("error disabling inactive users: %w", result.Error)
	}
	if result.RowsAffected > 0 {
		s.log.Warn("sync_disabled_inactive_users",
			slog.Int64("count", result.RowsAffected),
			slog.Int("max_inactive_days", maxDays),
		)
	}
	return nil
}
