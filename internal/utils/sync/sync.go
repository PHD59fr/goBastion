package sync

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"goBastion/internal/telemetry"
	"log/slog"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/sys/unix"
	"gorm.io/gorm"

	"goBastion/internal/config"
	internaldb "goBastion/internal/db"
	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/reconcilelock"
	"goBastion/internal/recording"
	"goBastion/internal/utils"
	"goBastion/internal/utils/sshHostKey"
	"goBastion/internal/utils/sshkey"
	"goBastion/internal/utils/validation"
)

// Syncer handles DB → OS synchronisation operations.
type Syncer struct {
	db                     *gorm.DB
	os                     osadapter.SystemAdapter
	log                    slog.Logger
	acquireLock            func(context.Context) (func() error, error)
	lookupUser             func(string) (*osuser.User, error)
	lookupUID              func(string) (*osuser.User, error)
	openAuditorJournal     func() (*auditorJournal, error)
	provisionRecording     func(string, string) error
	reconcileAuditorAccess bool
}

// New returns a Syncer backed by the given adapter (use osadapter.NewLinuxAdapter() in production).
func New(db *gorm.DB, adapter osadapter.SystemAdapter, log slog.Logger) *Syncer {
	s := &Syncer{db: db, os: adapter, log: log, acquireLock: reconcilelock.Acquire, lookupUser: osuser.Lookup, lookupUID: osuser.LookupId, openAuditorJournal: openAuditorJournal}
	if _, ok := adapter.(*osadapter.LinuxAdapter); ok && os.Geteuid() == 0 {
		s.provisionRecording = recording.ProvisionAccount
		s.reconcileAuditorAccess = true
	}
	return s
}

// CreateUserFromDB creates the OS system user and writes its authorized_keys from DB.
func (s *Syncer) CreateUserFromDB(user models.User) error {
	if os.Geteuid() != 0 {
		if _, ok := s.os.(*osadapter.LinuxAdapter); ok {
			out, err := s.os.ExecCommand("/usr/bin/sudo", "-n", "/usr/local/sbin/gobastion-sync-user", user.Username)
			if err != nil {
				return fmt.Errorf("privileged user sync failed: %w, output: %s", err, out)
			}
			return nil
		}
	}
	if os.Geteuid() == 0 {
		return s.SyncUserByName(user.Username)
	}
	return s.createUserFromDBUnlocked(user)
}

// createUserFromDBUnlocked applies a previously validated snapshot. Root callers
// must hold the reconciliation lock for the snapshot and this entire operation.
func (s *Syncer) createUserFromDBUnlocked(user models.User) error {
	if !s.os.UserHomeExists(user.Username) {
		if err := s.os.CreateUser(user.Username); err != nil {
			return fmt.Errorf("error creating system user for %s: %w", user.Username, err)
		}
	}
	if !user.Enabled && s.reconcileAuditorAccess {
		// Reject ambiguous NSS identities before sending signals by numeric UID.
		if e := s.reconcileAuditors(); e != nil {
			return e
		}
		account, e := s.lookupUser(user.Username)
		if e != nil {
			return e
		}
		if e = s.terminateAuditorProcesses(account); e != nil {
			return e
		}
	}
	if err := s.prepareRecordingAccess(user); err != nil {
		return err
	}
	if err := s.IngressKeyFromDB(user); err != nil {
		return fmt.Errorf("error syncing ingress keys for %s: %w", user.Username, err)
	}
	if err := s.KnownHostsFromDB(&user); err != nil {
		return fmt.Errorf("error syncing known_hosts for %s: %w", user.Username, err)
	}
	if err := s.os.UpdateSudoers(&user); err != nil {
		return fmt.Errorf("error updating sudoers for %s: %w", user.Username, err)
	}
	return nil
}

// SyncUserByName snapshots and applies a single user under the node-local lock.
// It is intended for the root-owned privileged helper.
func (s *Syncer) SyncUserByName(username string) (resultErr error) {
	if username != strings.ToLower(username) || !validation.IsValidManagedUsername(username) {
		return fmt.Errorf("invalid or reserved username")
	}
	ctx, cancel := context.WithTimeout(context.Background(), reconcilelock.Timeout)
	defer cancel()
	release, err := s.acquireLock(ctx)
	if err != nil {
		return fmt.Errorf("lock reconciliation: %w", err)
	}
	defer func() {
		if err := release(); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("release reconciliation lock: %w", err))
		}
	}()
	var user models.User
	if err := s.db.Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) && s.reconcileAuditorAccess {
			return s.retireDeletedUserUnlocked(username)
		}
		return fmt.Errorf("user %q not found: %w", username, err)
	}
	var retiredNames int64
	if err := s.db.Unscoped().Model(&models.User{}).Where("LOWER(username) = ? AND deleted_at IS NOT NULL", username).Count(&retiredNames).Error; err != nil {
		return err
	}
	if retiredNames != 0 {
		return fmt.Errorf("retired login name cannot be reused")
	}

	if user.SystemUser {
		return fmt.Errorf("refusing to manage system account %q", username)
	}
	account, err := s.lookupUser(username)
	if err != nil {
		var unknown osuser.UnknownUserError
		if !errors.As(err, &unknown) {
			return fmt.Errorf("lookup OS user %q: %w", username, err)
		}
	} else {
		uid, err := strconv.ParseUint(account.Uid, 10, 32)
		if err != nil || uid < 1000 || uid >= 65000 {
			return fmt.Errorf("refusing to manage system account %q", username)
		}
	}
	return s.createUserFromDBUnlocked(user)
}

// CreateUsersFromDB syncs all DB users to the OS, creating missing system accounts.
// Only runs on fresh installation (empty /home).
func (s *Syncer) CreateUsersFromDB() (resultErr error) {
	if os.Geteuid() == 0 {
		ctx, cancel := context.WithTimeout(context.Background(), reconcilelock.Timeout)
		defer cancel()
		release, err := s.acquireLock(ctx)
		if err != nil {
			return fmt.Errorf("lock reconciliation: %w", err)
		}
		defer func() {
			if err := release(); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("release reconciliation lock: %w", err))
			}
		}()
	}
	if err := s.reconcileAuditors(); err != nil {
		return err
	}
	homeFiles, err := os.ReadDir(config.Get().Paths.HomeBaseDir)
	if err != nil {
		return fmt.Errorf("error reading HOME directory: %w", err)
	}
	if len(homeFiles) > 0 {
		s.log.Info("skip_initial_user_sync", slog.String("reason", "home directory is not empty"), slog.String("path", config.Get().Paths.HomeBaseDir), slog.Int("entries", len(homeFiles)))
		return nil
	}

	var users []models.User
	if err := s.db.Where(internaldb.BoolFalseExpr(s.db, "system_user")).Find(&users).Error; err != nil {
		return fmt.Errorf("error retrieving users: %w", err)
	}
	for _, u := range users {
		s.log.Info("sync_user", slog.String("user", u.Username))
		if err := s.createUserFromDBUnlocked(u); err != nil {
			return err
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
	if os.Geteuid() != 0 {
		if _, ok := s.os.(*osadapter.LinuxAdapter); ok {
			out, err := s.os.ExecCommand("/usr/bin/sudo", "-n", "/usr/local/sbin/gobastion-sync-user", user.Username)
			if err != nil {
				return fmt.Errorf("privileged ingress-key sync failed: %w, output: %s", err, out)
			}
			return nil
		}
	}
	var keys []models.IngressKey
	if user.Enabled {
		if err := s.db.Where("user_id = ? AND (expires_at IS NULL OR expires_at > ?)", user.ID, time.Now()).Find(&keys).Error; err != nil {
			return fmt.Errorf("error retrieving keys for %s: %w", user.Username, err)
		}
	}

	if s.useSecureSSH() {
		var content bytes.Buffer
		for _, key := range keys {
			canonical, discarded, err := sshkey.CanonicalIngressKey(key.Key, key.PIVAttested)
			if err != nil {
				s.log.Error("ingress_key_rejected", "user", user.Username, "key_id", key.ID, "error", err)
				continue
			}
			if discarded {
				s.log.Warn("ingress_key_extra_data_ignored", "user", user.Username, "key_id", key.ID)
			}
			fmt.Fprintf(&content, "%s #ID:%s\n", canonical, key.ID.String())
		}
		dir, uid, gid, err := s.secureSSHDir(user)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(dir) }()
		if err := publishSSHFile(dir, uid, gid, "authorized_keys", content.Bytes()); err != nil {
			return fmt.Errorf("publish authorized_keys: %w", err)
		}
		return nil
	}

	sshDir := filepath.Join(config.Get().Paths.HomeBaseDir, utils.NormalizeUsername(user.Username), ".ssh")
	authorizedKeysPath := filepath.Join(sshDir, "authorized_keys")

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
		canonical, discarded, err := sshkey.CanonicalIngressKey(key.Key, key.PIVAttested)
		if err != nil {
			s.log.Error("ingress_key_rejected", "user", user.Username, "key_id", key.ID, "error", err)
			continue
		}
		if discarded {
			s.log.Warn("ingress_key_extra_data_ignored", "user", user.Username, "key_id", key.ID)
		}
		line := fmt.Sprintf("%s #ID:%s\n", canonical, key.ID.String())
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
// Root publication uses held descriptors; unprivileged sessions update their
// own directory. Preserve the canonical local name without identity rewriting.
func (s *Syncer) KnownHostsFromDB(user *models.User) error {
	if user == nil || !validation.IsValidManagedUsername(user.Username) {
		return fmt.Errorf("invalid managed known_hosts identity")
	}
	sshDir := filepath.Join(config.Get().Paths.HomeBaseDir, user.Username, ".ssh")
	knownHostsPath := filepath.Join(sshDir, "known_hosts")

	var entries []models.KnownHostsEntry
	if err := s.db.Where("user_id = ?", user.ID).Find(&entries).Error; err != nil {
		return fmt.Errorf("failed to retrieve known_hosts entries from DB: %w", err)
	}

	if s.useSecureSSH() {
		dir, uid, gid, err := s.secureSSHDir(*user)
		if err != nil {
			return err
		}
		defer func() { _ = unix.Close(dir) }()
		if len(entries) == 0 {
			if err := unix.Unlinkat(dir, "known_hosts", 0); err != nil && err != unix.ENOENT {
				return fmt.Errorf("remove known_hosts: %w", err)
			}
			return unix.Fsync(dir)
		}
		var content bytes.Buffer
		for _, entry := range entries {
			fmt.Fprintln(&content, entry.Entry)
		}
		if err := publishSSHFile(dir, uid, gid, "known_hosts", content.Bytes()); err != nil {
			return fmt.Errorf("publish known_hosts: %w", err)
		}
		return nil
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
	if os.Geteuid() == 0 {
		if err = s.os.ChownDir(*user, sshDir); err != nil {
			return fmt.Errorf("error changing ownership of %s: %w", sshDir, err)
		}
	}
	return nil
}

// KnownHostsEntriesFromSystemToDb imports known_hosts file entries into the database.
func (s *Syncer) KnownHostsEntriesFromSystemToDb(user *models.User) error {
	if user == nil || !validation.IsValidManagedUsername(user.Username) {
		return fmt.Errorf("invalid managed known_hosts identity")
	}
	sshDir := filepath.Join(config.Get().Paths.HomeBaseDir, user.Username, ".ssh")
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
func (s *Syncer) EnforceFromDB() (resultErr error) {
	ctx, span := telemetry.Start(context.Background(), "sync.reconcile", telemetry.Component("sync"))
	defer func() {
		if resultErr != nil {
			span.Failure()
		} else {
			span.Success()
		}
		span.End()
	}()

	started := time.Now()
	defer func() {
		s.log.InfoContext(ctx, "sync_result", slog.Duration("duration", time.Since(started)), slog.Bool("success", resultErr == nil))
	}()
	if os.Geteuid() == 0 {
		lockCtx, cancel := context.WithTimeout(context.Background(), reconcilelock.Timeout)
		defer cancel()
		release, err := s.acquireLock(lockCtx)
		if err != nil {
			return fmt.Errorf("lock reconciliation: %w", err)
		}
		defer func() {
			if err := release(); err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("release reconciliation lock: %w", err))
			}
		}()
	}
	var failures []error
	s.log.Info("sync_start")

	// Reload config from DB to pick up admin changes.
	config.Reload(s.db)

	if err := s.RestoreBastionSSHHostKeys(); err != nil {
		s.log.Error("sync_ssh_host_keys_failed", slog.Any("error", err))
		failures = append(failures, fmt.Errorf("sync_ssh_host_keys_failed: %w", err))
	}

	if err := s.disableInactiveUsers(); err != nil {
		s.log.Error("sync_disable_inactive_failed", slog.Any("error", err))
		failures = append(failures, fmt.Errorf("sync_disable_inactive_failed: %w", err))
	}

	var dbUsers []models.User
	if err := s.db.Where(internaldb.BoolFalseExpr(s.db, "system_user")).Find(&dbUsers).Error; err != nil {
		return errors.Join(append(failures, fmt.Errorf("[sync] error querying DB users: %w", err))...)
	}
	// Remove stale auditor memberships before publishing any account access,
	// including when the database no longer contains any managed accounts.
	if err := s.reconcileAuditors(); err != nil {
		return errors.Join(append(failures, err)...)
	}

	dbUsernames := make(map[string]bool)
	for _, u := range dbUsers {
		dbUsernames[u.Username] = true
	}

	for _, u := range dbUsers {
		if !s.os.UserHomeExists(u.Username) {
			s.log.Warn("sync_os_user_missing", slog.String("user", u.Username))
			if err := s.os.CreateUser(u.Username); err != nil {
				s.log.Error("sync_os_user_create_failed", slog.String("user", u.Username), slog.Any("error", err))
				failures = append(failures, fmt.Errorf("sync_os_user_create_failed: %w", err))
				continue
			}
		}
		if !u.Enabled {
			if err := s.os.TerminateUserSessions(u.Username); err != nil {
				s.log.Error("sync_session_revocation_failed", slog.String("user", u.Username), slog.Any("error", err))
				failures = append(failures, fmt.Errorf("sync_session_revocation_failed: %w", err))
			}
		}
		if err := s.prepareRecordingAccess(u); err != nil {
			s.log.Error("sync_recording_access_failed", slog.String("user", u.Username), slog.Any("error", err))
			failures = append(failures, err)
			continue
		}
		homeDir := filepath.Join(config.Get().Paths.HomeBaseDir, utils.NormalizeUsername(u.Username))
		if hErr := func() error {
			if s.useSecureSSH() {
				return nil
			}
			return s.os.ChownDir(u, homeDir)
		}(); hErr != nil {
			s.log.Warn("sync_chown_home_failed", slog.String("user", u.Username), slog.Any("error", hErr))
			failures = append(failures, fmt.Errorf("sync_chown_home_failed: %w", hErr))
		}
		if err := s.IngressKeyFromDB(u); err != nil {
			s.log.Error("sync_authorized_keys_failed", slog.String("user", u.Username), slog.Any("error", err))
			failures = append(failures, fmt.Errorf("sync_authorized_keys_failed: %w", err))
		}
		if err := s.KnownHostsFromDB(&u); err != nil {
			s.log.Error("sync_known_hosts_failed", slog.String("user", u.Username), slog.Any("error", err))
			failures = append(failures, fmt.Errorf("sync_known_hosts_failed: %w", err))
		}
		if err := s.os.UpdateSudoers(&u); err != nil {
			s.log.Error("sync_sudoers_failed", slog.String("user", u.Username), slog.Any("error", err))
			failures = append(failures, fmt.Errorf("sync_sudoers_failed: %w", err))
		}

	}

	if err := s.retireDeletedUsers(); err != nil {
		return errors.Join(append(failures, err)...)
	}
	homeEntries, err := os.ReadDir(config.Get().Paths.HomeBaseDir)
	if err != nil {
		return errors.Join(append(failures, fmt.Errorf("[sync] error reading home directory: %w", err))...)
	}
	for _, entry := range homeEntries {
		if !entry.IsDir() {
			continue
		}
		osUser := entry.Name()

		if dbUsernames[osUser] {
			continue
		}
		if !validation.IsValidUsername(osUser) {
			continue
		}
		if s.reconcileAuditorAccess {
			// Never recycle an untracked UID or recurse into the root helper while
			// this process already holds the reconciliation lock.
			if !dbUsernames[osUser] {
				var tombstones int64
				if err := s.db.Unscoped().Model(&models.User{}).Where("LOWER(username) = ? AND deleted_at IS NOT NULL", osUser).Count(&tombstones).Error; err != nil {
					return err
				}
				if tombstones != 1 {
					return fmt.Errorf("untracked local account requires operator repair")
				}
				continue
			}
		}
		active, pErr := s.userHasProcesses(osUser)
		if pErr != nil {
			// Fail closed: if we cannot confirm the user has no active sessions,
			// do NOT remove the account or its home directory.
			s.log.Warn("sync_rogue_user_pgrep_failed", slog.String("user", osUser), slog.Any("error", pErr))
			failures = append(failures, fmt.Errorf("sync_rogue_user_pgrep_failed: %w", pErr))
			continue
		}
		if active {
			s.log.Warn("sync_rogue_user_session_active", slog.String("user", osUser))
			continue
		}
		s.log.Warn("sync_rogue_user_removing", slog.String("user", osUser))
		if err := s.os.DeleteUser(osUser); err != nil {
			s.log.Error("sync_rogue_user_remove_failed", slog.String("user", osUser), slog.Any("error", err))
			failures = append(failures, fmt.Errorf("sync_rogue_user_remove_failed: %w", err))
		}
	}

	if len(failures) > 0 {
		return errors.Join(failures...)
	}
	s.log.Info("sync_complete")
	return nil
}

func (s *Syncer) userHasProcesses(username string) (bool, error) {
	out, err := s.os.ExecCommand("pgrep", "-u", username)
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return false, nil // pgrep: no matching processes (also on BusyBox).
		}
		return false, err
	}
	return strings.TrimSpace(out) != "", nil
}

// disableInactiveUsers disables accounts that haven't logged in within the
// configured MaxInactiveDays window. Accounts that have never logged in
// (zero LastLoginAt) are excluded.
func (s *Syncer) disableInactiveUsers() error {
	maxDays := config.Get().Account.MaxInactiveDays
	if maxDays <= 0 {
		return nil
	}

	return models.WithAccountChange(s.db, func(tx *gorm.DB) error {
		cutoff := time.Now().AddDate(0, 0, -maxDays)
		var candidates []models.User
		if err := tx.Where(map[string]any{"system_user": false, "enabled": true}).Where("last_login_at < ? AND last_login_at != ?", cutoff, time.Time{}).Order("last_login_at ASC").Order("id ASC").Find(&candidates).Error; err != nil {
			return err
		}
		for _, u := range candidates {
			if err := models.RequireOtherAdmin(tx, &u); err != nil {
				if errors.Is(err, models.ErrLastAdmin) {
					s.log.Warn("sync_preserved_last_admin", "user", u.Username)
					continue
				}
				return err
			}
			if err := tx.Model(&u).Update("enabled", false).Error; err != nil {
				return err
			}
		}
		return nil
	})
}
