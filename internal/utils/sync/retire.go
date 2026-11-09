package sync

import (
	"context"
	"errors"
	"fmt"
	"os"
	osuser "os/user"
	"path/filepath"
	"syscall"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/recording"
	"golang.org/x/sys/unix"
)

// The caller holds the reconciliation lock. Native accounts/homes are retained
// as UID reservations, while the active DB record is the authorization truth.
func (s *Syncer) retireDeletedUserUnlocked(username string) error {
	if !s.useSecureSSH() || !canonicalAccountName(username) {
		return fmt.Errorf("retirement requires root reconciliation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var history []models.User
	if err := s.db.WithContext(ctx).Unscoped().Where("LOWER(username) = ?", username).Find(&history).Error; err != nil {
		return err
	}
	if len(history) != 1 || history[0].Username != username || !history[0].DeletedAt.Valid || history[0].SystemUser {
		return fmt.Errorf("ambiguous or untracked account retirement requires operator repair")
	}
	// Revoke and clean local session records before retirement. Sessions on
	// other instances cannot be verified or terminated locally.
	var localSessions []models.ActiveSession
	if err := s.db.WithContext(ctx).Where("username = ? AND instance_id = ?", username, config.InstanceID()).Find(&localSessions).Error; err != nil {
		return err
	}
	for _, sess := range localSessions {
		alive := false
		if sess.PID > 0 {
			if err := syscall.Kill(sess.PID, 0); err == nil || errors.Is(err, syscall.EPERM) {
				alive = true
			}
		}
		if alive && s.os != nil {
			// Best-effort: terminate the account's local processes to enforce
			// revocation during retirement. Fall back to record cleanup only if
			// the process is already gone.
			if err := s.os.TerminateUserSessions(username); err != nil {
				return fmt.Errorf("terminate local sessions for retirement: %w", err)
			}
			break
		}
	}
	// Re-check and clean stale local records after termination attempt.
	localSessions = nil
	if err := s.db.WithContext(ctx).Where("username = ? AND instance_id = ?", username, config.InstanceID()).Find(&localSessions).Error; err != nil {
		return err
	}
	for _, sess := range localSessions {
		if sess.PID > 0 {
			if err := syscall.Kill(sess.PID, 0); err == nil || errors.Is(err, syscall.EPERM) {
				continue
			}
		}
		if err := s.db.WithContext(ctx).Where("session_id = ?", sess.SessionID).Delete(&models.ActiveSession{}).Error; err != nil {
			return err
		}
	}
	var active int64
	if err := s.db.WithContext(ctx).Model(&models.ActiveSession{}).Where("username = ?", username).Count(&active).Error; err != nil {
		return err
	}
	if active != 0 {
		return fmt.Errorf("drain and verify registered sessions before retiring account")
	}
	// A sealed namespace alone is insufficient if a stale auditor membership
	// or an unfinished process revocation still needs operator repair.
	if err := s.reconcileAuditors(); err != nil {
		return err
	}
	account, err := s.lookupUser(username)
	if err != nil {
		var unknown osuser.UnknownUserError
		if !errors.As(err, &unknown) {
			return err
		}
		sealed, e := recording.IsRetiredAccount(config.Get().Paths.TtyrecDir, username)
		if e != nil {
			return e
		}
		if sealed {
			return nil
		}
		_, statErr := os.Lstat(filepath.Join(config.Get().Paths.TtyrecDir, username))
		if os.IsNotExist(statErr) {
			return nil
		}
		return fmt.Errorf("recording identity unavailable; offline recovery required")
	}
	if account == nil || account.Username != username {
		return fmt.Errorf("invalid retirement identity")
	}
	// Also revoke processes of non-auditors. Keep a retry marker until verified.
	journal, err := s.openAuditorJournal()
	if err != nil {
		return err
	}
	defer func() { _ = journal.close() }()
	if err = journal.mark(username, account.Uid); err != nil {
		return err
	}
	if err = s.terminateAuditorProcesses(account); err != nil {
		return err
	}
	if err = journal.clear(username, account.Uid); err != nil {
		return err
	}
	retired := history[0]
	retired.Enabled = false
	if s.os.UserHomeExists(username) {
		fd, uid, gid, e := s.secureSSHDir(retired)
		if e != nil {
			return e
		}
		e = publishSSHFile(fd, uid, gid, "authorized_keys", nil)
		_ = unix.Close(fd)
		if e != nil {
			return e
		}
	}
	if err = s.os.UpdateSudoers(&retired); err != nil {
		return err
	}
	recording.Recover(config.Get().Paths.TtyrecDir, &s.log)
	return recording.RetireAccount(config.Get().Paths.TtyrecDir, username)
}

func (s *Syncer) retireDeletedUsers() error {
	if !s.reconcileAuditorAccess {
		return nil
	}
	var retired []models.User
	if err := s.db.Unscoped().Where("deleted_at IS NOT NULL AND system_user = ?", false).Find(&retired).Error; err != nil {
		return err
	}
	for _, u := range retired {
		if err := s.retireDeletedUserUnlocked(u.Username); err != nil {
			return err
		}
	}
	return nil
}
