package session

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"gorm.io/gorm"
)

func registerActiveSession(db *gorm.DB, currentUser *models.User, sessionID, kind string) (func(), error) {
	instanceID := config.InstanceID()
	limit := config.Get().Session.MaxConcurrentSessions
	identity, err := processIdentity(os.Getpid())
	if err != nil {
		return nil, fmt.Errorf("identify active session process: %w", err)
	}
	record := models.ActiveSession{
		SessionID:       sessionID,
		InstanceID:      instanceID,
		Username:        currentUser.Username,
		PID:             os.Getpid(),
		ProcessIdentity: identity,
		Kind:            kind,
	}

	if err := db.Transaction(func(tx *gorm.DB) error {
		if err := cleanupStaleActiveSessions(tx, instanceID); err != nil {
			return err
		}

		if limit > 0 {
			var activeCount int64
			if err := tx.Model(&models.ActiveSession{}).
				Where("instance_id = ?", instanceID).
				Count(&activeCount).Error; err != nil {
				return err
			}
			if activeCount >= int64(limit) {
				return fmt.Errorf("maximum concurrent sessions reached on instance %s", instanceID)
			}
		}

		return tx.Create(&record).Error
	}, &sql.TxOptions{Isolation: sql.LevelSerializable}); err != nil {
		return nil, err
	}

	return func() {
		_ = db.Where("session_id = ?", sessionID).Delete(&models.ActiveSession{}).Error
	}, nil
}

func cleanupStaleActiveSessions(db *gorm.DB, instanceID string) error {
	var sessions []models.ActiveSession
	if err := db.Where("instance_id = ?", instanceID).Find(&sessions).Error; err != nil {
		return err
	}
	for _, session := range sessions {
		if activeSessionProcessAlive(session) {
			continue
		}
		if err := db.Where("session_id = ?", session.SessionID).Delete(&models.ActiveSession{}).Error; err != nil {
			return err
		}
	}
	return nil
}

func activeSessionProcessAlive(session models.ActiveSession) bool {
	if !processAlive(session.PID) {
		return false
	}
	// Upgrades cannot infer the original process identity for an existing row.
	// Keep a live legacy PID rather than dropping a potentially active session.
	if session.ProcessIdentity == "" {
		return true
	}
	identity, err := processIdentity(session.PID)
	// A procfs restriction must not cause an active session to disappear from
	// admission accounting. The process may also have exited during the read.
	if err != nil {
		return processAlive(session.PID)
	}
	return identity == session.ProcessIdentity
}

// processIdentity uses the kernel start counter, boot ID and current PID
// namespace. A recycled PID, host reboot or container PID namespace change
// therefore cannot make a new process inherit an old session registration.
func processIdentity(pid int) (string, error) {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return "", err
	}
	start, err := processStartCounter(string(stat))
	if err != nil {
		return "", err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", err
	}
	namespace, err := os.Readlink("/proc/self/ns/pid")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(string(boot)) == "" || namespace == "" {
		return "", errors.New("missing kernel process identity")
	}
	digest := sha256.Sum256([]byte(strings.TrimSpace(string(boot)) + "\x00" + namespace + "\x00" + start))
	return fmt.Sprintf("v1:%x", digest), nil
}

func processStartCounter(stat string) (string, error) {
	// comm is parenthesized and may itself contain spaces and parentheses.
	end := strings.LastIndex(stat, ")")
	if end < 0 {
		return "", errors.New("invalid process stat")
	}
	fields := strings.Fields(stat[end+1:])
	// starttime is field 22; fields begins at field 3 (state).
	if len(fields) <= 19 {
		return "", errors.New("incomplete process stat")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", errors.New("invalid process start counter")
	}
	return fields[19], nil
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return errors.Is(err, syscall.EPERM)
}
