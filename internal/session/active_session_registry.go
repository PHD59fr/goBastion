package session

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"gorm.io/gorm"
)

func registerActiveSession(db *gorm.DB, currentUser *models.User, sessionID, kind string) (func(), error) {
	instanceID := config.InstanceID()
	limit := config.Get().Session.MaxConcurrentSessions
	record := models.ActiveSession{
		SessionID:  sessionID,
		InstanceID: instanceID,
		Username:   currentUser.Username,
		PID:        os.Getpid(),
		Kind:       kind,
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
	}); err != nil {
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
		if processAlive(session.PID) {
			continue
		}
		if err := db.Where("session_id = ?", session.SessionID).Delete(&models.ActiveSession{}).Error; err != nil {
			return err
		}
	}
	return nil
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
