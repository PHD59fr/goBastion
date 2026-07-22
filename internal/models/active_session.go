package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ActiveSession tracks authenticated sessions currently running on one bastion instance.
// It is used for instance-wide session concurrency limits.
type ActiveSession struct {
	SessionID  string `gorm:"primaryKey;column:session_id"`
	InstanceID string `gorm:"index;not null"`
	Username   string `gorm:"index;not null"`
	PID        int    `gorm:"not null"`
	Kind       string `gorm:"not null"`
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (s *ActiveSession) BeforeCreate(*gorm.DB) error {
	if s.SessionID == "" {
		s.SessionID = uuid.NewString()
	}
	return nil
}
