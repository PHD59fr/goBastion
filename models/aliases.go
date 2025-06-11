package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Aliases struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey"`
	ResolveFrom string     `gorm:"not null"`
	Host        string     `gorm:"not null"`
	UserID      *uuid.UUID `gorm:"type:uuid;index;constraint:OnDelete:CASCADE"` // If a User is deleted, associated Aliases are deleted
	GroupID     *uuid.UUID `gorm:"type:uuid;index;constraint:OnDelete:CASCADE"` // If Group is deleted, associated Aliases are deleted
	User        *User      `gorm:"foreignKey:UserID"`
	Group       *Group     `gorm:"foreignKey:GroupID"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func (h *Aliases) BeforeCreate(*gorm.DB) (err error) {
	h.ID = uuid.New()
	if h.UserID != nil && h.GroupID != nil {
		return fmt.Errorf("a host cannot be attached to both a user and a group")
	}
	if h.UserID == nil && h.GroupID == nil {
		return fmt.Errorf("a host must be attached either to a user or a group")
	}
	return nil
}
