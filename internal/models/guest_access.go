package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// GroupGuestAccess stores granular per-user, per-server guest access grants
// within a group. A guest-role user can only connect to servers listed in
// their grants, using the group's egress key.
type GroupGuestAccess struct {
	ID           uuid.UUID      `gorm:"type:uuid;primaryKey"`
	GroupID      uuid.UUID      `gorm:"type:uuid;not null;index"`
	Group        Group          `gorm:"foreignKey:GroupID"`
	UserID       uuid.UUID      `gorm:"type:uuid;not null;index"`
	User         User           `gorm:"foreignKey:UserID"`
	Username     string         `gorm:"not null"`
	Server       string         `gorm:"not null"`
	Port         int64          `gorm:"not null"`
	Protocol     string         `gorm:"default:ssh"`
	Comment      string         `gorm:"default:null"`
	AllowedFrom  string         `gorm:"default:null"`
	ExpiresAt    *time.Time     `gorm:"default:null"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}

// BeforeCreate generates a UUID for GroupGuestAccess before insertion.
func (gga *GroupGuestAccess) BeforeCreate(*gorm.DB) (err error) {
	gga.ID = uuid.New()
	return
}
