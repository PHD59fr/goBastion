package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SelfDBAccess grants a user personal access to a database server.
// Follows the same pattern as SelfAccess: stores Host/Port/Protocol/Username directly.
// Password is encrypted with the egress encryption key.
type SelfDBAccess struct {
	ID             uuid.UUID  `gorm:"type:uuid;primaryKey"`
	UserID         uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	User           User       `gorm:"foreignKey:UserID"`
	Host           string     `gorm:"not null"`
	Port           int64      `gorm:"not null"`
	Protocol       string     `gorm:"not null"` // mysql, postgres, mongo, redis
	Username       string     `gorm:"not null"`
	Password       string     `gorm:"default:null"` // encrypted, nullable (client prompts if empty)
	Database       string     `gorm:"default:null"` // specific DB name (nullable = connect without selecting)
	Comment        string     `gorm:"default:null"`
	AllowedFrom    string     `gorm:"default:null"` // CIDRs
	ExpiresAt      *time.Time `gorm:"default:null"`
	LastConnection time.Time  `gorm:"default:null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      gorm.DeletedAt `gorm:"index"`
}

func (s *SelfDBAccess) BeforeCreate(tx *gorm.DB) (err error) {
	s.ID = uuid.New()
	return nil
}

// GroupDBAccess grants a group access to a database server.
type GroupDBAccess struct {
	ID             uuid.UUID  `gorm:"type:uuid;primaryKey"`
	GroupID        uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	Group          Group      `gorm:"foreignKey:GroupID"`
	Host           string     `gorm:"not null"`
	Port           int64      `gorm:"not null"`
	Protocol       string     `gorm:"not null"`
	Username       string     `gorm:"not null"`
	Password       string     `gorm:"default:null"` // encrypted, nullable
	Database       string     `gorm:"default:null"`
	Comment        string     `gorm:"default:null"`
	AllowedFrom    string     `gorm:"default:null"`
	ExpiresAt      *time.Time `gorm:"default:null"`
	LastConnection time.Time  `gorm:"default:null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      gorm.DeletedAt `gorm:"index"`
}

func (g *GroupDBAccess) BeforeCreate(tx *gorm.DB) (err error) {
	g.ID = uuid.New()
	return nil
}

// GroupGuestDBAccess grants a specific user within a group access to a database server.
type GroupGuestDBAccess struct {
	ID             uuid.UUID      `gorm:"type:uuid;primaryKey"`
	GroupID        uuid.UUID      `gorm:"type:uuid;not null;index"`
	Group          Group          `gorm:"foreignKey:GroupID"`
	UserID         uuid.UUID      `gorm:"type:uuid;not null;index"`
	User           User           `gorm:"foreignKey:UserID"`
	Host           string         `gorm:"not null"`
	Port           int64          `gorm:"not null"`
	Protocol       string         `gorm:"not null"`
	Username       string         `gorm:"not null"`
	Password       string         `gorm:"default:null"` // encrypted, nullable
	Database       string         `gorm:"default:null"`
	Comment        string         `gorm:"default:null"`
	AllowedFrom    string         `gorm:"default:null"`
	ExpiresAt      *time.Time     `gorm:"default:null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      gorm.DeletedAt `gorm:"index"`
}

func (g *GroupGuestDBAccess) BeforeCreate(tx *gorm.DB) (err error) {
	g.ID = uuid.New()
	if g.UserID == uuid.Nil {
		return fmt.Errorf("user_id is required for group guest DB access")
	}
	return nil
}

// DBAccessRight is the runtime representation of a resolved database access.
type DBAccessRight struct {
	ID             uuid.UUID
	Source         string // "account-name" or "group-name"
	Host           string
	Port           int64
	Protocol       string // mysql, postgres, mongo, redis
	Username       string
	Password       string // decrypted, empty if not stored
	Database       string
	AllowedFrom    string
	MFARequired    bool
}

// DatabaseAlias maps a friendly name to a real database host:port:protocol.
// Follows the same pattern as Aliases (but carries Port + Protocol since DB
// targets are identified by host:port:protocol, not just hostname).
type DatabaseAlias struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey"`
	ResolveFrom string     `gorm:"not null"` // alias name
	Host        string     `gorm:"not null"`
	Port        int64      `gorm:"not null"`
	Protocol    string     `gorm:"not null"`
	UserID      *uuid.UUID `gorm:"type:uuid;index;constraint:OnDelete:CASCADE"`
	GroupID     *uuid.UUID `gorm:"type:uuid;index;constraint:OnDelete:CASCADE"`
	User        *User      `gorm:"foreignKey:UserID"`
	Group       *Group     `gorm:"foreignKey:GroupID"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func (a *DatabaseAlias) BeforeCreate(tx *gorm.DB) (err error) {
	a.ID = uuid.New()
	if a.UserID != nil && a.GroupID != nil {
		return fmt.Errorf("a database alias cannot be attached to both a user and a group")
	}
	if a.UserID == nil && a.GroupID == nil {
		return fmt.Errorf("a database alias must be attached either to a user or a group")
	}
	return nil
}
