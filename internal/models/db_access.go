package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// DatabaseHost stores a database server's connection credentials.
// Password is encrypted with the egress encryption key.
type DatabaseHost struct {
	ID       uuid.UUID `gorm:"type:uuid;primaryKey"`
	Name     string    `gorm:"uniqueIndex;not null"`
	Host     string    `gorm:"not null"`
	Port     int64     `gorm:"not null"`
	Protocol string    `gorm:"not null"` // mysql, postgres, mongo, redis
	Username string    `gorm:"not null"`
	Password string    `gorm:"default:null"` // encrypted, nullable (client prompts if empty)
	Comment  string    `gorm:"default:null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (dh *DatabaseHost) BeforeCreate(*gorm.DB) (err error) {
	dh.ID = uuid.New()
	return
}

// SelfDBAccess grants a user personal access to a DatabaseHost.
type SelfDBAccess struct {
	ID             uuid.UUID  `gorm:"type:uuid;primaryKey"`
	UserID         uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	User           User       `gorm:"foreignKey:UserID"`
	DatabaseHostID uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	DatabaseHost   DatabaseHost `gorm:"foreignKey:DatabaseHostID"`
	Database       string     `gorm:"default:null"` // specific DB name (nullable = connect without selecting)
	Comment        string     `gorm:"default:null"`
	AllowedFrom    string     `gorm:"default:null"` // CIDRs
	ExpiresAt      *time.Time `gorm:"default:null"`
	LastConnection time.Time  `gorm:"default:null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (s *SelfDBAccess) BeforeCreate(*gorm.DB) (err error) {
	s.ID = uuid.New()
	return
}

// GroupDBAccess grants a group access to a DatabaseHost.
type GroupDBAccess struct {
	ID             uuid.UUID  `gorm:"type:uuid;primaryKey"`
	GroupID        uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	Group          Group      `gorm:"foreignKey:GroupID"`
	DatabaseHostID uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	DatabaseHost   DatabaseHost `gorm:"foreignKey:DatabaseHostID"`
	Database       string     `gorm:"default:null"`
	Comment        string     `gorm:"default:null"`
	AllowedFrom    string     `gorm:"default:null"`
	ExpiresAt      *time.Time `gorm:"default:null"`
	LastConnection time.Time  `gorm:"default:null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (g *GroupDBAccess) BeforeCreate(*gorm.DB) (err error) {
	g.ID = uuid.New()
	return
}

// GroupGuestDBAccess grants a specific user within a group access to a DatabaseHost.
type GroupGuestDBAccess struct {
	ID             uuid.UUID      `gorm:"type:uuid;primaryKey"`
	GroupID        uuid.UUID      `gorm:"type:uuid;not null;index"`
	Group          Group          `gorm:"foreignKey:GroupID"`
	UserID         uuid.UUID      `gorm:"type:uuid;not null;index"`
	User           User           `gorm:"foreignKey:UserID"`
	DatabaseHostID uuid.UUID      `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	DatabaseHost   DatabaseHost   `gorm:"foreignKey:DatabaseHostID"`
	Database       string         `gorm:"default:null"`
	Comment        string         `gorm:"default:null"`
	AllowedFrom    string         `gorm:"default:null"`
	ExpiresAt      *time.Time     `gorm:"default:null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (g *GroupGuestDBAccess) BeforeCreate(*gorm.DB) (err error) {
	g.ID = uuid.New()
	return
}

// DBAccessRight is the runtime representation of a resolved database access.
type DBAccessRight struct {
	Source     string // "account-name" or "group-name"
	Host       string
	Port       int64
	Protocol   string // mysql, postgres, mongo, redis
	Username   string
	Password   string // decrypted, empty if not stored
	Database   string
	MFARequired bool
}
