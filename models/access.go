package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type SelfAccess struct {
	ID             uuid.UUID  `gorm:"type:uuid;primaryKey"`
	UserID         uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	User           User       `gorm:"foreignKey:UserID"`
	Username       string     `gorm:"not null"`
	Server         string     `gorm:"not null"`
	Port           int64      `gorm:"not null"`
	Protocol       string     `gorm:"default:ssh"` // ssh, scpupload, scpdownload, sftp, rsync
	Comment        string     `gorm:"default:null"`
	AllowedFrom    string     `gorm:"default:null"`
	ExpiresAt      *time.Time `gorm:"default:null"`
	LastConnection time.Time  `gorm:"default:null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      gorm.DeletedAt `gorm:"index"`
}

// BeforeCreate generates a UUID for SelfAccess before insertion.
func (sa *SelfAccess) BeforeCreate(*gorm.DB) (err error) {
	sa.ID = uuid.New()
	return
}

type GroupAccess struct {
	ID             uuid.UUID  `gorm:"type:uuid;primaryKey"`
	GroupID        uuid.UUID  `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	Group          Group      `gorm:"foreignKey:GroupID"`
	Username       string     `gorm:"not null"`
	Server         string     `gorm:"not null"`
	Port           int64      `gorm:"not null"`
	Protocol       string     `gorm:"default:ssh"` // ssh, scpupload, scpdownload, sftp, rsync
	Comment        string     `gorm:"default:null"`
	AllowedFrom    string     `gorm:"default:null"`
	ExpiresAt      *time.Time `gorm:"default:null"`
	LastConnection time.Time  `gorm:"default:null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      gorm.DeletedAt `gorm:"index"`
}

// BeforeCreate generates a UUID for GroupAccess before insertion.
func (ga *GroupAccess) BeforeCreate(*gorm.DB) (err error) {
	ga.ID = uuid.New()
	return
}

type AccessRight struct {
	ID             uuid.UUID
	Source         string
	Username       string
	Server         string
	Port           int64
	Type           string
	KeyId          uuid.UUID
	KeyType        string
	KeySize        int
	KeyFingerprint string
	KeyUpdatedAt   time.Time
	PublicKey      string
	PrivateKey     string
	RemoteCmd      string // non-empty for non-interactive sessions (e.g. SCP commands)
	MFARequired    bool   // JIT MFA required for this access (from group policy)
}
