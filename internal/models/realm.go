package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Realm defines trust metadata for external bastion identities.
type Realm struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey"`
	Name        string    `gorm:"not null;uniqueIndex"`
	BastionHost string    `gorm:"not null"` // remote bastion entrypoint hostname/IP
	BastionPort int64     `gorm:"not null;default:22"`
	AllowedFrom string    `gorm:"not null"` // comma-separated CIDRs trusted for ingress from remote bastion
	PublicKey   string    `gorm:"not null"` // remote bastion egress public key
	Enabled     bool      `gorm:"type:boolean;default:true"`
	CreatedByID uuid.UUID `gorm:"type:uuid;not null"`
	CreatedBy   User      `gorm:"foreignKey:CreatedByID"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func (r *Realm) BeforeCreate(*gorm.DB) (err error) {
	r.ID = uuid.New()
	return
}

// RestrictedCommandGrant allows a non-admin account to run a specific restricted command.
type RestrictedCommandGrant struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID      uuid.UUID `gorm:"type:uuid;not null;index:idx_user_command_grant,unique"`
	User        User      `gorm:"foreignKey:UserID"`
	Command     string    `gorm:"not null;index:idx_user_command_grant,unique"`
	GrantedByID uuid.UUID `gorm:"type:uuid;not null"`
	GrantedBy   User      `gorm:"foreignKey:GrantedByID"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func (g *RestrictedCommandGrant) BeforeCreate(*gorm.DB) (err error) {
	g.ID = uuid.New()
	return
}
