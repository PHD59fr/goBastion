package models

import (
	"fmt"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

type User struct {
	ID            uuid.UUID `gorm:"type:uuid;primaryKey"`
	Username      string    `gorm:"not null;index:idx_username_deletedat,unique"`
	Role          string    `gorm:"not null"` // "admin" or "user"
	Enabled       bool      `gorm:"default:true"`
	SystemUser    bool      `gorm:"default:false"`
	LastLoginFrom string    `gorm:"default:null"`
	LastLoginAt   time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
	DeletedAt     gorm.DeletedAt `gorm:"index:idx_username_deletedat"`
}

func (u *User) BeforeDelete(tx *gorm.DB) (err error) {
	if err := tx.Model(&UserGroup{}).Where("user_id = ?", u.ID).Update("deleted_at", time.Now()).Error; err != nil {
		return fmt.Errorf("error marking user groups as deleted: %w", err)
	}
	return nil
}

func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

func (u *User) IsEnabled() bool {
	return u.Enabled
}

func (u *User) BeforeCreate(*gorm.DB) (err error) {
	u.ID = uuid.New()
	return
}

type Group struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	Name      string    `gorm:"not null;index:idx_groupname_deletedat,unique"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index:idx_groupname_deletedat"`
}

func (g *Group) BeforeCreate(*gorm.DB) (err error) {
	g.ID = uuid.New()
	return
}

type UserGroup struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index"`
	GroupID   uuid.UUID `gorm:"type:uuid;not null;index"`
	Group     Group     `gorm:"foreignKey:GroupID;references:ID"`
	Role      string    `gorm:"not null"` // "owner", "gatekeeper", "aclkeeper", "member", "guest"
	User      User      `gorm:"foreignKey:UserID;constraint:OnDelete:CASCADE;where:deleted_at IS NULL"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (ug *UserGroup) BeforeCreate(*gorm.DB) (err error) {
	ug.ID = uuid.New()
	return
}

func (ug *UserGroup) IsOwner() bool {
	return ug.Role == "owner"
}

func (ug *UserGroup) IsGateKeeper() bool {
	return ug.Role == "gatekeeper"
}

func (ug *UserGroup) IsACLKeeper() bool {
	return ug.Role == "aclkeeper"
}

func (ug *UserGroup) IsMember() bool {
	return ug.Role == "member"
}

func (ug *UserGroup) IsGuest() bool {
	return ug.Role == "guest"
}
