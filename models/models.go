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

var Grades = []string{
	"Owner",
	"GateKeeper",
	"ACLKeeper",
	"Member",
	"Guest",
}

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

type IngressKey struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID      uuid.UUID `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	Key         string    `gorm:"not null"`
	Type        string    `gorm:"not null"`
	Size        int       `gorm:"not null"`
	Fingerprint string    `gorm:"not null"`
	Comment     string
	User        User `gorm:"foreignKey:UserID"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func (ik *IngressKey) BeforeCreate(*gorm.DB) (err error) {
	ik.ID = uuid.New()
	return
}

type SelfEgressKey struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID      uuid.UUID `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	PubKey      string    `gorm:"not null"`
	PrivKey     string    `gorm:"not null"`
	Type        string    `gorm:"not null"`
	Size        int       `gorm:"not null"`
	Fingerprint string    `gorm:"not null"`
	User        User      `gorm:"foreignKey:UserID"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func (sek *SelfEgressKey) BeforeCreate(*gorm.DB) (err error) {
	sek.ID = uuid.New()
	return
}

type GroupEgressKey struct {
	ID          uuid.UUID `gorm:"type:uuid;primaryKey"`
	GroupID     uuid.UUID `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	PubKey      string    `gorm:"not null"`
	PrivKey     string    `gorm:"not null"`
	Type        string    `gorm:"not null"`
	Size        int       `gorm:"not null"`
	Fingerprint string    `gorm:"not null"`
	Group       Group     `gorm:"foreignKey:GroupID"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func (gek *GroupEgressKey) BeforeCreate(*gorm.DB) (err error) {
	gek.ID = uuid.New()
	return
}

type SelfAccess struct {
	ID             uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID         uuid.UUID `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	User           User      `gorm:"foreignKey:UserID"`
	Username       string    `gorm:"not null"`
	Server         string    `gorm:"not null"`
	Port           int64     `gorm:"not null"`
	Comment        string    `gorm:"default:null"`
	LastConnection time.Time `gorm:"default:null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      gorm.DeletedAt `gorm:"index"`
}

func (sa *SelfAccess) BeforeCreate(*gorm.DB) (err error) {
	sa.ID = uuid.New()
	return
}

type GroupAccess struct {
	ID             uuid.UUID `gorm:"type:uuid;primaryKey"`
	GroupID        uuid.UUID `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	Group          Group     `gorm:"foreignKey:GroupID"`
	Username       string    `gorm:"not null"`
	Server         string    `gorm:"not null"`
	Port           int64     `gorm:"not null"`
	Comment        string    `gorm:"default:null"`
	LastConnection time.Time `gorm:"default:null"`
	CreatedAt      time.Time
	UpdatedAt      time.Time
	DeletedAt      gorm.DeletedAt `gorm:"index"`
}

func (ga *GroupAccess) BeforeCreate(*gorm.DB) (err error) {
	ga.ID = uuid.New()
	return
}

type AccessRight struct {
	ID             uuid.UUID
	Source         string // "account", "group", "admin"
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
}

type Aliases struct {
	ID          uuid.UUID  `gorm:"type:uuid;primaryKey"`
	ResolveFrom string     `gorm:"not null"`
	Host        string     `gorm:"not null"`
	UserID      *uuid.UUID `gorm:"type:uuid;index;constraint:OnDelete:CASCADE"` // If User is deleted, associated Aliases are deleted
	GroupID     *uuid.UUID `gorm:"type:uuid;index;constraint:OnDelete:CASCADE"` // If Group is deleted, associated Aliases are deleted
	User        *User      `gorm:"foreignKey:UserID"`
	Group       *Group     `gorm:"foreignKey:GroupID"`
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   gorm.DeletedAt `gorm:"index"`
}

func (h *Aliases) BeforeCreate(tx *gorm.DB) (err error) {
	h.ID = uuid.New()
	if h.UserID != nil && h.GroupID != nil {
		return fmt.Errorf("a host cannot be attached to both a user and a group")
	}
	if h.UserID == nil && h.GroupID == nil {
		return fmt.Errorf("a host must be attached either to a user or a group")
	}
	return nil
}
