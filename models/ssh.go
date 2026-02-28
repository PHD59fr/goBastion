package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type SshHostKey struct {
	Type       string `gorm:"primaryKey"`
	PrivateKey []byte
	PublicKey  []byte
}

type KnownHostsEntry struct {
	ID        uuid.UUID `gorm:"type:uuid;primaryKey"`
	UserID    uuid.UUID `gorm:"type:uuid;not null;index;constraint:OnDelete:CASCADE"`
	Entry     string    `gorm:"not null"`
	User      User      `gorm:"foreignKey:UserID"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

// BeforeCreate generates a UUID for KnownHostsEntry before insertion.
func (khe *KnownHostsEntry) BeforeCreate(*gorm.DB) (err error) {
	khe.ID = uuid.New()
	return nil
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

// BeforeCreate generates a UUID for IngressKey before insertion.
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

// BeforeCreate generates a UUID for SelfEgressKey before insertion.
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

// BeforeCreate generates a UUID for GroupEgressKey before insertion.
func (gek *GroupEgressKey) BeforeCreate(*gorm.DB) (err error) {
	gek.ID = uuid.New()
	return
}
