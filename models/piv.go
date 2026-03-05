package models

import (
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// PIVTrustAnchor holds a CA certificate (PEM) that admins trust for PIV attestation.
// Users can add ingress keys whose attestation chain roots back to one of these anchors.
type PIVTrustAnchor struct {
	ID           uuid.UUID `gorm:"type:uuid;primaryKey"`
	Name         string    `gorm:"not null;uniqueIndex"`
	CertPEM      string    `gorm:"not null"`
	AddedByID    uuid.UUID `gorm:"type:uuid;not null"`
	AddedBy      User      `gorm:"foreignKey:AddedByID"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"`
}

func (p *PIVTrustAnchor) BeforeCreate(*gorm.DB) (err error) {
	p.ID = uuid.New()
	return
}
