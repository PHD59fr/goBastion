package models

import "time"

// BastionInstance stores per-instance configuration in the database.
// Each bastion instance (identified by INSTANCE_ID) has its own config
// and role (master/slave). The Config field holds a JSON-encoded copy
// of the Config struct (everything except bootstrap DB connection params).
type BastionInstance struct {
	InstanceID string    `gorm:"primaryKey;column:instance_id"`
	Role       string    `gorm:"not null;default:'master'"` // "master" or "slave"
	Config     string    `gorm:"type:text"`                 // JSON-encoded config
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
