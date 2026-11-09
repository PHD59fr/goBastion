package models

import "time"

// ObservationCounter accumulates a fixed metric for one configured instance.
// ForceCommand processes share these rows with the dedicated metrics exporter.
// Values contain only counts/durations, never user names or event attributes.
type ObservationCounter struct {
	InstanceID string `gorm:"size:191;primaryKey"`
	Name       string `gorm:"size:96;primaryKey"`
	Value      int64  `gorm:"not null"`
	UpdatedAt  time.Time
}

func (ObservationCounter) TableName() string { return "observation_counters" }
