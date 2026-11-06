package account

import (
	"goBastion/internal/models"
	"gorm.io/gorm"
)

func withAccountChange(db *gorm.DB, fn func(*gorm.DB) error) error {
	return models.WithAccountChange(db, fn)
}
func requireOtherAdmin(db *gorm.DB, u *models.User) error { return models.RequireOtherAdmin(db, u) }
