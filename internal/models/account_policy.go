package models

import (
	"database/sql"
	"errors"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var ErrLastAdmin = errors.New("cannot remove the last usable administrator")

// All administrator removal paths share the same transaction/lock order.
// Serializable isolation also protects PostgreSQL against concurrent changes
// to the set of administrators; SQLite fails closed on a competing writer.
func WithAccountChange(db *gorm.DB, change func(*gorm.DB) error) error {
	return db.Transaction(func(tx *gorm.DB) error {
		var admins []User
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("role = ?", RoleAdmin).Order("id").Find(&admins).Error; err != nil {
			return err
		}
		return change(tx)
	}, &sql.TxOptions{Isolation: sql.LevelSerializable})
}

func RequireOtherAdmin(db *gorm.DB, target *User) error {
	if !target.IsAdmin() {
		return nil
	}
	var count int64
	if err := db.Model(&User{}).
		Where(clause.Neq{Column: "id", Value: target.ID}).
		Where(map[string]any{"role": RoleAdmin, "enabled": true, "system_user": false}).
		Count(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		return ErrLastAdmin
	}
	return nil
}
