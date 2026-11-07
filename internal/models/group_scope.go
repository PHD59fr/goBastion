package models

import "gorm.io/gorm"

// ActiveGroup excludes orphaned rows left by older group deletions. Preloading
// Group alone does not filter the row when its parent has been soft-deleted.
func ActiveGroup(db *gorm.DB) *gorm.DB {
	groups := db.Session(&gorm.Session{NewDB: true}).Model(&Group{}).Select("id")
	return db.Where("group_id IN (?)", groups)
}
