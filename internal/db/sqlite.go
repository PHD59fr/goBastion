package db

import "fmt"

// boolFalseExprSQLite returns a WHERE fragment for column = false on SQLite.
// glebarez/sqlite stores GORM bool fields as integer (0/1).
// The column name is double-quoted to avoid any keyword conflict.
func boolFalseExprSQLite(column string) string {
	return fmt.Sprintf(`"%s" = 0`, column)
}

// boolTrueExprSQLite returns a WHERE fragment for column = true on SQLite.
func boolTrueExprSQLite(column string) string {
	return fmt.Sprintf(`"%s" = 1`, column)
}
