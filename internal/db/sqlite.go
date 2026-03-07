package db

import "fmt"

// boolFalseExprSQLite returns a WHERE fragment for column = false on SQLite.
// glebarez/sqlite stores GORM bool fields as integer (0/1); NOT expr evaluates 0 as false.
func boolFalseExprSQLite(column string) string {
	return fmt.Sprintf("NOT %s", column)
}

// boolTrueExprSQLite returns a WHERE fragment for column = true on SQLite.
func boolTrueExprSQLite(column string) string {
	return column
}
