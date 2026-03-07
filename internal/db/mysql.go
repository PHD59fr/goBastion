package db

import "fmt"

// boolFalseExprMySQL returns a WHERE fragment for column = false on MySQL.
// MySQL stores GORM bool fields as TINYINT(1); NOT expr evaluates 0 as false.
func boolFalseExprMySQL(column string) string {
	return fmt.Sprintf("NOT %s", column)
}

// boolTrueExprMySQL returns a WHERE fragment for column = true on MySQL.
func boolTrueExprMySQL(column string) string {
	return column
}
