package db

import "fmt"

// boolFalseExprMySQL returns a WHERE fragment for column = false on MySQL.
// MySQL stores GORM bool fields as TINYINT(1).
// The column name is backtick-quoted; SYSTEM_USER is a built-in function in MySQL.
func boolFalseExprMySQL(column string) string {
	return fmt.Sprintf("`%s` = 0", column)
}

// boolTrueExprMySQL returns a WHERE fragment for column = true on MySQL.
func boolTrueExprMySQL(column string) string {
	return fmt.Sprintf("`%s` = 1", column)
}
