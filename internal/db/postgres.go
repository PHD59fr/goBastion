package db

import "fmt"

// boolFalseExprPostgres returns a WHERE fragment for column = false on PostgreSQL.
// The column name is double-quoted to prevent PostgreSQL from interpreting it as a
// built-in keyword (e.g. system_user is SYSTEM_USER in PostgreSQL 16).
// The string literal 'false' is implicitly cast to the column type (boolean or text).
func boolFalseExprPostgres(column string) string {
	return fmt.Sprintf(`"%s" = 'false'`, column)
}

// boolTrueExprPostgres returns a WHERE fragment for column = true on PostgreSQL.
func boolTrueExprPostgres(column string) string {
	return fmt.Sprintf(`"%s" = 'true'`, column)
}
