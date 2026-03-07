package db

import "fmt"

// boolFalseExprPostgres returns a WHERE fragment for column = false on PostgreSQL.
// Uses string literal 'false' which PostgreSQL implicitly casts to the column type,
// making it safe for both text and boolean column types.
func boolFalseExprPostgres(column string) string {
	return fmt.Sprintf("%s = 'false'", column)
}

// boolTrueExprPostgres returns a WHERE fragment for column = true on PostgreSQL.
func boolTrueExprPostgres(column string) string {
	return fmt.Sprintf("%s = 'true'", column)
}
