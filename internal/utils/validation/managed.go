package validation

import "strings"

// IsValidManagedUsername applies the reserved local-identity boundary. It does
// not replace IsValidUsername for remote database or SSH target names.
func IsValidManagedUsername(name string) bool {
	return name == strings.ToLower(strings.TrimSpace(name)) && IsValidUsername(name) && name != "gobastion" && name != "nobody" && name != "gobastion-session"
}
