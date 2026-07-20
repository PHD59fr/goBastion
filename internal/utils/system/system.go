package system

import (
	"os"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
)

// defaultAdapter is the production adapter used by standalone helper functions.
var defaultAdapter = osadapter.NewLinuxAdapter()

// ClientIPFromEnv safely extracts the client IP address from the SSH_CLIENT
// environment variable. Returns "unknown" if the variable is empty, missing,
// or malformed.
func ClientIPFromEnv() string {
	raw := os.Getenv("SSH_CLIENT")
	if raw == "" {
		return "unknown"
	}
	fields := strings.Fields(raw)
	if len(fields) == 0 || fields[0] == "" {
		return "unknown"
	}
	return fields[0]
}

// CreateUser adds a new system OS user with disabled password.
// Delegates to the OS adapter to avoid code duplication with linux.go.
func CreateUser(username string) error {
	return defaultAdapter.CreateUser(username)
}

// DeleteUser removes a system OS user and their home directory.
// Delegates to the OS adapter to avoid code duplication with linux.go.
func DeleteUser(username string) error {
	return defaultAdapter.DeleteUser(username)
}

// ChownDir recursively changes ownership of a directory to the given user.
// Delegates to the OS adapter to avoid code duplication with linux.go.
func ChownDir(user models.User, dir string) error {
	return defaultAdapter.ChownDir(user, dir)
}

// UpdateSudoers writes or removes the sudoers entry for a user based on their role.
// Delegates to the OS adapter to avoid code duplication with linux.go.
func UpdateSudoers(user *models.User) error {
	return defaultAdapter.UpdateSudoers(user)
}

// ExecCommand runs an OS command and returns its combined output.
func ExecCommand(name string, arg ...string) (string, error) {
	return defaultAdapter.ExecCommand(name, arg...)
}
