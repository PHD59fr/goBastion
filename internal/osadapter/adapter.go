package osadapter

import "goBastion/internal/models"

// SystemAdapter abstracts all OS-level operations so they can be mocked in tests.
type SystemAdapter interface {
	// CreateUser adds a new system OS user with disabled password.
	CreateUser(username string) error
	// DeleteUser removes a system OS user and their home directory.
	DeleteUser(username string) error
	// UpdateSudoers writes or removes the sudoers entry for a user based on their role.
	UpdateSudoers(user *models.User) error
	// ChownDir recursively changes ownership of a directory to the given user.
	ChownDir(user models.User, dir string) error
	// ExecCommand runs an OS command and returns its combined output.
	ExecCommand(name string, args ...string) (string, error)
	// UserHomeExists reports whether the user's home directory exists on disk.
	UserHomeExists(username string) bool
}
