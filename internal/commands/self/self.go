package self

import (
	"os"

	"golang.org/x/term"
)

// readPassword reads a password from stdin without echo.
func readPassword() (string, error) {
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	return string(pass), err
}
