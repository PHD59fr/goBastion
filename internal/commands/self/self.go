package self

import (
	"os"

	"golang.org/x/term"
)

// readPassword reads a password from stdin without echo.
func readPassword() (string, error) {
	pass, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	s := string(pass)
	// Wipe plaintext bytes from memory
	for i := range pass {
		pass[i] = 0
	}
	return s, nil
}
