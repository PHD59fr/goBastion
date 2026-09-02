package utils

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// ResolveSecret returns the provided value, or — when none was provided and
// stdin is an interactive terminal — prompts for it without echo. This lets
// callers accept credentials via a flag (for non-interactive -osh scripting)
// while keeping them out of the shell history and the process list during an
// interactive session.
//
// When nothing is provided and stdin is not a TTY (automation), it returns an
// empty string so that password-less accesses keep working.
func ResolveSecret(provided, prompt string) (string, error) {
	if provided != "" {
		return provided, nil
	}
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", nil
	}
	fmt.Fprintf(os.Stderr, "%s: ", prompt)
	bytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("could not read secret: %w", err)
	}
	s := string(bytes)
	for i := range bytes {
		bytes[i] = 0
	}
	return s, nil
}