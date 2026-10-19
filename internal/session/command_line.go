package session

import (
	"errors"
	"strings"
	"unicode"
)

// parseCommandLine splits terminal input and SSH command strings into arguments.
// It supports shell-style quotes and escapes, but performs no shell expansion or
// execution. Callers with an existing argv must pass it through without reparsing.
func parseCommandLine(line string) ([]string, error) {
	var args []string
	var word strings.Builder
	var quote rune
	started, escaped := false, false
	for _, ch := range line {
		switch {
		case escaped:
			// Inside double quotes, backslashes only escape shell metacharacters.
			if quote == '"' && !strings.ContainsRune("$`\"\\\n", ch) {
				word.WriteRune('\\')
			}
			if ch != '\n' {
				word.WriteRune(ch)
				started = true
			}
			escaped = false
		case ch == '\\' && quote != '\'':
			escaped = true
		case quote != 0:
			if ch == quote {
				quote = 0
			} else {
				word.WriteRune(ch)
			}
		case ch == '\'' || ch == '"':
			quote = ch
			started = true
		case unicode.IsSpace(ch):
			if started {
				args = append(args, word.String())
				word.Reset()
				started = false
			}
		default:
			word.WriteRune(ch)
			started = true
		}
	}
	if escaped {
		return nil, errors.New("unfinished escape: add a character after the backslash")
	}
	if quote != 0 {
		return nil, errors.New("unterminated quote: close the quoted argument")
	}
	if started {
		args = append(args, word.String())
	}
	return args, nil
}
