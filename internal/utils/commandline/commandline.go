package commandline

import (
	"errors"
	"strings"
	"unicode"
)

// Scan splits terminal input and SSH command strings into arguments with source positions.
// It supports shell-style quotes and escapes, but performs no shell expansion or
// execution. Callers with an existing argv must pass it through without reparsing.
func Scan(line string) ([]Token, error) {
	var args []Token
	start := -1
	shellSyntax := false
	var word strings.Builder
	var quote rune
	started, escaped := false, false
	for pos, ch := range line {
		if start < 0 && !unicode.IsSpace(ch) {
			start = pos
		}
		if !escaped && (quote == 0 && strings.ContainsRune("$`;&|<>()\n\r", ch) || quote == '"' && strings.ContainsRune("$`", ch) || quote == 0 && ch == '#' && !started) {
			shellSyntax = true
		}
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
				args = append(args, Token{Value: word.String(), Start: start, End: pos, ShellSyntax: shellSyntax})
				start = -1
				shellSyntax = false
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
		args = append(args, Token{Value: word.String(), Start: start, End: len(line), ShellSyntax: shellSyntax})
	}
	return args, nil
}

// Token retains the source range so forwarding options can be removed without
// changing quotes or spaces in a remote command. ShellSyntax flags expansion,
// comments and control operators that must not be executed by transfer servers.
type Token struct {
	Value       string
	Start, End  int
	ShellSyntax bool
}

func Split(line string) ([]string, error) {
	tokens, err := Scan(line)
	if err != nil {
		return nil, err
	}
	var args []string
	for _, token := range tokens {
		args = append(args, token.Value)
	}
	return args, nil
}

// Quote makes one literal POSIX shell argument, including embedded apostrophes.
func Quote(arg string) string {
	return "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
}
