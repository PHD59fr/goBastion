package session

import (
	"net/url"
	"regexp"
	"strings"
)

const auditRedactedValue = "[REDACTED]"

var auditCredentialAssignment = regexp.MustCompile(`(?i)(?:^|[\s;&?])(?:password|passwd|pwd|pgpassword|token|access_token|refresh_token|api_key|secret|authorization)\s*=`)

func sensitiveAuditArgument(name string) bool {
	name = strings.ReplaceAll(strings.ToLower(strings.TrimLeft(name, "-")), "_", "-")
	switch name {
	case "password", "passwd", "pwd", "pgpassword", "token", "access-token", "refresh-token", "api-key", "secret", "totp-secret", "private-key", "authorization", "dsn", "db-dsn", "database-url", "database-uri", "connection-string":
		return true
	}
	return false
}

// Credential-bearing connection strings can be positional arguments or values
// of otherwise innocuous flags. Omit the complete token rather than attempting
// to preserve a partially parsed database dialect or quoted password.
func credentialBearingAuditValue(value string) bool {
	if auditCredentialAssignment.MatchString(value) {
		return true
	}
	if u, err := url.Parse(value); err == nil && u.Scheme != "" {
		if u.User != nil {
			return true
		}
		for key := range u.Query() {
			if sensitiveAuditArgument(key) {
				return true
			}
		}
	}
	// MySQL's user:password@tcp(...) and user:password@unix(...) DSNs.
	if at := strings.Index(value, "@"); at > 0 && strings.Contains(value[:at], ":") {
		return true
	}
	return false
}

// redactAuditArgs returns a copy suitable for logging without changing the
// arguments passed to command handlers.
func redactAuditArgs(args []string) []string {
	if args == nil {
		return nil
	}

	redacted := append([]string(nil), args...)
	redactNext := false
	for i, arg := range redacted {
		if redactNext {
			redacted[i] = auditRedactedValue
			// Some callers separate an assignment with whitespace around '='.
			redactNext = arg == "="
			continue
		}
		name, value, inline := strings.Cut(arg, "=")
		separateAssignment := i+1 < len(redacted) && strings.HasPrefix(redacted[i+1], "=")
		if sensitiveAuditArgument(name) && (inline || strings.HasPrefix(name, "-") || separateAssignment) {
			if inline {
				redacted[i] = name + "=" + auditRedactedValue
				redactNext = value == ""
			} else {
				redactNext = true
			}
		} else if credentialBearingAuditValue(arg) || (inline && credentialBearingAuditValue(value)) {
			redacted[i] = auditRedactedValue
		}
	}
	return redacted
}

// redactAuditCommand handles SSH_ORIGINAL_COMMAND, which can arrive as one
// argument containing the complete command line.
func redactAuditCommand(command string) string {
	parts, err := parseCommandLine(command)
	if err != nil {
		// Malformed quoting cannot be safely split to locate secret values.
		return auditRedactedValue
	}
	redacted := redactAuditArgs(parts)
	for i := range parts {
		if parts[i] != redacted[i] {
			return strings.Join(redacted, " ")
		}
	}
	return command
}
