package session

import "strings"

const auditRedactedValue = "[REDACTED]"

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
			redactNext = false
			continue
		}
		name, _, inline := strings.Cut(arg, "=")
		if name == "--password" || name == "-password" {
			if inline {
				redacted[i] = name + "=" + auditRedactedValue
			} else {
				redactNext = true
			}
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
