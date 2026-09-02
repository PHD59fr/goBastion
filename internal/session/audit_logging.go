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
		if arg == "--password" {
			redactNext = true
			continue
		}
		if strings.HasPrefix(arg, "--password=") {
			redacted[i] = "--password=" + auditRedactedValue
		}
	}
	return redacted
}

// redactAuditCommand handles SSH_ORIGINAL_COMMAND, which can arrive as one
// argument containing the complete command line.
func redactAuditCommand(command string) string {
	parts := strings.Fields(command)
	redacted := redactAuditArgs(parts)
	for i := range parts {
		if parts[i] != redacted[i] {
			return strings.Join(redacted, " ")
		}
	}
	return command
}
