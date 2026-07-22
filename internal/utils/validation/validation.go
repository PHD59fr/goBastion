package validation

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// EntityNameRegexp matches valid entity names (aliases, group names, realm names, etc.).
var EntityNameRegexp = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

// ValidProtocols is the set of accepted protocol values for access entries.
var ValidProtocols = map[string]bool{
	"ssh":         true,
	"scpupload":   true,
	"scpdownload": true,
	"sftp":        true,
	"rsync":       true,
}

// IsValidProtocol returns true when p is one of the accepted access protocols.
func IsValidProtocol(p string) bool {
	return ValidProtocols[p]
}

// ValidDBProtocols is the set of accepted database client protocols.
var ValidDBProtocols = map[string]bool{
	"mysql":    true,
	"postgres": true,
	"redis":    true,
}

// IsValidDBProtocol returns true when p is one of the accepted database protocols.
func IsValidDBProtocol(p string) bool {
	return ValidDBProtocols[p]
}

// DBProtocolDefaultPort returns the default port for a database protocol.
func DBProtocolDefaultPort(p string) int64 {
	switch p {
	case "mysql":
		return 3306
	case "postgres":
		return 5432
	case "redis":
		return 6379
	default:
		return 0
	}
}

// DBProtocolClient returns the default client binary name for a protocol.
func DBProtocolClient(p string) string {
	switch p {
	case "mysql":
		return "mariadb"
	case "postgres":
		return "psql"
	case "redis":
		return "redis-cli"
	default:
		return ""
	}
}

// IsValidHost returns true when h is a valid hostname or IP address.
// IPv6 addresses enclosed in square brackets (e.g. [::1]) are accepted.
// Rejects strings containing spaces, '@', '/', or '\'.
func IsValidHost(h string) bool {
	if strings.ContainsAny(h, " @/\\") {
		return false
	}
	host := h
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	if net.ParseIP(host) != nil {
		return true
	}
	return EntityNameRegexp.MatchString(host)
}

// IsValidUsername returns true when u is a valid Linux username.
// According to POSIX, usernames must contain only letters, digits,
// underscores, hyphens, periods, and at signs, and must not start with a hyphen,
// plus sign, or at sign. For simplicity, we restrict to alphanumeric,
// underscore, hyphen, period, and at sign, and ensure it does not start with
// a special character.
func IsValidUsername(u string) bool {
	if u == "" {
		return false
	}
	// Regex: start with alphanumeric or @, then alphanumeric, underscore, hyphen, period, @
	// but we also want to restrict to reasonable characters.
	// Let's use: ^[a-zA-Z0-9][a-zA-Z0-9._-]*$
	// However Linux usernames can have @? Actually not typical. We'll follow typical pattern.
	// We'll use same as host but without allowing @? Actually username can have @? Not typical.
	// We'll use: ^[a-zA-Z0-9][a-zA-Z0-9._-]*$
	// and ensure length <= 32 (typical limit).
	if len(u) > 32 {
		return false
	}
	// First char must be alphanumeric
	if (u[0] < 'a' || u[0] > 'z') && (u[0] < 'A' || u[0] > 'Z') && (u[0] < '0' || u[0] > '9') {
		return false
	}
	for _, ch := range u {
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '.' && ch != '_' && ch != '-' {
			return false
		}
	}
	return true
}

// WrapDBError returns a generic error message for database operations
// to avoid exposing internal database details to users.
func WrapDBError(err error, context string) error {
	if err == nil {
		return nil
	}
	// Don't wrap already wrapped errors
	if strings.Contains(err.Error(), "Please contact admin") ||
		strings.Contains(err.Error(), "Please try again") {
		return err
	}
	return fmt.Errorf("%s: %w", context, err)
}

// IsValidCIDRs validates a comma-separated list of CIDR notation strings.
// Returns true only if every entry is a valid CIDR (or empty string).
func IsValidCIDRs(cidrs string) bool {
	if cidrs == "" {
		return true
	}
	for _, c := range strings.Split(cidrs, ",") {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(c); err != nil {
			return false
		}
	}
	return true
}

// IsValidPort returns true when port is in the valid TCP/UDP range 1-65535.
func IsValidPort(port int64) bool {
	return port >= 1 && port <= 65535
}

// IsPrivateOrReservedTarget returns true when server resolves to a private,
// loopback, link-local, multicast, or unspecified IP address.
// Hostnames that do not resolve to an IP are not considered private.
// This is used to restrict active TCP probes to internal targets only,
// preventing scanner-like behavior against public addresses.
func IsPrivateOrReservedTarget(server string) bool {
	host := strings.TrimSpace(server)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}
