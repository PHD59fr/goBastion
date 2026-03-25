package validation

import (
	"net"
	"regexp"
	"strings"
)

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

// hostRegexp matches valid hostnames/FQDNs.
var hostRegexp = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)

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
	return hostRegexp.MatchString(host)
}
