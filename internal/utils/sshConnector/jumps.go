package sshConnector

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"goBastion/internal/models"
	"goBastion/internal/utils/validation"
	"gorm.io/gorm"
)

func sshConfigValue(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n\x00") {
		return "", fmt.Errorf("invalid SSH configuration value")
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(value) + `"`, nil
}

// OpenSSH propagates -F to ProxyJump subprocesses, whereas -i is not inherited.
func jumpConfig(db *gorm.DB, user models.User, hops []string, key, known string) (string, []string, error) {
	keyValue, err := sshConfigValue(key)
	if err != nil {
		return "", nil, err
	}
	knownValue, err := sshConfigValue(known)
	if err != nil {
		return "", nil, err
	}
	var content strings.Builder
	fmt.Fprintf(&content, "Host *\n IdentityFile %s\n IdentitiesOnly yes\n IdentityAgent none\n UserKnownHostsFile %s\n StrictHostKeyChecking yes\n", keyValue, knownValue)
	var aliases []string
	for i, hop := range hops {
		username := user.Username
		address := hop
		if before, after, ok := strings.Cut(hop, "@"); ok {
			username, address = before, after
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return "", nil, fmt.Errorf("invalid jump address: %w", err)
		}
		number, err := strconv.ParseInt(port, 10, 64)
		if err != nil || !validation.IsValidPort(number) || !validation.IsValidHostReference(host) {
			return "", nil, fmt.Errorf("invalid jump host or port")
		}
		usernameValue, err := sshConfigValue(username)
		if err != nil {
			return "", nil, err
		}
		if err := CheckAndUpdateHostKey(db, user, host, number); err != nil {
			return "", nil, err
		}
		alias := fmt.Sprintf("gobastion-hop-%s-%d", uuid.NewString(), i)
		fmt.Fprintf(&content, "Host %s\n HostName %s\n Port %d\n User %s\n", alias, host, number, usernameValue)
		aliases = append(aliases, alias)
	}
	file, err := os.CreateTemp(filepath.Dir(key), "ssh-jumps-*.conf")
	if err != nil {
		return "", nil, err
	}
	if _, err := file.WriteString(content.String()); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return "", nil, err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(file.Name())
		return "", nil, err
	}
	return file.Name(), aliases, nil
}
