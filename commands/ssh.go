package commands

import (
	"errors"
	"fmt"
	"net"
	"goBastion/utils/sshConnector"
	"goBastion/utils/tcpProxy"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"goBastion/models"
	"goBastion/utils"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// SSHConnect resolves the target and establishes an SSH connection through the bastion.
func SSHConnect(db *gorm.DB, user models.User, logger slog.Logger, params string) error {
	sshUser, sshHost, sshPort, remoteCmd, err := parseSSHCommand(params)
	if err != nil {
		return fmt.Errorf("invalid SSH command: %v", err)
	}

	sshFrom := strings.Split(os.Getenv("SSH_CLIENT"), " ")[0]
	hostname, _ := os.Hostname()

	log := logger.With(
		slog.String("user", user.Username),
		slog.String("from", sshFrom),
		slog.String("target_user", sshUser),
		slog.String("target_host", sshHost),
		slog.String("target_port", sshPort),
	)

	log.Info("ssh connection attempt")

	forcedHost, err := resolveForcedHost(db, user, sshHost)
	if err != nil {
		log.Error("alias resolution failed", slog.String("error", err.Error()))
		return fmt.Errorf("error searching host: %v", err)
	}

	loginHostname := user.Username + "@" + hostname
	fmt.Printf("⚡ %s → %s → %s ...\n\n", utils.FgBlueB(sshFrom), loginHostname, utils.FgYellow(sshUser+"@"+sshHost+":"+sshPort))

	if forcedHost.Host != "" {
		log.Info("alias resolved", slog.String("alias", sshHost), slog.String("resolved_host", forcedHost.Host))
		sshHost = forcedHost.Host
	}

	accesses, err := accessFilter(db, user, sshUser, sshHost, sshPort)
	if err != nil {
		log.Warn("ssh access denied", slog.String("error", err.Error()))
		return fmt.Errorf("%v\n", err)
	}

	if len(accesses) > 0 {
		fmt.Printf("Trying keys ...\n")
		for _, access := range accesses {
			if access.KeyId == uuid.Nil {
				fmt.Printf("- %s - Skip empty egress key.\n", access.Source)
				continue
			}
			fmt.Printf("- "+utils.BgGreenB("%s")+" - ID: %s "+utils.FgBlueB("%s-%d")+" [%s]...\n", access.Source, access.KeyId.String(), strings.ToUpper(access.KeyType), access.KeySize, access.KeyUpdatedAt.Format("2006-01-02"))

			if access.Type == "self" {
				db.Model(&models.SelfAccess{}).Where("id = ?", access.ID).Update("last_connection", time.Now())
			} else {
				db.Model(&models.GroupAccess{}).Where("id = ?", access.ID).Update("last_connection", time.Now())
			}

			log.Info("ssh connection started", slog.String("source", access.Source), slog.String("key_id", access.KeyId.String()))
			access.RemoteCmd = remoteCmd
			err = sshConnector.SshConnection(db, user, access)
			if err != nil {
				log.Error("ssh connection failed", slog.String("source", access.Source), slog.String("error", err.Error()))
				fmt.Printf("Key verification failed: %v\n", err)
			} else {
				log.Info("ssh connection closed", slog.String("source", access.Source))
			}
			return nil
		}
	}

	log.Warn("ssh connection blocked", slog.String("reason", "no valid key found"))
	fmt.Println("No valid key found for the user or group.")
	return nil
}

// accessFilter returns the list of access rights matching username, host and port for the user.
func accessFilter(DB *gorm.DB, user models.User, username, host, port string) ([]models.AccessRight, error) {
	portInt, err := strconv.ParseInt(port, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid port value: %v", err)
	}

	clientIP := strings.Split(os.Getenv("SSH_CLIENT"), " ")[0]
	now := time.Now()

	var selfAccessList []models.SelfAccess
	var groupAccessList []models.GroupAccess

	// ADMIN LOGIC
	if user.Role == models.RoleAdmin {
		if err = DB.Where("username = ? AND server = ? AND port = ? AND (expires_at IS NULL OR expires_at > ?)", username, host, portInt, now).
			Find(&selfAccessList).Error; err != nil {
			return nil, fmt.Errorf("error retrieving self access for admin: %v", err)
		}
		if err = DB.Where("username = ? AND server = ? AND port = ? AND (expires_at IS NULL OR expires_at > ?)", username, host, portInt, now).
			Preload("Group").
			Find(&groupAccessList).Error; err != nil {
			return nil, fmt.Errorf("error retrieving group access for admin: %v", err)
		}

		if len(groupAccessList) > 0 {
			ga := groupAccessList[0]
			if !ipAllowed(clientIP, ga.AllowedFrom) {
				return nil, errors.New("⛔ " + utils.BgRedB("Access denied: your IP "+clientIP+" is not allowed for this access"))
			}
			var groupEgressKey models.GroupEgressKey
			if err = DB.Where("group_id = ?", ga.GroupID).
				First(&groupEgressKey).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("error retrieving group egress key for group %v: %v", ga.GroupID, err)
			}
			access := models.AccessRight{
				Source:         "admin-group-" + ga.Group.Name,
				ID:             ga.ID,
				Username:       ga.Username,
				Server:         ga.Server,
				Port:           ga.Port,
				Type:           "group",
				KeyId:          groupEgressKey.ID,
				KeyType:        groupEgressKey.Type,
				KeySize:        groupEgressKey.Size,
				KeyFingerprint: groupEgressKey.Fingerprint,
				KeyUpdatedAt:   groupEgressKey.UpdatedAt,
				PublicKey:      groupEgressKey.PubKey,
				PrivateKey:     groupEgressKey.PrivKey,
			}
			return []models.AccessRight{access}, nil
		} else if len(selfAccessList) > 0 {
			sa := selfAccessList[0]
			if !ipAllowed(clientIP, sa.AllowedFrom) {
				return nil, errors.New("⛔ " + utils.BgRedB("Access denied: your IP "+clientIP+" is not allowed for this access"))
			}
			var selfEgressKey models.SelfEgressKey
			if err = DB.Where("user_id = ?", sa.UserID).
				First(&selfEgressKey).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
				return nil, fmt.Errorf("error retrieving self egress key for user %v: %v", sa.UserID, err)
			}
			access := models.AccessRight{
				ID:             sa.ID,
				Source:         "admin-account-" + sa.Username,
				Username:       sa.Username,
				Server:         sa.Server,
				Port:           sa.Port,
				Type:           "self",
				KeyId:          selfEgressKey.ID,
				KeyType:        selfEgressKey.Type,
				KeySize:        selfEgressKey.Size,
				KeyFingerprint: selfEgressKey.Fingerprint,
				KeyUpdatedAt:   selfEgressKey.UpdatedAt,
				PublicKey:      selfEgressKey.PubKey,
				PrivateKey:     selfEgressKey.PrivKey,
			}
			return []models.AccessRight{access}, nil
		} else {
			return nil, errors.New("⛔ " + utils.BgRedB("Access denied for "+user.Username+" to "+username+"@"+host+":"+port))
		}
	}

	// USER LOGIC
	if err = DB.Where("user_id = ? AND username = ? AND server = ? AND port = ? AND (expires_at IS NULL OR expires_at > ?)", user.ID, username, host, portInt, now).
		Find(&selfAccessList).Error; err != nil {
		return nil, fmt.Errorf("error retrieving self access: %v", err)
	}

	var userGroups []models.UserGroup
	if err = DB.Where("user_id = ?", user.ID).
		Preload("Group").
		Find(&userGroups).Error; err != nil {
		return nil, fmt.Errorf("error retrieving user groups: %v", err)
	}

	groupIDs := make([]uuid.UUID, 0, len(userGroups))
	for _, ug := range userGroups {
		groupIDs = append(groupIDs, ug.GroupID)
	}

	if len(groupIDs) > 0 {
		if err = DB.Where("group_id IN ? AND username = ? AND server = ? AND port = ? AND (expires_at IS NULL OR expires_at > ?)", groupIDs, username, host, portInt, now).
			Preload("Group").
			Find(&groupAccessList).Error; err != nil {
			return nil, fmt.Errorf("error retrieving group access: %v", err)
		}
	}

	if len(groupAccessList) > 0 {
		ga := groupAccessList[0]
		if !ipAllowed(clientIP, ga.AllowedFrom) {
			return nil, errors.New("⛔ " + utils.BgRedB("Access denied: your IP "+clientIP+" is not allowed for this access"))
		}
		var groupEgressKey models.GroupEgressKey
		if err = DB.Where("group_id = ?", ga.GroupID).
			First(&groupEgressKey).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("error retrieving group egress key for group %v: %v", ga.GroupID, err)
		}
		access := models.AccessRight{
			ID:             ga.ID,
			Source:         "group-" + ga.Group.Name,
			Username:       ga.Username,
			Server:         ga.Server,
			Port:           ga.Port,
			Type:           "group",
			KeyId:          groupEgressKey.ID,
			KeyType:        groupEgressKey.Type,
			KeySize:        groupEgressKey.Size,
			KeyFingerprint: groupEgressKey.Fingerprint,
			KeyUpdatedAt:   groupEgressKey.UpdatedAt,
			PublicKey:      groupEgressKey.PubKey,
			PrivateKey:     groupEgressKey.PrivKey,
		}
		return []models.AccessRight{access}, nil
	} else if len(selfAccessList) > 0 {
		sa := selfAccessList[0]
		if !ipAllowed(clientIP, sa.AllowedFrom) {
			return nil, errors.New("⛔ " + utils.BgRedB("Access denied: your IP "+clientIP+" is not allowed for this access"))
		}
		var selfEgressKey models.SelfEgressKey
		if err = DB.Where("user_id = ?", sa.UserID).
			First(&selfEgressKey).Error; err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("error retrieving self egress key for user %v: %v", sa.UserID, err)
		}
		access := models.AccessRight{
			ID:             sa.ID,
			Source:         "account-" + sa.Username,
			Username:       sa.Username,
			Server:         sa.Server,
			Port:           sa.Port,
			Type:           "self",
			KeyId:          selfEgressKey.ID,
			KeyType:        selfEgressKey.Type,
			KeySize:        selfEgressKey.Size,
			KeyFingerprint: selfEgressKey.Fingerprint,
			KeyUpdatedAt:   selfEgressKey.UpdatedAt,
			PublicKey:      selfEgressKey.PubKey,
			PrivateKey:     selfEgressKey.PrivKey,
		}
		return []models.AccessRight{access}, nil
	} else {
		return nil, errors.New("⛔ " + utils.BgRedB("Access denied for "+user.Username+" to "+username+"@"+host+":"+port))
	}
}

// ipAllowed checks whether clientIP is permitted by an allowedFrom CIDR list.
// Empty allowedFrom means unrestricted.
func ipAllowed(clientIP, allowedFrom string) bool {
	if allowedFrom == "" || clientIP == "" {
		return true
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return true // can't parse client IP - allow and log at connection level
	}
	for _, cidr := range strings.Split(allowedFrom, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// parseSSHCommand parses an SSH command string into user, host, port, and optional remote command.
// Supported formats:
//   user@host
//   user@host:port
//   user@host -p port
//   user@host command args...
//   user@host -p port command args...
func parseSSHCommand(command string) (user, host, port, remoteCmd string, err error) {
	command = strings.TrimSpace(command)
	tokens := strings.Fields(command)
	if len(tokens) == 0 {
		return "", "", "", "", errors.New("empty command")
	}

	// First token must be [user@]host or [user@]host:port
	target := tokens[0]
	rest := tokens[1:]

	// Extract user and host[:port]
	if idx := strings.Index(target, "@"); idx >= 0 {
		user = target[:idx]
		target = target[idx+1:]
	}
	if idx := strings.LastIndex(target, ":"); idx >= 0 {
		// host:port form
		host = target[:idx]
		port = target[idx+1:]
	} else {
		host = target
	}

	// Parse remaining tokens for -p flag and remote command
	for i := 0; i < len(rest); i++ {
		if rest[i] == "-p" && i+1 < len(rest) {
			port = rest[i+1]
			i++
		} else {
			remoteCmd = strings.Join(rest[i:], " ")
			break
		}
	}

	if port == "" {
		port = "22"
	}
	if user == "" {
		user = "root"
	}
	if host == "" {
		return "", "", "", "", errors.New("invalid format: missing host")
	}
	return user, host, port, remoteCmd, nil
}

// resolveForcedHost resolves an alias hostname to its underlying access target.
func resolveForcedHost(db *gorm.DB, user models.User, forcedHostname string) (models.Aliases, error) {
	host := models.Aliases{}

	err := db.
		Where("LOWER(resolve_from) = ? AND user_id = ?", strings.ToLower(forcedHostname), user.ID).
		First(&host).Error
	if err == nil {
		return host, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return host, fmt.Errorf("error retrieving user host: %v", err)
	}

	var groupIDs []uuid.UUID
	err = db.Model(&models.UserGroup{}).
		Where("user_id = ?", user.ID).
		Pluck("group_id", &groupIDs).Error
	if err != nil {
		return host, fmt.Errorf("error retrieving user groups: %v", err)
	}

	if len(groupIDs) == 0 {
		return host, nil
	}

	err = db.
		Where("LOWER(resolve_from) = ? AND group_id IN (?)", strings.ToLower(forcedHostname), groupIDs).
		First(&host).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return host, nil
	} else if err != nil {
		return host, fmt.Errorf("error retrieving group host: %v", err)
	}

	return host, nil
}

// TCPProxy establishes a raw TCP tunnel to host:port after verifying the user has at least
// one access entry for that host. Used for transparent SCP/SFTP/rsync passthrough.
// Client-side config example:
//
//	Host target
//	  ProxyCommand ssh -p 2222 %r@bastion -W %h:%p
func TCPProxy(db *gorm.DB, user models.User, logger slog.Logger, host, port string) error {
	portInt, err := strconv.ParseInt(port, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid port: %v", err)
	}

	sshFrom := strings.Split(os.Getenv("SSH_CLIENT"), " ")[0]
	log := logger.With(
		slog.String("user", user.Username),
		slog.String("from", sshFrom),
		slog.String("target_host", host),
		slog.String("target_port", port),
	)

	if !hasAnyAccessToHost(db, user, host, portInt) {
		log.Warn("tcp proxy access denied")
		return fmt.Errorf("⛔ Access denied for %s to %s:%s", user.Username, host, port)
	}

	log.Info("tcp proxy started")
	if err := tcpProxy.Proxy(host, port); err != nil {
		log.Error("tcp proxy error", slog.String("error", err.Error()))
		return err
	}
	log.Info("tcp proxy closed")
	return nil
}

// hasAnyAccessToHost returns true if the user has any self or group access entry for the given
// host and port (regardless of the remote username). Used by the TCP proxy access check.
func hasAnyAccessToHost(db *gorm.DB, user models.User, host string, port int64) bool {
	var count int64

	if user.Role == models.RoleAdmin {
		// Admin can use any access entry (self or group) from any user for this host.
		// Mirrors the behaviour of accessFilter which queries without user_id filter.
		db.Model(&models.SelfAccess{}).Where("server = ? AND port = ?", host, port).Count(&count)
		if count > 0 {
			return true
		}
		db.Model(&models.GroupAccess{}).Where("server = ? AND port = ?", host, port).Count(&count)
		return count > 0
	}

	db.Model(&models.SelfAccess{}).
		Where("user_id = ? AND server = ? AND port = ?", user.ID, host, port).
		Count(&count)
	if count > 0 {
		return true
	}

	var groupIDs []uuid.UUID
	db.Model(&models.UserGroup{}).Where("user_id = ?", user.ID).Pluck("group_id", &groupIDs)
	if len(groupIDs) == 0 {
		return false
	}

	db.Model(&models.GroupAccess{}).
		Where("group_id IN ? AND server = ? AND port = ?", groupIDs, host, port).
		Count(&count)
	return count > 0
}
