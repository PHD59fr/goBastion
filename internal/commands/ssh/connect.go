package ssh

import (
	"bufio"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/cryptokey"
	"goBastion/internal/utils/sftpProxy"
	"goBastion/internal/utils/sshConnector"
	"goBastion/internal/utils/system"
	"goBastion/internal/utils/tcpProxy"
	totpUtil "goBastion/internal/utils/totp"
	"goBastion/internal/utils/validation"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Access selection priority scores. Higher score = higher priority.
// The order enforces: self-exact > group-exact > self-wildcard > group-wildcard > admin-override.
const (
	scoreAdminOverride = 0
	scoreGroupWildcard = 1
	scoreSelfWildcard  = 2
	scoreGroupExact    = 3
	scoreSelfExact     = 4
)

// accessCandidate holds a candidate access entry and its selection score.
type accessCandidate struct {
	selfAccess  *models.SelfAccess
	groupAccess *models.GroupAccess
	score       int
	reason      string
}

// Connect resolves the target and establishes an SSH connection through the bastion.
func Connect(db *gorm.DB, user models.User, logger slog.Logger, params string) error {
	// Extract -F forwarding hops before parsing the main target.
	cleanParams, hops, err := extractForwardHops(params)
	if err != nil {
		return fmt.Errorf("invalid -F hop: %w", err)
	}

	sshUser, sshHost, sshPort, remoteCmd, err := parseSSHCommand(cleanParams)
	if err != nil {
		return fmt.Errorf("invalid SSH command: %w", err)
	}

	sshFrom := system.ClientIPFromEnv()
	hostname, _ := os.Hostname()
	protocol := detectProtocol(remoteCmd)

	// ssh.enabled gates interactive SSH sessions only; SCP/RSync have their
	// own feature toggles below and SFTP is handled via a separate path.
	if protocol == "ssh" && !config.Get().SSH.Enabled {
		return fmt.Errorf("outgoing SSH connections are disabled; use SFTP or SCP instead")
	}

	// Protocol feature gates.
	switch protocol {
	case "scpupload", "scpdownload":
		if !config.Get().SCP.Enabled {
			return fmt.Errorf("⛔ SCP transfers are disabled")
		}
	case "rsync":
		if !config.Get().RSync.Enabled {
			return fmt.Errorf("⛔ Rsync transfers are disabled")
		}
	}

	log := logger.With(
		slog.String("user", user.Username),
		slog.String("from", sshFrom),
		slog.String("target_user", sshUser),
		slog.String("target_host", sshHost),
		slog.String("target_port", sshPort),
		slog.String("protocol", protocol),
	)
	if len(hops) > 0 {
		log = log.With(slog.String("jump_chain", formatHopChain(hops)))
	}

	log.Info("ssh_connect")

	forcedHost, err := resolveForcedHost(db, user, sshHost)
	if err != nil {
		log.Error("alias_resolved", slog.String("error", err.Error()))
		return validation.WrapDBError(err, "error searching host")
	}

	if forcedHost.Host != "" {
		log.Info("alias_resolved", slog.String("alias", sshHost), slog.String("to", forcedHost.Host))
		sshHost = forcedHost.Host
	}

	if sshUser == "" {
		portInt, err := strconv.ParseInt(sshPort, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid ssh port: %w", err)
		}

		resolved, ok := inferSSHUsername(db, user, sshHost, portInt)
		if !ok {
			return fmt.Errorf(
				"no SSH username could be resolved for %s:%s — specify one explicitly (e.g. user@%s)",
				sshHost, sshPort, sshHost,
			)
		}
		sshUser = resolved
	}

	// Connection policy: block target username "root" when the policy is on.
	if config.Get().DenyRootTarget.Enabled && sshUser == "root" {
		return fmt.Errorf("⛔ Connections to the 'root' target are not allowed")
	}

	loginHostname := user.Username + "@" + hostname
	// Show host:port if target username not provided; otherwise show user@host:port
	target := sshHost + ":" + sshPort
	if sshUser != "" {
		target = sshUser + "@" + sshHost + ":" + sshPort
	}
	fmt.Printf("⚡ %s → %s → %s ...\n\n", utils.FgBlueB(sshFrom), loginHostname, utils.FgYellow(target))

	accesses, err := accessFilter(db, user, sshUser, sshHost, sshPort, protocol)
	if err != nil {
		log.Warn("ssh_connect", slog.String("reason", "access_denied"), slog.String("error", err.Error()))
		return fmt.Errorf("access filter failed: %w", err)
	}

	if len(accesses) > 0 {
		fmt.Printf("Trying keys ...\n")
		var lastConnErr error
		for _, access := range accesses {
			if access.KeyId == uuid.Nil {
				fmt.Printf("- %s - Skip empty egress key.\n", access.Source)
				continue
			}
			fmt.Printf("- "+utils.BgGreenB("%s")+" - ID: %s "+utils.FgBlueB("%s-%d")+" [%s]...\n", access.Source, access.KeyId.String(), strings.ToUpper(access.KeyType), access.KeySize, access.KeyUpdatedAt.Format("2006-01-02"))

			if access.Type == "self" {
				if err := db.Model(&models.SelfAccess{}).Where("id = ?", access.ID).Update("last_connection", time.Now()).Error; err != nil {
					log.Warn("last_connection_update", slog.String("error", err.Error()))
				}
			} else {
				if err := db.Model(&models.GroupAccess{}).Where("id = ?", access.ID).Update("last_connection", time.Now()).Error; err != nil {
					log.Warn("last_connection_update", slog.String("error", err.Error()))
				}
			}

			// JIT MFA: if the group requires MFA and the user hasn't done global TOTP,
			// prompt for a TOTP code now.
			if access.MFARequired && !user.TOTPEnabled {
				if user.TOTPSecret == "" {
					fmt.Println("⛔ This group requires MFA but you have no TOTP secret configured.")
					fmt.Println("   Run selfSetupTOTP first, then ask your admin to enable JIT MFA for this group.")
					log.Warn("mfa_failure", slog.String("event", "mfa_totp"), slog.String("reason", "no totp secret"), slog.String("to", access.Source))
					return fmt.Errorf("⛔ MFA required but no TOTP secret configured")
				}
				if !promptTOTP(user, log) {
					return fmt.Errorf("⛔ MFA validation failed")
				}
			}

			log.Info("ssh_connect", slog.String("to", access.Source), slog.String("key_id", access.KeyId.String()))
			access.RemoteCmd = remoteCmd
			access.JumpHosts = formatJumpHosts(hops)
			err = sshConnector.SshConnection(db, user, access)
			if err != nil {
				log.Error("ssh_close", slog.String("to", access.Source), slog.String("error", err.Error()))
				fmt.Printf("SSH connection to %s failed: %v\n", access.Source, err)
				lastConnErr = err
				continue
			}
			log.Info("ssh_close", slog.String("to", access.Source))
			return nil
		}
		if lastConnErr != nil {
			return lastConnErr
		}
	}

	log.Warn("ssh_connect", slog.String("reason", "no_valid_key"))
	fmt.Printf("No usable SSH egress key found for %s@%s:%s.\n", sshUser, sshHost, sshPort)
	fmt.Println("Generate one with:")
	fmt.Println("  selfGenerateEgressKey --type ed25519")
	return nil
}

// inferSSHUsername resolves the SSH username to use when connecting to host:port
// without an explicit username. It queries the user's own accesses and group accesses
// using the same priority order as accessFilter. Returns ("", false) only when no
// access entry exists — the caller must then return an explicit error.
func inferSSHUsername(db *gorm.DB, user models.User, host string, port int64) (string, bool) {
	now := time.Now()

	// Self accesses first (higher priority than group).
	var sa models.SelfAccess
	if err := db.Where("user_id = ? AND server = ? AND port = ? AND (expires_at IS NULL OR expires_at > ?)",
		user.ID, host, port, now).
		Order("CASE WHEN username != '*' THEN 0 ELSE 1 END"). // exact before wildcard
		First(&sa).Error; err == nil {
		if u, ok := resolveAccessUsername(sa.Username); ok {
			return u, true
		}
	}

	// Group accesses.
	var groupIDs []uuid.UUID
	if err := db.Model(&models.UserGroup{}).Where("user_id = ?", user.ID).
		Pluck("group_id", &groupIDs).Error; err == nil && len(groupIDs) > 0 {
		var ga models.GroupAccess
		if err := db.Where("group_id IN ? AND server = ? AND port = ? AND (expires_at IS NULL OR expires_at > ?)",
			groupIDs, host, port, now).
			Order("CASE WHEN username != '*' THEN 0 ELSE 1 END").
			First(&ga).Error; err == nil {
			if u, ok := resolveAccessUsername(ga.Username); ok {
				return u, true
			}
		}
	}

	// Admin override: any access entry in the system for this host.
	if user.Role == models.RoleAdmin {
		var ga models.GroupAccess
		if err := db.Where("server = ? AND port = ? AND (expires_at IS NULL OR expires_at > ?)", host, port, now).
			First(&ga).Error; err == nil {
			if u, ok := resolveAccessUsername(ga.Username); ok {
				return u, true
			}
		}
		var sa2 models.SelfAccess
		if err := db.Where("server = ? AND port = ? AND (expires_at IS NULL OR expires_at > ?)", host, port, now).
			First(&sa2).Error; err == nil {
			if u, ok := resolveAccessUsername(sa2.Username); ok {
				return u, true
			}
		}
	}

	return "", false
}

func resolveAccessUsername(username string) (string, bool) {
	switch {
	case username == "*":
		return "root", true
	case username != "":
		return username, true
	default:
		return "", false
	}
}

// accessFilter returns the best-matching access right for the given user, target and protocol.
//
// Priority order (highest first):
//  1. User's own access, exact username match (score 4)
//  2. Group access, exact username match      (score 3)
//  3. User's own access, wildcard '*' match   (score 2)
//  4. Group access, wildcard '*' match        (score 1)
//  5. Admin override: any matching system access (score 0, admin only)
//
// Within the same score, ordering is stable (database insertion order).
func accessFilter(DB *gorm.DB, user models.User, username, host, port, protocol string) ([]models.AccessRight, error) {
	portInt, err := strconv.ParseInt(port, 10, 64)
	if err != nil {
		return nil, validation.WrapDBError(err, "error retrieving user groups")
	}

	clientIP := system.ClientIPFromEnv()
	now := time.Now()

	var candidates []accessCandidate

	// --- Self accesses (scores 2 and 4) ---
	var selfAccesses []models.SelfAccess
	if err = DB.Where(
		"user_id = ? AND (username = ? OR username = '*') AND server = ? AND port = ? "+
			"AND (expires_at IS NULL OR expires_at > ?) AND (protocol = 'ssh' OR protocol = ?)",
		user.ID, username, host, portInt, now, protocol,
	).Find(&selfAccesses).Error; err != nil {
		return nil, fmt.Errorf("error retrieving self accesses: %w", err)
	}
	for i := range selfAccesses {
		sa := &selfAccesses[i]
		score := scoreSelfWildcard
		reason := "self-wildcard"
		if sa.Username != "*" {
			score = scoreSelfExact
			reason = "self-exact"
		}
		candidates = append(candidates, accessCandidate{selfAccess: sa, score: score, reason: reason})
	}

	// --- Group accesses (scores 1 and 3) ---
	var userGroups []models.UserGroup
	if err = DB.Where("user_id = ?", user.ID).Preload("Group").Find(&userGroups).Error; err != nil {
		return nil, fmt.Errorf("error retrieving user groups: %w", err)
	}
	groupIDs := make([]uuid.UUID, 0, len(userGroups))
	groupRoles := make(map[uuid.UUID]string, len(userGroups))
	hasGuestRole := false
	for _, ug := range userGroups {
		groupIDs = append(groupIDs, ug.GroupID)
		groupRoles[ug.GroupID] = ug.Role
		if ug.Role == models.GroupRoleGuest {
			hasGuestRole = true
		}
	}

	if len(groupIDs) > 0 {
		var groupAccesses []models.GroupAccess
		if err = DB.Where(
			"group_id IN ? AND (username = ? OR username = '*') AND server = ? AND port = ? "+
				"AND (expires_at IS NULL OR expires_at > ?) AND (protocol = 'ssh' OR protocol = ?)",
			groupIDs, username, host, portInt, now, protocol,
		).Preload("Group").Find(&groupAccesses).Error; err != nil {
			return nil, validation.WrapDBError(err, "error retrieving group accesses")
		}

		// For guest-role users, collect their granular grants.
		var guestGrants []models.GroupGuestAccess
		if hasGuestRole {
			if err := DB.Where(
				"user_id = ? AND server = ? AND port = ? AND username = ? AND (expires_at IS NULL OR expires_at > ?)",
				user.ID, host, portInt, username, now,
			).Find(&guestGrants).Error; err != nil {
				return nil, fmt.Errorf("error retrieving guest grants: %w", err)
			}
			// Build a set of group IDs for which this user has a matching grant.
			grantGroupIDs := make(map[uuid.UUID]bool, len(guestGrants))
			for i := range guestGrants {
				grantGroupIDs[guestGrants[i].GroupID] = true
			}

			for i := range groupAccesses {
				ga := &groupAccesses[i]
				if groupRoles[ga.GroupID] == models.GroupRoleGuest && !grantGroupIDs[ga.GroupID] {
					continue
				}
				score := scoreGroupWildcard
				reason := "group-wildcard"
				if ga.Username != "*" {
					score = scoreGroupExact
					reason = "group-exact"
				}
				candidates = append(candidates, accessCandidate{groupAccess: ga, score: score, reason: reason})
			}
		} else {
			for i := range groupAccesses {
				ga := &groupAccesses[i]
				score := scoreGroupWildcard
				reason := "group-wildcard"
				if ga.Username != "*" {
					score = scoreGroupExact
					reason = "group-exact"
				}
				candidates = append(candidates, accessCandidate{groupAccess: ga, score: score, reason: reason})
			}
		}
	}

	// --- Admin override: any matching system access (score 0, last resort) ---
	if user.Role == models.RoleAdmin && len(candidates) == 0 {
		var adminSelfAccesses []models.SelfAccess
		if err = DB.Where(
			"(username = ? OR username = '*') AND server = ? AND port = ? "+
				"AND (expires_at IS NULL OR expires_at > ?) AND (protocol = 'ssh' OR protocol = ?)",
			username, host, portInt, now, protocol,
		).Find(&adminSelfAccesses).Error; err == nil {
			for i := range adminSelfAccesses {
				candidates = append(candidates, accessCandidate{
					selfAccess: &adminSelfAccesses[i],
					score:      scoreAdminOverride,
					reason:     "admin-override-self",
				})
			}
		}
		var adminGroupAccesses []models.GroupAccess
		if err = DB.Where(
			"(username = ? OR username = '*') AND server = ? AND port = ? "+
				"AND (expires_at IS NULL OR expires_at > ?) AND (protocol = 'ssh' OR protocol = ?)",
			username, host, portInt, now, protocol,
		).Preload("Group").Find(&adminGroupAccesses).Error; err == nil {
			for i := range adminGroupAccesses {
				candidates = append(candidates, accessCandidate{
					groupAccess: &adminGroupAccesses[i],
					score:       scoreAdminOverride,
					reason:      "admin-override-group",
				})
			}
		}
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("⛔ Access denied: no access entry found for %s@%s:%s.\n"+
			"Run: selfAddAccess --server %s --port %s --username %s",
			user.Username, username, host, host, port, username)
	}

	// Sort by score descending; stable so DB insertion order breaks ties.
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].score > candidates[j].score
	})

	best := candidates[0]

	// IP allowance check.
	allowedFrom := ""
	if best.selfAccess != nil {
		allowedFrom = best.selfAccess.AllowedFrom
	} else if best.groupAccess != nil {
		allowedFrom = best.groupAccess.AllowedFrom
	}
	if !ipAllowed(clientIP, allowedFrom) {
		src := "personal"
		if best.groupAccess != nil {
			src = best.groupAccess.Group.Name
		}
		return nil, fmt.Errorf("⛔ Access denied: your IP %s is not in the allowed CIDRs for this access entry (%s)"+
			" — contact your admin to update the --from restriction",
			clientIP, src)
	}

	// Build the AccessRight from the best candidate.
	var access models.AccessRight
	if best.selfAccess != nil {
		access, err = buildSelfAccessRight(DB, slog.Default(), *best.selfAccess, username, best.reason)
	} else {
		access, err = buildGroupAccessRight(DB, slog.Default(), *best.groupAccess, username, best.reason)
	}
	if err != nil {
		return nil, err
	}

	return []models.AccessRight{access}, nil
}

// buildGroupAccessRight constructs an AccessRight from a GroupAccess entry and its egress key.
func buildGroupAccessRight(db *gorm.DB, log *slog.Logger, ga models.GroupAccess, requestedUsername, reason string) (models.AccessRight, error) {
	var key models.GroupEgressKey
	if err := db.Where("group_id = ?", ga.GroupID).First(&key).Error; err != nil &&
		!errors.Is(err, gorm.ErrRecordNotFound) {
		return models.AccessRight{}, validation.WrapDBError(fmt.Errorf("error retrieving egress key for group %v: %w", ga.GroupID, err), "database error")
	}

	sourcePrefix := "group"
	if reason == "admin-override-group" {
		sourcePrefix = "admin-group"
	}

	access := models.AccessRight{
		ID:             ga.ID,
		Source:         sourcePrefix + "-" + ga.Group.Name,
		Username:       ga.Username,
		Server:         ga.Server,
		Port:           ga.Port,
		Type:           "group",
		KeyId:          key.ID,
		KeyType:        key.Type,
		KeySize:        key.Size,
		KeyFingerprint: key.Fingerprint,
		KeyUpdatedAt:   key.UpdatedAt,
		PublicKey:      key.PubKey,
		PrivateKey:     decryptPrivKey(key.PrivKey),
		MFARequired:    ga.Group.MFARequired,
	}
	access.Username = normalizeWildcardUsername(access.Username, requestedUsername)
	maybeReEncryptKey(db, log, "group", key.ID, key.PrivKey)
	return access, nil
}

// buildSelfAccessRight constructs an AccessRight from a SelfAccess entry and its egress key.
func buildSelfAccessRight(db *gorm.DB, log *slog.Logger, sa models.SelfAccess, requestedUsername, reason string) (models.AccessRight, error) {
	var key models.SelfEgressKey
	if err := db.Where("user_id = ?", sa.UserID).First(&key).Error; err != nil &&
		!errors.Is(err, gorm.ErrRecordNotFound) {
		return models.AccessRight{}, validation.WrapDBError(fmt.Errorf("error retrieving egress key for user %v: %w", sa.UserID, err), "database error")
	}

	sourcePrefix := "account"
	if reason == "admin-override-self" {
		sourcePrefix = "admin-account"
	}

	access := models.AccessRight{
		ID:             sa.ID,
		Source:         sourcePrefix + "-" + sa.Username,
		Username:       sa.Username,
		Server:         sa.Server,
		Port:           sa.Port,
		Type:           "self",
		KeyId:          key.ID,
		KeyType:        key.Type,
		KeySize:        key.Size,
		KeyFingerprint: key.Fingerprint,
		KeyUpdatedAt:   key.UpdatedAt,
		PublicKey:      key.PubKey,
		PrivateKey:     decryptPrivKey(key.PrivKey),
	}
	access.Username = normalizeWildcardUsername(access.Username, requestedUsername)
	maybeReEncryptKey(db, log, "self", key.ID, key.PrivKey)
	return access, nil
}

// decryptPrivKey returns the plaintext private key, handling both encrypted and legacy plaintext values.
func decryptPrivKey(raw string) string {
	return cryptokey.DecryptOrPassThrough(raw)
}

// maybeReEncryptKey re-encrypts a plaintext egress key if EGRESS_ENC_KEY is now set.
// Runs synchronously to ensure the re-encryption is persisted before the session ends.
func maybeReEncryptKey(db *gorm.DB, log *slog.Logger, keyType string, keyID uuid.UUID, currentPrivKey string) {
	if !cryptokey.Enabled() {
		return
	}
	if cryptokey.IsEncrypted(currentPrivKey) {
		return // already encrypted
	}
	encrypted, err := cryptokey.Encrypt(currentPrivKey)
	if err != nil {
		log.Warn("re_encrypt_key", slog.String("error", err.Error()))
		return
	}
	var updateErr error
	switch keyType {
	case "self":
		updateErr = db.Model(&models.SelfEgressKey{}).Where("id = ?", keyID).Update("priv_key", encrypted).Error
	case "group":
		updateErr = db.Model(&models.GroupEgressKey{}).Where("id = ?", keyID).Update("priv_key", encrypted).Error
	}
	if updateErr != nil {
		log.Warn("re_encrypt_key", slog.String("key_type", keyType), slog.String("error", updateErr.Error()))
	}
}

// normalizeWildcardUsername replaces a wildcard username '*' with the requested username.
// Falls back to "root" only when no username was explicitly requested (wildcard access,
// no username specified — the access entry grants unrestricted user access).
func normalizeWildcardUsername(stored, requested string) string {
	if stored != "*" {
		return stored
	}
	if requested != "" {
		return requested
	}
	return config.Get().Security.DefaultWildcardUsername
}

// detectProtocol inspects the remote command string to determine the access protocol.
// Returns "ssh" for interactive sessions, or the specific protocol otherwise.
func detectProtocol(remoteCmd string) string {
	if remoteCmd == "" {
		return "ssh"
	}
	cmd := strings.ToLower(strings.TrimSpace(remoteCmd))
	switch {
	case strings.HasPrefix(cmd, "scp ") && strings.Contains(cmd, " -t "):
		return "scpupload"
	case strings.HasPrefix(cmd, "scp ") && strings.Contains(cmd, " -f "):
		return "scpdownload"
	case strings.Contains(cmd, "sftp-server"):
		return "sftp"
	case strings.HasPrefix(cmd, "rsync ") || strings.Contains(cmd, "rsync --server"):
		return "rsync"
	default:
		return "ssh"
	}
}

// promptTOTP reads a TOTP code from stdin and verifies it.
// Used for JIT MFA enforcement at connection time.
func promptTOTP(user models.User, log *slog.Logger) bool {
	for attempt := 1; attempt <= config.Get().MFA.MaxAttempts; attempt++ {
		fmt.Printf("🔐 This group requires MFA. Enter TOTP code [attempt %d/%d]: ", attempt, config.Get().MFA.MaxAttempts)
		reader := bufio.NewReader(os.Stdin)
		code, err := reader.ReadString('\n')
		if err != nil {
			log.Warn("mfa_error", slog.String("event", "mfa_totp"), slog.String("user", user.Username), slog.String("error", err.Error()))
			fmt.Fprintln(os.Stderr, "⛔ Could not read TOTP code.")
			return false
		}
		if totpUtil.Verify(user.TOTPSecret, strings.TrimSpace(code)) {
			log.Info("mfa_success", slog.String("event", "mfa_totp"), slog.String("user", user.Username))
			return true
		}
		if attempt < config.Get().MFA.MaxAttempts {
			fmt.Println("⛔ Invalid TOTP code. Try again.")
			time.Sleep(time.Duration(attempt) * time.Duration(config.Get().MFA.BackoffBase)) // linear backoff
		}
	}
	log.Warn("mfa_failure", slog.String("event", "mfa_totp"), slog.String("user", user.Username))
	fmt.Println("⛔ Invalid TOTP code. Access denied.")
	return false
}

// ipAllowed checks whether clientIP is permitted by an allowedFrom CIDR list.
// Empty allowedFrom means unrestricted.
// Returns false when the clientIP cannot be parsed (fail-closed).
func ipAllowed(clientIP, allowedFrom string) bool {
	if allowedFrom == "" {
		return true
	}
	if clientIP == "" {
		return false
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		slog.Warn("ip_parse_failed", slog.String("client_ip", clientIP))
		return false
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
//
//	user@host
//	user@host:port
//	user@host -p port
//	user@host command args...
//	user@host -p port command args...
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
		port = strconv.FormatInt(config.Get().SSH.DefaultPort, 10)
	}

	portInt, err := strconv.ParseInt(port, 10, 64)
	if err != nil || !validation.IsValidPort(portInt) {
		return "", "", "", "", fmt.Errorf("invalid port: %q (must be 1-65535)", port)
	}

	// Do not default the username here. If the caller omitted a username, SSHConnect
	// will attempt to infer it from stored accesses and fall back to "root" when needed.
	if host == "" {
		return "", "", "", "", errors.New("invalid format: missing host")
	}
	return user, host, port, remoteCmd, nil
}

// splitHostRealmChain is superseded by the -F flag syntax. Kept for reference only.
// Use extractForwardHops instead.

// SSHHop represents a single intermediate bastion in a -F forwarding chain.
type SSHHop struct {
	User string
	Host string
	Port string
}

// extractForwardHops pulls out all -F user@host[:port] flags from params.
// Returns the cleaned command string (without -F tokens) and the ordered hop slice.
// Hop order follows the user-specified order (outermost to innermost).
func extractForwardHops(params string) (string, []SSHHop, error) {
	tokens := strings.Fields(params)
	var clean []string
	var hops []SSHHop
	for i := 0; i < len(tokens); i++ {
		if tokens[i] == "--via" {
			if i+1 >= len(tokens) {
				return "", nil, fmt.Errorf("--via requires an argument (user@host[:port])")
			}
			i++
			hop, err := parseHop(tokens[i])
			if err != nil {
				return "", nil, fmt.Errorf("invalid --via hop %q: %w", tokens[i], err)
			}
			hops = append(hops, hop)
		} else {
			clean = append(clean, tokens[i])
		}
	}
	return strings.Join(clean, " "), hops, nil
}

// parseHop parses "[user@]host[:port]" into an SSHHop.
func parseHop(s string) (SSHHop, error) {
	hop := SSHHop{Port: strconv.FormatInt(config.Get().SSH.DefaultPort, 10)}
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "@"); idx >= 0 {
		hop.User = s[:idx]
		s = s[idx+1:]
	}
	if idx := strings.LastIndex(s, ":"); idx >= 0 {
		hop.Host = s[:idx]
		hop.Port = s[idx+1:]
	} else {
		hop.Host = s
	}
	if hop.Host == "" {
		return SSHHop{}, fmt.Errorf("missing host")
	}
	if !validation.IsValidHost(hop.Host) {
		return SSHHop{}, fmt.Errorf("invalid host %q", hop.Host)
	}
	portInt, err := strconv.ParseInt(hop.Port, 10, 64)
	if err != nil || !validation.IsValidPort(portInt) {
		return SSHHop{}, fmt.Errorf("invalid port %q", hop.Port)
	}
	return hop, nil
}

// formatJumpHosts converts SSHHop slice to SSH -J strings ("user@host:port").
func formatJumpHosts(hops []SSHHop) []string {
	out := make([]string, len(hops))
	for i, h := range hops {
		if h.User != "" {
			out[i] = h.User + "@" + h.Host + ":" + h.Port
		} else {
			out[i] = h.Host + ":" + h.Port
		}
	}
	return out
}

// formatHopChain returns a readable chain string for logging: "user@h1:p->user@h2:p".
func formatHopChain(hops []SSHHop) string {
	parts := make([]string, len(hops))
	for i, h := range hops {
		if h.User != "" {
			parts[i] = h.User + "@" + h.Host + ":" + h.Port
		} else {
			parts[i] = h.Host + ":" + h.Port
		}
	}
	return strings.Join(parts, "->")
}

// resolveRealmHop looks up a named realm in the DB and returns its bastion endpoint.
// Used when a -F hop matches a registered realm name rather than a direct address.
func resolveRealmHop(db *gorm.DB, realmName string) (string, string, error) {
	// Realms feature disabled: refuse -F / --via jumps entirely.
	if !config.Get().Realms.Enabled {
		return "", "", fmt.Errorf("⛔ Realms are disabled")
	}
	realmName = strings.ToLower(strings.TrimSpace(realmName))
	var realm models.Realm
	if err := db.Where("name = ? AND enabled = ?", realmName, true).First(&realm).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return "", "", fmt.Errorf("⛔ Realm '%s' is not configured or disabled", realmName)
		}
		return "", "", validation.WrapDBError(err, "error resolving realm")
	}
	hopHost := strings.TrimSpace(realm.BastionHost)
	if hopHost == "" {
		hopHost = realm.Name
	}
	if !validation.IsValidHost(hopHost) {
		return "", "", fmt.Errorf("⛔ Realm '%s' has invalid bastion host '%s'", realm.Name, hopHost)
	}
	hopPort := realm.BastionPort
	if hopPort == 0 {
		hopPort = config.Get().SSH.DefaultPort
	}
	if !validation.IsValidPort(hopPort) {
		return "", "", fmt.Errorf("⛔ Realm '%s' has invalid bastion port %d", realm.Name, hopPort)
	}
	return hopHost, strconv.FormatInt(hopPort, 10), nil
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
		return host, validation.WrapDBError(err, "error retrieving user host")
	}

	var groupIDs []uuid.UUID
	err = db.Model(&models.UserGroup{}).
		Where("user_id = ?", user.ID).
		Pluck("group_id", &groupIDs).Error
	if err != nil {
		return host, validation.WrapDBError(err, "error retrieving self accesses")
	}

	if len(groupIDs) == 0 {
		return host, nil
	}

	var aliases []models.Aliases
	err = db.Preload("Group").
		Where("group_id IN (?)", groupIDs).
		Find(&aliases).Error
	if err != nil {
		return host, validation.WrapDBError(err, "error retrieving group host")
	}
	if len(aliases) == 0 {
		return host, nil
	}

	var explicitMatches []models.Aliases
	var exactMatches []models.Aliases
	for _, alias := range aliases {
		if alias.Group != nil && strings.EqualFold(alias.Group.Name+"-"+alias.ResolveFrom, forcedHostname) {
			explicitMatches = append(explicitMatches, alias)
		}
		if strings.EqualFold(alias.ResolveFrom, forcedHostname) {
			exactMatches = append(exactMatches, alias)
		}
	}

	if len(explicitMatches) == 1 {
		return explicitMatches[0], nil
	}
	if len(exactMatches) == 1 {
		return exactMatches[0], nil
	}
	if len(explicitMatches) > 1 || len(exactMatches) > 1 {
		var groups []string
		candidates := exactMatches
		if len(explicitMatches) > 1 {
			candidates = explicitMatches
		}
		for _, alias := range candidates {
			if alias.Group != nil {
				groups = append(groups, alias.Group.Name)
			}
		}
		sort.Strings(groups)
		return host, fmt.Errorf("alias '%s' is ambiguous across groups: %s; use <group>-%s", forcedHostname, strings.Join(groups, ", "), forcedHostname)
	}

	return host, nil
}

// TCPProxy establishes a raw TCP tunnel to host:port after verifying the user has at least
// one access entry for that host. Used for transparent SCP/SFTP/rsync passthrough.
// Client-side config example:
//
// Host target
//
//	ProxyCommand ssh -p 2222 %r@bastion -W %h:%p
func TCPProxy(db *gorm.DB, user models.User, logger slog.Logger, host, port string) error {
	portInt, err := strconv.ParseInt(port, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid port: %w", err)
	}

	sshFrom := system.ClientIPFromEnv()
	log := logger.With(
		slog.String("user", user.Username),
		slog.String("from", sshFrom),
		slog.String("target_host", host),
		slog.String("target_port", port),
	)

	// Resolve alias (e.g. "test" → actual hostname/IP), mirroring SSHConnect behaviour.
	forcedHost, err := resolveForcedHost(db, user, host)
	if err != nil {
		log.Error("alias_resolved", slog.String("error", err.Error()))
		return fmt.Errorf("error searching host: %w", err)
	}
	if forcedHost.Host != "" {
		log.Info("alias_resolved", slog.String("alias", host), slog.String("to", forcedHost.Host))
		host = forcedHost.Host
	}

	access, err := tcpProxyAccessFilter(db, log, user, host, portInt)
	if err != nil {
		log.Warn("tcp_proxy", slog.String("reason", "access_denied"), slog.String("error", err.Error()))
		return err
	}

	// JIT MFA enforcement for passthrough flows when the selected group policy requires it.
	if access.MFARequired && !user.TOTPEnabled {
		if user.TOTPSecret == "" {
			log.Warn("mfa_failure", slog.String("event", "mfa_totp"), slog.String("reason", "no totp secret"), slog.String("to", access.Source))
			return fmt.Errorf("⛔ This access requires MFA but no TOTP secret is configured. Run selfSetupTOTP first")
		}
		if !promptTOTP(user, log) {
			return fmt.Errorf("⛔ Access denied: MFA validation failed")
		}
	}

	log.Info("tcp_proxy")
	if err := tcpProxy.Proxy(host, port); err != nil {
		log.Error("tcp_proxy", slog.String("error", err.Error()))
		return err
	}
	log.Info("tcp_proxy_closed")
	return nil
}

// SFTPSession handles sftp passthrough by acting as a minimal SSH server on
// stdin/stdout, connecting to the target with the bastion's egress key and
// proxying the sftp subsystem — no client key on the target needed.
//
// Invoked when SSH_ORIGINAL_COMMAND = "sftp-session user@host:port".
// Client config example:
//
// Host myserver
//
//	User root
//	ProxyCommand ssh -p 2222 -- user@bastion "sftp-session root@%h:%p"
//	StrictHostKeyChecking no
//	UserKnownHostsFile /dev/null
func SFTPSession(db *gorm.DB, user models.User, logger slog.Logger, params string) error {
	sshUser, sshHost, sshPort, _, err := parseSSHCommand(params)
	if err != nil {
		return fmt.Errorf("invalid sftp-session command: %w", err)
	}

	// Connection policy: block target username "root" when the policy is on.
	if config.Get().DenyRootTarget.Enabled && sshUser == "root" {
		return fmt.Errorf("⛔ Connections to the 'root' target are not allowed")
	}

	sshFrom := system.ClientIPFromEnv()
	log := logger.With(
		slog.String("user", user.Username),
		slog.String("from", sshFrom),
		slog.String("target_user", sshUser),
		slog.String("target_host", sshHost),
		slog.String("target_port", sshPort),
	)

	// Resolve alias (e.g. "master2" → actual hostname/IP).
	forcedHost, err := resolveForcedHost(db, user, sshHost)
	if err != nil {
		log.Error("alias_resolved", slog.String("error", err.Error()))
		return fmt.Errorf("error searching host: %w", err)
	}
	if forcedHost.Host != "" {
		log.Info("alias_resolved", slog.String("alias", sshHost), slog.String("to", forcedHost.Host))
		sshHost = forcedHost.Host
	}

	accesses, err := accessFilter(db, user, sshUser, sshHost, sshPort, "sftp")
	if err != nil {
		log.Warn("sftp_session", slog.String("reason", "access_denied"), slog.String("error", err.Error()))
		return err
	}
	if len(accesses) == 0 {
		log.Warn("sftp_session", slog.String("reason", "no_matching_access"))
		return fmt.Errorf("⛔ Access denied for %s to %s@%s:%s", user.Username, sshUser, sshHost, sshPort)
	}

	access := accesses[0]
	if access.MFARequired && !user.TOTPEnabled {
		if user.TOTPSecret == "" {
			log.Warn("mfa_failure", slog.String("event", "mfa_totp"), slog.String("reason", "no totp secret"), slog.String("to", access.Source))
			return fmt.Errorf("⛔ This access requires MFA but no TOTP secret is configured. Run selfSetupTOTP first")
		}
		if !promptTOTP(user, log) {
			return fmt.Errorf("⛔ Access denied: MFA validation failed")
		}
	}

	if err := sshConnector.CheckAndUpdateHostKey(db, user, access.Server, access.Port); err != nil {
		log.Warn("sftp_session", slog.String("reason", "host_key_verification_failed"), slog.String("error", err.Error()))
		return err
	}

	log.Info("sftp_session", slog.String("to", access.Source))
	if err = sftpProxy.Proxy(access); err != nil {
		log.Error("sftp_session", slog.String("error", err.Error()))
		return err
	}
	log.Info("sftp_session_closed")
	return nil
}

// tcpProxyAccessFilter resolves a policy-compliant access entry for raw TCP proxying (-W).
// Because SSH payload is opaque in raw tunnel mode, the proxy only accepts accesses declared
// for protocol=ssh and still enforces TTL, IP CIDR and group JIT MFA policy.
func tcpProxyAccessFilter(db *gorm.DB, log *slog.Logger, user models.User, host string, port int64) (models.AccessRight, error) {
	now := time.Now()
	clientIP := system.ClientIPFromEnv()

	var selfAccesses []models.SelfAccess
	if err := db.Where(
		"user_id = ? AND server = ? AND port = ? AND protocol = 'ssh' AND (expires_at IS NULL OR expires_at > ?)",
		user.ID, host, port, now,
	).Find(&selfAccesses).Error; err != nil {
		return models.AccessRight{}, fmt.Errorf("⛔ Access denied: failed to resolve personal access: %w", err)
	}

	var groupAccesses []models.GroupAccess
	var groupIDs []uuid.UUID
	var userGroups []models.UserGroup
	if err := db.Where("user_id = ?", user.ID).Find(&userGroups).Error; err != nil {
		return models.AccessRight{}, fmt.Errorf("⛔ Access denied: failed to resolve user groups: %w", err)
	}
	groupRoles := make(map[uuid.UUID]string, len(userGroups))
	hasGuestRole := false
	for _, ug := range userGroups {
		groupIDs = append(groupIDs, ug.GroupID)
		groupRoles[ug.GroupID] = ug.Role
		if ug.Role == models.GroupRoleGuest {
			hasGuestRole = true
		}
	}
	if len(groupIDs) > 0 {
		if err := db.Where(
			"group_id IN ? AND server = ? AND port = ? AND protocol = 'ssh' AND (expires_at IS NULL OR expires_at > ?)",
			groupIDs, host, port, now,
		).Preload("Group").Find(&groupAccesses).Error; err != nil {
			return models.AccessRight{}, fmt.Errorf("⛔ Access denied: failed to resolve group access: %w", err)
		}
	}

	if len(selfAccesses) == 0 && len(groupAccesses) == 0 && user.Role == models.RoleAdmin {
		// Admin override, but still constrained by protocol, TTL and source CIDR.
		if err := db.Where(
			"server = ? AND port = ? AND protocol = 'ssh' AND (expires_at IS NULL OR expires_at > ?)",
			host, port, now,
		).Find(&selfAccesses).Error; err != nil {
			return models.AccessRight{}, fmt.Errorf("⛔ Access denied: failed to resolve admin self access: %w", err)
		}
		if err := db.Where(
			"server = ? AND port = ? AND protocol = 'ssh' AND (expires_at IS NULL OR expires_at > ?)",
			host, port, now,
		).Preload("Group").Find(&groupAccesses).Error; err != nil {
			return models.AccessRight{}, fmt.Errorf("⛔ Access denied: failed to resolve admin group access: %w", err)
		}
	}

	for _, sa := range selfAccesses {
		if !ipAllowed(clientIP, sa.AllowedFrom) {
			continue
		}
		access, err := buildSelfAccessRight(db, log, sa, "", "tcp-proxy-self")
		if err == nil {
			return access, nil
		}
	}

	// For guest-role users, collect their granular grants.
	var guestGrantGroupIDs map[uuid.UUID]bool
	if hasGuestRole {
		var guestGrants []models.GroupGuestAccess
		if err := db.Where(
			"user_id = ? AND server = ? AND port = ? AND (expires_at IS NULL OR expires_at > ?)",
			user.ID, host, port, now,
		).Find(&guestGrants).Error; err != nil {
			return models.AccessRight{}, fmt.Errorf("error retrieving guest grants: %w", err)
		}
		guestGrantGroupIDs = make(map[uuid.UUID]bool, len(guestGrants))
		for i := range guestGrants {
			guestGrantGroupIDs[guestGrants[i].GroupID] = true
		}
	}

	for _, ga := range groupAccesses {
		if hasGuestRole && groupRoles[ga.GroupID] == models.GroupRoleGuest && !guestGrantGroupIDs[ga.GroupID] {
			continue
		}
		if !ipAllowed(clientIP, ga.AllowedFrom) {
			continue
		}
		reason := "tcp-proxy-group"
		if user.Role == models.RoleAdmin && len(groupIDs) == 0 {
			reason = "admin-override-group"
		}
		access, err := buildGroupAccessRight(db, log, ga, "", reason)
		if err == nil {
			return access, nil
		}
	}

	return models.AccessRight{}, fmt.Errorf("⛔ Access denied: no eligible SSH access entry for %s to %s:%d", user.Username, host, port)
}
