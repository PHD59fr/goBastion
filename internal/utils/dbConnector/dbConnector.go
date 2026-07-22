package dbConnector

import (
	"compress/gzip"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"log/slog"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/cryptokey"
	"goBastion/internal/utils/validation"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	scoreDBAdminOverride = 0
	scoreDBGroupWildcard = 1
	scoreDBSelfWildcard  = 2
	scoreDBGroupExact    = 3
	scoreDBSelfExact     = 4
)

type dbCandidate struct {
	access  models.DBAccessRight
	score   int
	expired bool
}

// Connect launches a database client wrapped in ttyrec for session recording.
func Connect(db *gorm.DB, user models.User, access models.DBAccessRight) error {
	runCtx := context.Background()
	if d := config.Get().Session.MaxSessionDuration; d > 0 {
		var cancel context.CancelFunc
		runCtx, cancel = context.WithTimeout(runCtx, time.Duration(d))
		defer cancel()
	}

	clientBin := validation.DBProtocolClient(access.Protocol)
	if clientBin == "" {
		return fmt.Errorf("unsupported database protocol: %s", access.Protocol)
	}

	clientArgs := buildClientArgs(access)

	if !config.Get().TTYRec.Enabled {
		cmd := exec.CommandContext(runCtx, clientBin, clientArgs...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("db client execution error: %v", err)
		}
		return nil
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	sessionID := os.Getenv("GOB_SESSION_ID")
	safeUser := strings.ReplaceAll(user.Username, "/", "_")
	safeUser = strings.ReplaceAll(safeUser, "..", "_")
	safeHost := strings.ReplaceAll(access.Host, "/", "_")
	safeHost = strings.ReplaceAll(safeHost, "..", "_")
	dir := fmt.Sprintf("%s/%s/%s/", config.Get().Paths.TtyrecDir, safeUser, safeHost)
	if err := os.MkdirAll(dir, 02770); err != nil {
		return fmt.Errorf("error creating ttyrec dir: %w", err)
	}

	filenameSuffix := ""
	if sessionID != "" {
		filenameSuffix = "_sid-" + sessionID
	}
	ttyrecFile := fmt.Sprintf("%s%s_%s_%s_%s%s.ttyrec", dir, access.Protocol, safeHost, timestamp, access.Protocol, filenameSuffix)
	ttyrecGzFile := ttyrecFile + ".gz"

	tmpGz, err := os.CreateTemp(dir, "*.gz.tmp")
	if err != nil {
		return fmt.Errorf("error creating temp gzip file: %w", err)
	}
	if err = tmpGz.Chmod(0640); err != nil {
		_ = tmpGz.Close()
		return fmt.Errorf("setting recording permissions: %w", err)
	}
	tmpGzPath := tmpGz.Name()
	defer func() { _ = os.Remove(tmpGzPath) }()
	gzipWriter := gzip.NewWriter(tmpGz)

	defer func() { _ = os.Remove(ttyrecFile) }()

	ttyrecArgs := []string{"-f", ttyrecFile, "--", clientBin}
	ttyrecArgs = append(ttyrecArgs, clientArgs...)
	cmd := exec.CommandContext(runCtx, "ttyrec", ttyrecArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	ttyrecOut, err := os.Open(ttyrecFile)
	if err == nil {
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 32*1024)
			for {
				n, rErr := ttyrecOut.Read(buf)
				if n > 0 {
					_, _ = gzipWriter.Write(buf[:n])
				}
				if rErr != nil {
					_ = gzipWriter.Close()
					_ = ttyrecOut.Close()
					return
				}
			}
		}()
		defer func() { <-done }()
	}

	cmdErr := cmd.Run()

	if ttyrecOut != nil {
		_ = ttyrecOut.Close()
	}
	_ = gzipWriter.Close()
	_ = tmpGz.Close()

	if err := os.Rename(tmpGzPath, ttyrecGzFile); err != nil {
		return fmt.Errorf("error renaming gzip file: %w", err)
	}
	tmpGzPath = ""

	if cmdErr != nil {
		switch cmdErr.Error() {
		case "exit status 100", "exit status 130", "signal: interrupt":
			return nil
		}
		return fmt.Errorf("db client ttyrec execution error: %v", cmdErr)
	}

	return nil
}

// ResolveTarget finds a matching DBAccessRight for the given target.
// Supports: host, user@host, host:port, host:port:protocol, alias
// Flags: --mysql, --pg, --mongo, --redis, --dbname <name>
// Disambiguates when multiple matches exist.
func ResolveTarget(db *gorm.DB, user models.User, target string, extraArgs ...string) (models.DBAccessRight, error) {
	dbUser, host, port, protocol, database := parseDBTarget(target, extraArgs)

	// If no host parsed, try alias resolution
	if host == "" {
		alias, err := resolveDBAlias(db, user, target)
		if err != nil {
			return models.DBAccessRight{}, err
		}
		if alias.ID != uuid.Nil {
			host = alias.Host
			port = alias.Port
			protocol = alias.Protocol
		}
	}

	if host == "" {
		return models.DBAccessRight{}, fmt.Errorf("no database access found for '%s'", target)
	}

	accesses, err := dbAccessFilter(db, user, host, port, protocol)
	if err != nil {
		return models.DBAccessRight{}, err
	}
	if len(accesses) == 0 {
		return models.DBAccessRight{}, fmt.Errorf("no database access found for '%s'", target)
	}

	// Filter by database name if specified
	if database != "" {
		var filtered []models.DBAccessRight
		for _, a := range accesses {
			if a.Database == database {
				filtered = append(filtered, a)
			}
		}
		if len(filtered) == 0 {
			return models.DBAccessRight{}, fmt.Errorf("no database '%s' found on '%s'", database, target)
		}
		accesses = filtered
	}

	// Filter by username if specified (user@host format)
	if dbUser != "" {
		var filtered []models.DBAccessRight
		for _, a := range accesses {
			if strings.EqualFold(a.Username, dbUser) {
				filtered = append(filtered, a)
			}
		}
		if len(filtered) == 0 {
			return models.DBAccessRight{}, fmt.Errorf("no database access with user '%s' on '%s'", dbUser, target)
		}
		accesses = filtered
	}

	if len(accesses) == 1 {
		return accesses[0], nil
	}

	// Multiple matches remain — disambiguate
	return disambiguateDBAccess(target, accesses, protocol, dbUser, database)
}

// disambiguateDBAccess returns a helpful error when multiple DB accesses match.
func disambiguateDBAccess(target string, accesses []models.DBAccessRight, protocol, dbUser, database string) (models.DBAccessRight, error) {
	// Check: multiple protocols?
	if protocol == "" {
		seen := make(map[string]bool)
		var protocols []string
		for _, a := range accesses {
			if !seen[a.Protocol] {
				seen[a.Protocol] = true
				protocols = append(protocols, a.Protocol)
			}
		}
		if len(protocols) > 1 {
			var hints []string
			for _, p := range protocols {
				hints = append(hints, fmt.Sprintf("  bastion --db %s --%s", target, protoFlag(p)))
			}
			return models.DBAccessRight{}, fmt.Errorf("multiple database types found for '%s', please specify one:\n%s",
				target, strings.Join(hints, "\n"))
		}
	}

	// Check: multiple users?
	if dbUser == "" {
		seen := make(map[string]bool)
		var users []string
		for _, a := range accesses {
			if !seen[a.Username] {
				seen[a.Username] = true
				users = append(users, a.Username)
			}
		}
		if len(users) > 1 {
			var hints []string
			for _, u := range users {
				hints = append(hints, fmt.Sprintf("  bastion --db %s@%s", u, target))
			}
			return models.DBAccessRight{}, fmt.Errorf("multiple database users found for '%s', please specify one:\n%s",
				target, strings.Join(hints, "\n"))
		}
	}

	// Check: multiple database names?
	if database == "" {
		seen := make(map[string]bool)
		var dbs []string
		for _, a := range accesses {
			if a.Database != "" && !seen[a.Database] {
				seen[a.Database] = true
				dbs = append(dbs, a.Database)
			}
		}
		if len(dbs) > 1 {
			var hints []string
			for _, d := range dbs {
				hints = append(hints, fmt.Sprintf("  bastion --db %s --dbname %s", target, d))
			}
			return models.DBAccessRight{}, fmt.Errorf("multiple databases found on '%s', please specify one:\n%s",
				target, strings.Join(hints, "\n"))
		}
	}

	return models.DBAccessRight{}, fmt.Errorf("multiple matching database accesses found for '%s' (this should not happen)", target)
}

// protoFlag returns the CLI flag name for a protocol.
func protoFlag(p string) string {
	switch p {
	case "mysql":
		return "mysql"
	case "postgres":
		return "pg"
	case "mongo":
		return "mongo"
	case "redis":
		return "redis"
	default:
		return p
	}
}

// parseDBTarget parses a target string into user, host, port, protocol.
// Formats: "host", "user@host", "host:port", "host:port:protocol", "user@host:port:protocol"
// Also supports --dbname, --mysql, --pg, --mongo, --redis flags in args.
func parseDBTarget(target string, args []string) (dbUser, host string, port int64, protocol, database string) {
	// Check for flags in args
	for i, a := range args {
		switch {
		case a == "--mysql":
			protocol = "mysql"
		case a == "--pg" || a == "--postgres":
			protocol = "postgres"
		case a == "--mongo":
			protocol = "mongo"
		case a == "--redis":
			protocol = "redis"
		case (a == "--dbname" || a == "--db") && i+1 < len(args):
			database = args[i+1]
		case strings.HasPrefix(a, "--dbname="):
			database = strings.TrimPrefix(a, "--dbname=")
		case strings.HasPrefix(a, "--db="):
			database = strings.TrimPrefix(a, "--db=")
		}
	}

	// Parse user@host:port:protocol
	connectStr := target
	if idx := strings.Index(target, "@"); idx >= 0 {
		dbUser = target[:idx]
		connectStr = target[idx+1:]
	}

	parts := strings.Split(connectStr, ":")
	if len(parts) >= 1 {
		host = parts[0]
	}
	if len(parts) >= 2 {
		if p, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
			port = p
		}
	}
	if len(parts) >= 3 {
		protocol = parts[2]
	}
	return
}

// resolveDBAlias resolves a database alias (personal first, then group).
func resolveDBAlias(db *gorm.DB, user models.User, target string) (models.DatabaseAlias, error) {
	var alias models.DatabaseAlias

	// Tier 1: personal alias
	if err := db.Where("LOWER(resolve_from) = ? AND user_id = ? AND deleted_at IS NULL",
		strings.ToLower(target), user.ID).First(&alias).Error; err == nil {
		return alias, nil
	}

	// Tier 2: group aliases
	var userGroupIDs []uuid.UUID
	db.Model(&models.UserGroup{}).Where("user_id = ?", user.ID).Pluck("group_id", &userGroupIDs)
	if len(userGroupIDs) > 0 {
		if err := db.Where("LOWER(resolve_from) = ? AND group_id IN (?) AND deleted_at IS NULL",
			strings.ToLower(target), userGroupIDs).First(&alias).Error; err == nil {
			return alias, nil
		}
	}

	return models.DatabaseAlias{}, nil
}

// dbAccessFilter resolves database access rights following the SSH priority scoring system.
func dbAccessFilter(db *gorm.DB, user models.User, host string, port int64, protocol string) ([]models.DBAccessRight, error) {
	now := time.Now()
	var candidates []dbCandidate

	// Step 1: Self accesses
	var selfAccesses []models.SelfDBAccess
	db.Where(
		"user_id = ? AND (port = ? OR ? = 0) AND (host = ? OR ? = '') AND (expires_at IS NULL OR expires_at > ?)",
		user.ID, port, port, host, host, host, now,
	).Find(&selfAccesses)
	for _, a := range selfAccesses {
		if protocol != "" && a.Protocol != protocol {
			continue
		}
		score := scoreDBSelfWildcard
		if a.Host == host && (port == 0 || a.Port == port) {
			score = scoreDBSelfExact
		}
		candidates = append(candidates, dbCandidate{
			access:  buildSelfDBAccessRight("account-"+user.Username, a),
			score:   score,
			expired: a.ExpiresAt != nil && a.ExpiresAt.Before(now),
		})
	}

	// Step 2: Group accesses
	var userGroups []models.UserGroup
	db.Where("user_id = ?", user.ID).Find(&userGroups)
	if len(userGroups) > 0 {
		var groupIDs []uuid.UUID
		for _, ug := range userGroups {
			groupIDs = append(groupIDs, ug.GroupID)
		}
		var groupAccesses []models.GroupDBAccess
		db.Where(
			"group_id IN (?) AND (port = ? OR ? = 0) AND (host = ? OR ? = '') AND (expires_at IS NULL OR expires_at > ?)",
			groupIDs, port, port, host, host, host, now,
		).Find(&groupAccesses)
		for _, a := range groupAccesses {
			if protocol != "" && a.Protocol != protocol {
				continue
			}
			score := scoreDBGroupWildcard
			if a.Host == host && (port == 0 || a.Port == port) {
				score = scoreDBGroupExact
			}
			candidates = append(candidates, dbCandidate{
				access:  buildGroupDBAccessRight(db, a),
				score:   score,
				expired: a.ExpiresAt != nil && a.ExpiresAt.Before(now),
			})
		}
	}

	// Step 3: Admin override
	if len(candidates) == 0 && user.IsAdmin() {
		var allSelf []models.SelfDBAccess
		db.Where("(host = ? OR ? = '') AND (port = ? OR ? = 0)", host, host, port, port).Find(&allSelf)
		for _, a := range allSelf {
			if protocol != "" && a.Protocol != protocol {
				continue
			}
			candidates = append(candidates, dbCandidate{
				access:  buildSelfDBAccessRight("admin-override", a),
				score:   scoreDBAdminOverride,
				expired: a.ExpiresAt != nil && a.ExpiresAt.Before(now),
			})
		}
	}

	// Step 4: Sort by priority (highest first)
	for i := range candidates {
		for j := range candidates {
			if candidates[j].score > candidates[i].score {
				candidates[i], candidates[j] = candidates[j], candidates[i]
			}
		}
	}

	// Step 5: Filter expired and check IP allowlist
	var results []models.DBAccessRight
	for _, c := range candidates {
		if c.expired {
			continue
		}
		if c.access.AllowedFrom != "" {
			clientIP := os.Getenv("SSH_CLIENT")
			if clientIP == "" {
				clientIP = os.Getenv("SSH_CONNECTION")
			}
			if clientIP != "" {
				parts := strings.Fields(clientIP)
				if len(parts) > 0 && !ipAllowed(parts[0], c.access.AllowedFrom) {
					continue
				}
			}
		}
		results = append(results, c.access)
	}

	return results, nil
}

func buildSelfDBAccessRight(source string, a models.SelfDBAccess) models.DBAccessRight {
	password := ""
	if a.Password != "" {
		if decrypted, err := cryptokey.Decrypt(a.Password); err == nil {
			password = decrypted
		} else {
			slog.Warn("db_password_decrypt_failed", slog.String("host", a.Host), slog.Any("error", err))
		}
	}
	return models.DBAccessRight{
		ID:          a.ID,
		Source:      source,
		Host:        a.Host,
		Port:        a.Port,
		Protocol:    a.Protocol,
		Username:    a.Username,
		Password:    password,
		Database:    a.Database,
		AllowedFrom: a.AllowedFrom,
	}
}

func buildGroupDBAccessRight(db *gorm.DB, a models.GroupDBAccess) models.DBAccessRight {
	password := ""
	if a.Password != "" {
		if decrypted, err := cryptokey.Decrypt(a.Password); err == nil {
			password = decrypted
		} else {
			slog.Warn("db_password_decrypt_failed", slog.String("host", a.Host), slog.Any("error", err))
		}
	}
	var group models.Group
	db.Where("id = ?", a.GroupID).First(&group)
	return models.DBAccessRight{
		ID:          a.ID,
		Source:      "group-" + group.Name,
		Host:        a.Host,
		Port:        a.Port,
		Protocol:    a.Protocol,
		Username:    a.Username,
		Password:    password,
		Database:    a.Database,
		AllowedFrom: a.AllowedFrom,
		MFARequired: group.MFARequired,
	}
}

// buildClientArgs constructs the command-line arguments for the database client.
func buildClientArgs(access models.DBAccessRight) []string {
	var args []string

	switch access.Protocol {
	case "mysql":
		args = append(args,
			"-h", access.Host,
			"-P", strconv.FormatInt(access.Port, 10),
			"-u", access.Username,
			"--protocol=tcp",
		)
		if access.Password != "" {
			args = append(args, "-p"+access.Password)
		}
		if access.Database != "" {
			args = append(args, access.Database)
		}

	case "postgres":
		args = append(args,
			"-h", access.Host,
			"-p", strconv.FormatInt(access.Port, 10),
			"-U", access.Username,
		)
		if access.Database != "" {
			args = append(args, "-d", access.Database)
		}

	case "mongo":
		connStr := fmt.Sprintf("mongodb://%s:%d", access.Host, access.Port)
		if access.Database != "" {
			connStr += "/" + access.Database
		}
		args = append(args, connStr)
		if access.Username != "" {
			args = append(args, "-u", access.Username)
		}

	case "redis":
		args = append(args,
			"-h", access.Host,
			"-p", strconv.FormatInt(access.Port, 10),
		)
		if access.Password != "" {
			args = append(args, "-a", access.Password)
		}
	}

	return args
}

func ipAllowed(clientIP string, allowedFrom string) bool {
	if allowedFrom == "" {
		return true
	}
	parsedClient := net.ParseIP(clientIP)
	if parsedClient == nil {
		return false
	}
	for _, cidrStr := range strings.Split(allowedFrom, ",") {
		cidrStr = strings.TrimSpace(cidrStr)
		if cidrStr == "" {
			continue
		}
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			continue
		}
		if cidr.Contains(parsedClient) {
			return true
		}
	}
	return false
}

func tmpDirPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".tmp")
}
