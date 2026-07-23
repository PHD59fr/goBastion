package dbConnector

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/cryptokey"
	"goBastion/internal/utils/system"
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
	ttyrecPollInterval   = 100 * time.Millisecond
)

type dbCandidate struct {
	access  models.DBAccessRight
	score   int
	expired bool
}

type ResolutionDetails struct {
	RequestedTarget   string
	RequestedUser     string
	RequestedHost     string
	RequestedPort     int64
	RequestedProtocol string
	RequestedDatabase string

	AliasResolved bool
	AliasName     string
	AliasHost     string
	AliasPort     int64
	AliasProtocol string

	EffectiveUser     string
	EffectiveHost     string
	EffectivePort     int64
	EffectiveProtocol string
	EffectiveDatabase string

	AccessSource string
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
	fmt.Print(connectionMessage(user, access))

	if !config.Get().TTYRec.Enabled {
		cmd := exec.CommandContext(runCtx, clientBin, clientArgs...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("⛔ Session ended: maximum session duration reached")
			}
			return fmt.Errorf("db client execution error: %v", err)
		}
		updateLastConnection(db, access)
		return nil
	}

	timestamp := time.Now().Format("2006-01-02_15-04-05")
	sessionID := os.Getenv("GOB_SESSION_ID")
	safeUser := strings.ReplaceAll(user.Username, "/", "_")
	safeUser = strings.ReplaceAll(safeUser, "..", "_")
	safeDBUser := strings.ReplaceAll(access.Username, "/", "_")
	safeDBUser = strings.ReplaceAll(safeDBUser, "..", "_")
	if safeDBUser == "" {
		safeDBUser = "unknown"
	}
	safeHost := strings.ReplaceAll(access.Host, "/", "_")
	safeHost = strings.ReplaceAll(safeHost, "..", "_")
	safeDatabase := strings.ReplaceAll(access.Database, "/", "_")
	safeDatabase = strings.ReplaceAll(safeDatabase, "..", "_")
	dir := fmt.Sprintf("%s/%s/%s/", config.Get().Paths.TtyrecDir, safeUser, safeHost)
	if err := os.MkdirAll(dir, 02770); err != nil {
		return fmt.Errorf("error creating ttyrec dir: %w", err)
	}
	if chmodErr := os.Chmod(dir, 02770); chmodErr != nil {
		slog.Warn("ttyrec dir chmod failed", "dir", dir, "err", chmodErr)
	}

	filenameSuffix := ""
	if access.Protocol != "" {
		filenameSuffix = "_" + access.Protocol
	}
	if safeDatabase != "" {
		filenameSuffix += "_" + safeDatabase
	}
	if sessionID != "" {
		filenameSuffix += "_sid-" + sessionID
	}
	ttyrecFile := fmt.Sprintf("%s%s.%s:%d_%s%s.ttyrec", dir, safeDBUser, safeHost, access.Port, timestamp, filenameSuffix)
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

	cmdDone := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		var f *os.File
		var openErr error
		for {
			f, openErr = os.Open(ttyrecFile)
			if openErr == nil {
				break
			}
			select {
			case <-cmdDone:
				done <- nil
				return
			default:
				time.Sleep(ttyrecPollInterval)
			}
		}
		defer func() { _ = f.Close() }()

		buf := make([]byte, 4096)
		for {
			n, readErr := f.Read(buf)
			if n > 0 {
				if _, werr := gzipWriter.Write(buf[:n]); werr != nil {
					done <- fmt.Errorf("gzip write error: %w", werr)
					return
				}
			}
			if readErr == io.EOF {
				select {
				case <-cmdDone:
					for {
						n, drainErr := f.Read(buf)
						if n > 0 {
							if _, werr := gzipWriter.Write(buf[:n]); werr != nil {
								done <- fmt.Errorf("gzip write error: %w", werr)
								return
							}
						}
						if drainErr != nil {
							if drainErr == io.EOF {
								done <- nil
							} else {
								done <- fmt.Errorf("file drain error: %w", drainErr)
							}
							return
						}
					}
				default:
					time.Sleep(ttyrecPollInterval)
					continue
				}
			}
			if readErr != nil {
				done <- fmt.Errorf("file read error: %w", readErr)
				return
			}
		}
	}()

	ttyrecArgs := []string{"-f", ttyrecFile, "--", clientBin}
	ttyrecArgs = append(ttyrecArgs, clientArgs...)
	cmd := exec.CommandContext(runCtx, "ttyrec", ttyrecArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	cmdErr := cmd.Run()
	close(cmdDone)
	gzipErr := <-done
	if gzipErr != nil {
		return fmt.Errorf("error compressing ttyrec output: %w", gzipErr)
	}
	_ = gzipWriter.Close()
	_ = tmpGz.Close()

	if err := os.Rename(tmpGzPath, ttyrecGzFile); err != nil {
		return fmt.Errorf("error renaming gzip file: %w", err)
	}
	tmpGzPath = ""

	if cmdErr != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			return fmt.Errorf("⛔ Session ended: maximum session duration reached")
		}
		switch cmdErr.Error() {
		case "exit status 100", "exit status 130", "signal: interrupt":
			return nil
		}
		return fmt.Errorf("db client ttyrec execution error: %v", cmdErr)
	}

	updateLastConnection(db, access)
	return nil
}

func updateLastConnection(db *gorm.DB, access models.DBAccessRight) {
	if db == nil {
		return
	}

	now := time.Now()
	switch {
	case strings.HasPrefix(access.Source, "account-"), access.Source == "admin-override":
		_ = db.Model(&models.SelfDBAccess{}).Where("id = ?", access.ID).Update("last_connection", now).Error
	case strings.HasPrefix(access.Source, "group-"):
		_ = db.Model(&models.GroupDBAccess{}).Where("id = ?", access.ID).Update("last_connection", now).Error
	}
}

func connectionMessage(user models.User, access models.DBAccessRight) string {
	dbFrom := system.ClientIPFromEnv()
	hostname, _ := os.Hostname()
	loginHostname := user.Username + "@" + hostname

	target := access.Host
	if access.Username != "" {
		target = access.Username + "@" + target
	}
	if access.Port > 0 {
		target = fmt.Sprintf("%s:%d", target, access.Port)
	}
	if access.Database != "" {
		target += "/" + access.Database
	}
	if access.Protocol != "" {
		target += " (" + access.Protocol + ")"
	}
	return fmt.Sprintf("⚡ %s → %s → %s ...\n\n",
		utils.FgBlueB(dbFrom),
		loginHostname,
		utils.FgYellow(target),
	)
}

// ResolveTarget finds a matching DBAccessRight for the given target.
// Supports: host, user@host, host:port, host:port:protocol, alias
// Flags: --mysql, --pg, --redis, --dbname <name>
// Disambiguates when multiple matches exist.
func ResolveTarget(db *gorm.DB, user models.User, target string, extraArgs ...string) (models.DBAccessRight, error) {
	access, _, err := ResolveTargetDetailed(db, user, target, extraArgs...)
	return access, err
}

func ResolveTargetDetailed(db *gorm.DB, user models.User, target string, extraArgs ...string) (models.DBAccessRight, ResolutionDetails, error) {
	details := ResolutionDetails{RequestedTarget: target}
	details.RequestedUser, details.RequestedHost, details.RequestedPort, details.RequestedProtocol, details.RequestedDatabase = parseDBTarget(target, extraArgs)

	if shouldResolveDBAliasFirst(target) {
		alias, err := resolveDBAlias(db, user, target)
		if err != nil {
			return models.DBAccessRight{}, details, err
		}
		if alias.ID != uuid.Nil {
			details.AliasResolved = true
			details.AliasName = target
			details.AliasHost = alias.Host
			details.AliasPort = alias.Port
			details.AliasProtocol = alias.Protocol
			target = alias.Host
			if alias.Port > 0 {
				target = fmt.Sprintf("%s:%d", target, alias.Port)
			}
			if alias.Protocol != "" {
				target = target + ":" + alias.Protocol
			}
		}
	}

	dbUser, host, port, protocol, database := parseDBTarget(target, extraArgs)

	// If no host parsed, try alias resolution
	if host == "" {
		alias, err := resolveDBAlias(db, user, target)
		if err != nil {
			return models.DBAccessRight{}, details, err
		}
		if alias.ID != uuid.Nil {
			details.AliasResolved = true
			details.AliasName = target
			details.AliasHost = alias.Host
			details.AliasPort = alias.Port
			details.AliasProtocol = alias.Protocol
			host = alias.Host
			port = alias.Port
			protocol = alias.Protocol
		}
	}

	if host == "" {
		return models.DBAccessRight{}, details, fmt.Errorf("no database access found for '%s'", target)
	}

	accesses, err := dbAccessFilter(db, user, host, port, protocol)
	if err != nil {
		return models.DBAccessRight{}, details, err
	}
	if len(accesses) == 0 {
		return models.DBAccessRight{}, details, fmt.Errorf("no database access found for '%s'", target)
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
			return models.DBAccessRight{}, details, fmt.Errorf("no database '%s' found on '%s'", database, target)
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
			return models.DBAccessRight{}, details, fmt.Errorf("no database access with user '%s' on '%s'", dbUser, target)
		}
		accesses = filtered
	}

	if len(accesses) == 1 {
		details.EffectiveUser = accesses[0].Username
		details.EffectiveHost = accesses[0].Host
		details.EffectivePort = accesses[0].Port
		details.EffectiveProtocol = accesses[0].Protocol
		details.EffectiveDatabase = accesses[0].Database
		details.AccessSource = accesses[0].Source
		return accesses[0], details, nil
	}

	// Multiple matches remain — disambiguate
	access, err := disambiguateDBAccess(target, accesses, protocol, dbUser, database)
	if err != nil {
		return models.DBAccessRight{}, details, err
	}
	details.EffectiveUser = access.Username
	details.EffectiveHost = access.Host
	details.EffectivePort = access.Port
	details.EffectiveProtocol = access.Protocol
	details.EffectiveDatabase = access.Database
	details.AccessSource = access.Source
	return access, details, nil
}

func shouldResolveDBAliasFirst(target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	return !strings.ContainsAny(target, "@:")
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
	case "redis":
		return "redis"
	default:
		return p
	}
}

// parseDBTarget parses a target string into user, host, port, protocol.
// Formats: "host", "user@host", "host:port", "host:port:protocol", "user@host:port:protocol"
// Also supports --dbname, --mysql, --pg, --redis flags in args.
func parseDBTarget(target string, args []string) (dbUser, host string, port int64, protocol, database string) {
	// Check for flags in args
	for i, a := range args {
		switch {
		case a == "--mysql":
			protocol = "mysql"
		case a == "--pg" || a == "--postgres":
			protocol = "postgres"
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
		var aliases []models.DatabaseAlias
		if err := db.Preload("Group").Where("group_id IN (?) AND deleted_at IS NULL",
			userGroupIDs).Find(&aliases).Error; err != nil {
			return models.DatabaseAlias{}, err
		}

		var explicitMatches []models.DatabaseAlias
		var exactMatches []models.DatabaseAlias
		for _, candidate := range aliases {
			if candidate.Group != nil && strings.EqualFold(candidate.Group.Name+"-"+candidate.ResolveFrom, target) {
				explicitMatches = append(explicitMatches, candidate)
			}
			if strings.EqualFold(candidate.ResolveFrom, target) {
				exactMatches = append(exactMatches, candidate)
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
			for _, a := range candidates {
				if a.Group != nil {
					groups = append(groups, a.Group.Name)
				}
			}
			sort.Strings(groups)
			return models.DatabaseAlias{}, fmt.Errorf("database alias '%s' is ambiguous across groups: %s; use <group>-%s", target, strings.Join(groups, ", "), target)
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
		user.ID, port, port, host, host, now,
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
			groupIDs, port, port, host, host, now,
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
		password = cryptokey.DecryptOrPassThrough(a.Password)
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
		password = cryptokey.DecryptOrPassThrough(a.Password)
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
