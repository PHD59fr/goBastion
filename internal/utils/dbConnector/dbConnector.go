package dbConnector

import (
	"compress/gzip"
	"context"
	"fmt"
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

	"gorm.io/gorm"
)

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
	safeServer := strings.ReplaceAll(access.Host, "/", "_")
	safeServer = strings.ReplaceAll(safeServer, "..", "_")
	dir := fmt.Sprintf("%s/%s/%s/", config.Get().Paths.TtyrecDir, safeUser, safeServer)
	if err := os.MkdirAll(dir, 02770); err != nil {
		return fmt.Errorf("error creating ttyrec dir: %w", err)
	}

	filenameSuffix := ""
	if sessionID != "" {
		filenameSuffix = "_sid-" + sessionID
	}
	ttyrecFile := fmt.Sprintf("%s%s.%s_%s_%s%s.ttyrec", dir, access.Protocol, safeServer, access.Protocol, timestamp, filenameSuffix)
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

// findDBAccess resolves access rights for a database connection.
func findDBAccess(db *gorm.DB, user models.User, host string) ([]models.DBAccessRight, error) {
	var selfAccesses []models.SelfDBAccess
	db.Where("user_id = ? AND (expires_at IS NULL OR expires_at > ?)", user.ID, time.Now()).
		Joins("DatabaseHost").
		Find(&selfAccesses)

	var results []models.DBAccessRight
	for _, a := range selfAccesses {
		if host != "" && !matchDBHost(a.DatabaseHost, host) {
			continue
		}
		results = append(results, buildDBAccessRight("account-"+user.Username, a.DatabaseHost, a.Database))
	}
	if len(results) > 0 {
		return results, nil
	}

	type groupAccessRow struct {
		DatabaseHostID string
		Database       string
		GroupName      string
		GroupRole      string
	}

	var guestHostIDs []string
	db.Table("group_guest_db_accesses").
		Where("user_id = ? AND (expires_at IS NULL OR expires_at > ?)", user.ID, time.Now()).
		Pluck("database_host_id", &guestHostIDs)
	guestSet := make(map[string]bool)
	for _, id := range guestHostIDs {
		guestSet[id] = true
	}

	var groupRows []groupAccessRow
	db.Table("group_db_accesses").
		Joins("JOIN user_groups ON user_groups.group_id = group_db_accesses.group_id").
		Where("user_groups.user_id = ? AND (group_db_accesses.expires_at IS NULL OR group_db_accesses.expires_at > ?)", user.ID, time.Now()).
		Select("group_db_accesses.database_host_id, group_db_accesses.database, groups.name as group_name, user_groups.role as group_role").
		Joins("JOIN groups ON groups.id = user_groups.group_id").
		Find(&groupRows)

	var guestRows []groupAccessRow
	db.Table("group_guest_db_accesses").
		Where("user_id = ? AND (group_guest_db_accesses.expires_at IS NULL OR group_guest_db_accesses.expires_at > ?)", user.ID, time.Now()).
		Select("group_guest_db_accesses.database_host_id, group_guest_db_accesses.database, '' as group_name, 'guest' as group_role").
		Find(&guestRows)
	groupRows = append(groupRows, guestRows...)

	type hostRow struct {
		models.DatabaseHost
	}
	for _, row := range groupRows {
		var h models.DatabaseHost
		if err := db.Where("id = ?", row.DatabaseHostID).First(&h).Error; err != nil {
			continue
		}
		if guestSet[row.DatabaseHostID] || row.GroupRole != "guest" {
			if host != "" && !matchDBHost(h, host) {
				continue
			}
			results = append(results, buildDBAccessRight("group-"+row.GroupName, h, row.Database))
		}
	}
	_ = guestSet

	if len(results) > 0 {
		return results, nil
	}

	if user.IsAdmin() {
		var all []models.SelfDBAccess
		db.Preload("DatabaseHost").Find(&all)
		for _, a := range all {
			if host != "" && !matchDBHost(a.DatabaseHost, host) {
				continue
			}
			results = append(results, buildDBAccessRight("admin-override", a.DatabaseHost, a.Database))
		}
	}

	return results, nil
}

func matchDBHost(h models.DatabaseHost, host string) bool {
	return strings.EqualFold(h.Name, host) || strings.EqualFold(h.Host, host)
}

func buildDBAccessRight(source string, h models.DatabaseHost, database string) models.DBAccessRight {
	password := ""
	if h.Password != "" {
		if decrypted, err := cryptokey.Decrypt(h.Password); err == nil {
			password = decrypted
		} else {
			slog.Warn("db_password_decrypt_failed", slog.String("host", h.Name), slog.Any("error", err))
		}
	}
	return models.DBAccessRight{
		Source:   source,
		Host:     h.Host,
		Port:     h.Port,
		Protocol: h.Protocol,
		Username: h.Username,
		Password: password,
		Database: database,
	}
}

// ResolveTarget finds a matching DBAccessRight for the given target (host name or alias).
// Returns the first match, or an error if no access is found.
func ResolveTarget(db *gorm.DB, user models.User, target string) (models.DBAccessRight, error) {
	accesses, err := findDBAccess(db, user, target)
	if err != nil {
		return models.DBAccessRight{}, fmt.Errorf("failed to resolve database access: %w", err)
	}
	if len(accesses) == 0 {
		return models.DBAccessRight{}, fmt.Errorf("no database access found for host '%s'", target)
	}
	if len(accesses) > 1 {
		var hints []string
		for _, a := range accesses {
			hints = append(hints, fmt.Sprintf("  %s://%s:%d (protocol=%s)", a.Protocol, a.Host, a.Port, a.Protocol))
		}
		return models.DBAccessRight{}, fmt.Errorf("multiple database accesses found for host '%s', please specify protocol:\n%s", target, strings.Join(hints, "\n"))
	}
	return accesses[0], nil
}

func tmpDirPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".tmp")
}
