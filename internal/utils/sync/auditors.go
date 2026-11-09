package sync

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	osuser "os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/recording"
	"goBastion/internal/utils/validation"
)

// prepareRecordingAccess runs only for the root Linux adapter in production.
// Tests can inject these operations without changing host accounts or archives.
func (s *Syncer) prepareRecordingAccess(user models.User) error {
	if err := s.reconcileAuditors(); err != nil {
		return err
	}
	if s.provisionRecording != nil {
		archive := config.Get().Paths.TtyrecDir
		if err := s.provisionRecording(archive, user.Username); err != nil {
			s.log.Error("recording_integrity_failed",
				slog.String("user", user.Username),
				slog.String("archive", archive),
				slog.Any("error", err),
			)
			return fmt.Errorf("provision recording account %q: recording storage integrity check failed: %w", user.Username, err)
		}
	}
	return nil
}

func canonicalAccountName(name string) bool {
	return name == strings.ToLower(name) && validation.IsValidManagedUsername(name)
}

func canonicalID(raw string) (uint64, error) {
	id, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || strconv.FormatUint(id, 10) != raw {
		return 0, fmt.Errorf("invalid numeric account metadata")
	}
	return id, nil
}

func (s *Syncer) auditorAccount(name string, auditorGID uint64) (*osuser.User, error) {
	if !canonicalAccountName(name) {
		return nil, fmt.Errorf("invalid auditor account name")
	}
	account, err := s.lookupUser(name)
	if err != nil {
		return nil, err
	}
	if account == nil || account.Username != name {
		return nil, fmt.Errorf("noncanonical auditor account %q", name)
	}
	uid, err := canonicalID(account.Uid)
	if err != nil || uid < 1000 || uid >= 65000 {
		return nil, fmt.Errorf("refusing auditor membership for system account %q", name)
	}
	gid, err := canonicalID(account.Gid)
	if err != nil || gid == auditorGID {
		return nil, fmt.Errorf("invalid primary group for auditor account %q", name)
	}
	return account, nil
}

// reconcileAuditors requires the caller's node-local reconciliation lock. The
// fixed group's authority comes from a fresh DB read, never a caller's role.
// This lock does not serialize SSH admission or account role transactions.
func (s *Syncer) reconcileAuditors() error {
	if !s.reconcileAuditorAccess {
		return nil
	}
	if err := s.rejectReusedActiveNames(); err != nil {
		return err
	}

	var users []models.User
	if err := s.db.Find(&users).Error; err != nil {
		return fmt.Errorf("read recording auditors: %w", err)
	}
	desired := make(map[string]bool)
	for _, user := range users {
		if !user.SystemUser && !canonicalAccountName(user.Username) {
			return fmt.Errorf("invalid managed account name in recording auditor inventory")
		}
		if user.IsAdmin() && user.Enabled && !user.SystemUser {
			desired[user.Username] = true
		}
	}
	group, err := s.os.ExecCommand("/usr/bin/getent", "group", recording.AuditorGroup)
	if err != nil {
		return fmt.Errorf("lookup recording auditor group: %w", err)
	}
	gid, members, err := parseAuditorGroup(group)
	if err != nil {
		return err
	}
	shared, err := s.os.ExecCommand("/usr/bin/getent", "group", "gobastion")
	if err != nil {
		return fmt.Errorf("lookup shared bastion group: %w", err)
	}
	fields := strings.Split(strings.TrimSuffix(shared, "\n"), ":")
	if len(fields) != 4 || fields[0] != "gobastion" {
		return fmt.Errorf("invalid shared bastion group")
	}
	sharedID, err := canonicalID(fields[2])
	if err != nil || sharedID == 0 || sharedID == gid {
		return fmt.Errorf("recording auditor group must differ from shared bastion group")
	}

	passwd, err := s.os.ExecCommand("/usr/bin/getent", "passwd")
	if err != nil {
		return fmt.Errorf("check recording auditor primary groups: %w", err)
	}
	if err := rejectAuditorPrimaryGroup(passwd, gid); err != nil {
		return err
	}
	// Validate every existing and prospective member before the first mutation.
	// Missing OS users are expected during initial bootstrap and are added only
	// after their account has actually been created and provisioned.
	if s.openAuditorJournal == nil {
		return fmt.Errorf("auditor revocation journal unavailable")
	}
	journal, err := s.openAuditorJournal()
	if err != nil {
		return err
	}
	defer func() { _ = journal.close() }()
	pending, err := journal.load()
	if err != nil {
		return err
	}
	accounts := make(map[string]*osuser.User)
	for name, uid := range pending {
		account, e := s.pendingAuditorAccount(name, uid, gid)
		if e != nil {
			return e
		}
		accounts[name] = account
	}
	for name := range members {
		if accounts[name] != nil {
			continue
		}
		account, e := s.auditorAccount(name, gid)
		if e != nil {
			return fmt.Errorf("validate existing recording auditor %q: %w", name, e)
		}
		accounts[name] = account
	}
	for name := range desired {
		if accounts[name] != nil {
			continue
		}
		account, err := s.auditorAccount(name, gid)
		if err != nil {
			var unknown osuser.UnknownUserError
			if errors.As(err, &unknown) {
				continue
			}
			return fmt.Errorf("validate prospective recording auditor %q: %w", name, err)
		}
		accounts[name] = account
	}
	var remove []string
	for name := range members {
		if !desired[name] {
			pending[name] = accounts[name].Uid
		}
	}
	for name := range pending {
		remove = append(remove, name)
	}
	sort.Strings(remove)
	for _, name := range remove {
		account := accounts[name]
		if err := journal.mark(name, account.Uid); err != nil {
			return err
		}
		if members[name] {
			if _, err := s.os.ExecCommand("/usr/sbin/delgroup", name, recording.AuditorGroup); err != nil {
				return fmt.Errorf("remove recording auditor %q: %w", name, err)
			}
			delete(members, name)
		}
		if err := s.terminateAuditorProcesses(account); err != nil {
			return err
		}
		if err := journal.clear(name, account.Uid); err != nil {
			return err
		}
	}
	var add []string
	for name := range desired {
		if !members[name] && accounts[name] != nil {
			add = append(add, name)
		}
	}
	sort.Strings(add)
	for _, name := range add {
		if _, err := s.os.ExecCommand("/usr/sbin/addgroup", name, recording.AuditorGroup); err != nil {
			return fmt.Errorf("add recording auditor %q: %w", name, err)
		}
	}
	return nil
}

func parseAuditorGroup(raw string) (uint64, map[string]bool, error) {
	if len(raw) > 1<<20 {
		return 0, nil, fmt.Errorf("recording auditor group inventory too large")
	}
	parts := strings.Split(strings.TrimSuffix(raw, "\n"), ":")
	if len(parts) != 4 || parts[0] != recording.AuditorGroup || strings.ContainsAny(parts[3], "\r\n") {
		return 0, nil, fmt.Errorf("invalid recording auditor group metadata")
	}
	gid, err := canonicalID(parts[2])
	if err != nil || gid == 0 {
		return 0, nil, fmt.Errorf("invalid recording auditor group ID")
	}
	members := make(map[string]bool)
	if parts[3] != "" {
		for _, name := range strings.Split(parts[3], ",") {
			if !canonicalAccountName(name) || members[name] {
				return 0, nil, fmt.Errorf("invalid recording auditor member metadata")
			}
			members[name] = true
		}
	}
	return gid, members, nil
}

func rejectAuditorPrimaryGroup(raw string, auditorGID uint64) error {
	if len(raw) == 0 || len(raw) > 8<<20 {
		return fmt.Errorf("invalid account inventory for recording auditors")
	}
	owners := make(map[uint64]string)
	names := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimSuffix(raw, "\n"), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) != 7 {
			return fmt.Errorf("invalid account inventory for recording auditors")
		}
		if parts[0] == "" || names[parts[0]] {
			return fmt.Errorf("duplicate or empty Unix login name")
		}
		names[parts[0]] = true
		uid, e := canonicalID(parts[2])
		if e != nil {
			return fmt.Errorf("invalid account UID inventory")
		}
		if uid >= 1000 && uid < 65000 {
			if prior, exists := owners[uid]; exists && prior != parts[0] {
				return fmt.Errorf("managed Unix UID is shared by multiple login names")
			}
			owners[uid] = parts[0]
		}
		gid, err := canonicalID(parts[3])
		if err != nil || gid == auditorGID {
			return fmt.Errorf("recording auditor group must never be a primary group")
		}
	}
	return nil
}

// A durable marker retains failed revocation after membership removal.
// SSH admission can race this sequence; it is not atomic
// admission/group revocation. A promotion applies to newly started sessions.
func (s *Syncer) terminateAuditorProcesses(account *osuser.User) error {
	if account == nil || !canonicalAccountName(account.Username) {
		return fmt.Errorf("invalid revocation account")
	}
	uid, validateErr := canonicalID(account.Uid)
	if validateErr != nil || uid < 1000 || uid >= 65000 {
		return fmt.Errorf("invalid revocation UID")
	}

	_, err := s.os.ExecCommand("/usr/bin/pkill", "-KILL", "-u", account.Uid)
	if err != nil && !noMatchingProcesses(err) {
		return fmt.Errorf("terminate recording auditor %q: %w", account.Username, err)
	}
	for attempt := 0; attempt < 20; attempt++ {
		out, err := s.os.ExecCommand("/usr/bin/pgrep", "-u", account.Uid)
		if noMatchingProcesses(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("verify recording auditor termination %q: %w", account.Username, err)
		}
		if strings.TrimSpace(out) == "" {
			return fmt.Errorf("invalid process inventory for recording auditor %q", account.Username)
		}
		stopped, checkErr := auditorProcessesStopped(out, account.Uid)
		if checkErr != nil {
			return checkErr
		}
		if stopped {
			return nil
		}
		if attempt < 19 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	return fmt.Errorf("recording auditor %q still has processes", account.Username)
}

func noMatchingProcesses(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == 1
}

// A zombie has no running code or open descriptors. Requiring its parent to
// reap it would retain revocation markers indefinitely in containers without
// an init reaper, even though its credential capability has already ended.
func auditorProcessesStopped(output, uid string) (bool, error) {
	pids := strings.Fields(output)
	if len(pids) == 0 || len(pids) > 100000 {
		return false, fmt.Errorf("invalid auditor process inventory")
	}
	for _, pid := range pids {
		n, err := canonicalID(pid)
		if err != nil || n == 0 {
			return false, fmt.Errorf("invalid auditor process ID")
		}
		f, err := os.Open(filepath.Join("/proc", pid, "status"))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("read auditor process status: %w", err)
		}
		raw, readErr := io.ReadAll(io.LimitReader(f, 65537))
		_ = f.Close()
		if readErr != nil || len(raw) > 65536 {
			return false, fmt.Errorf("invalid auditor process status")
		}
		running, err := auditorStatusRunning(string(raw), uid)
		if err != nil {
			return false, err
		}
		if running {
			return false, nil
		}
	}
	return true, nil
}
func auditorStatusRunning(raw, uid string) (bool, error) {
	var state, effective string
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "State:" {
			state = fields[1]
		}
		if len(fields) == 5 && fields[0] == "Uid:" {
			for _, id := range fields[1:] {
				if _, err := canonicalID(id); err != nil {
					return false, fmt.Errorf("invalid auditor process credentials")
				}
			}
			effective = fields[2]
		}
	}
	if len(state) != 1 || effective == "" {
		return false, fmt.Errorf("missing auditor process credentials")
	}
	return effective == uid && state != "Z" && state != "X", nil
}

func (s *Syncer) rejectReusedActiveNames() error {
	if !s.reconcileAuditorAccess {
		return nil
	}
	var conflicts []struct{ Username string }
	err := s.db.Unscoped().Model(&models.User{}).Select("LOWER(username) AS username").Group("LOWER(username)").Having("COUNT(*) > 1 AND SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END) > 0").Limit(1).Scan(&conflicts).Error
	if err != nil {
		return err
	}
	if len(conflicts) != 0 {
		return fmt.Errorf("historically reused active login requires offline identity repair")
	}
	return nil
}
