package recording

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"

	"goBastion/internal/utils/validation"
)

// PublishAccount is for the privileged local DB recorder. The destination's
// first component must be an explicit local account, not a realm assertion or
// a client-selected UID. It does not authorize access; admission precedes it.
func PublishAccount(archive, source, relative string) error {
	owner, err := recordingAccountUID(relative)
	if err != nil {
		return err
	}
	return Publish(archive, source, relative, owner)
}

func recordingAccountUID(relative string) (int, error) {
	if !filepath.IsLocal(relative) {
		return 0, fmt.Errorf("invalid recording account path")
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	if len(parts) != 3 || parts[1] == "" || parts[1] == "." || parts[1] == ".." || parts[2] == "" || parts[2] == "." || parts[2] == ".." {
		return 0, fmt.Errorf("invalid recording account path")
	}
	return recordingUsernameUID(parts[0])
}

func recordingUsernameUID(name string) (int, error) {
	if name != strings.ToLower(name) || !validation.IsValidManagedUsername(name) {
		return 0, fmt.Errorf("invalid recording account")
	}
	account, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("recording account is unavailable")
	}
	owner, err := strconv.Atoi(account.Uid)
	if err != nil || owner < 1000 || owner >= 65000 {
		return 0, fmt.Errorf("invalid recording account ID")
	}
	return owner, nil
}

// ProvisionAccount reserves an isolated recording namespace before publishing
// account SSH access. It never repairs or recursively changes a legacy tree.
func ProvisionAccount(archive, username string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("recording account provisioning requires root")
	}
	uid, err := recordingUsernameUID(username)
	if err != nil {
		return err
	}
	base, err := openArchiveDirectory(archive, ".", uid)
	if err != nil {
		return err
	}
	defer func() { _ = base.Close() }()
	isolated, err := archiveIsolation(base)
	if err != nil {
		return err
	}
	if !isolated {
		return fmt.Errorf("recording account provisioning requires an isolated archive")
	}
	gid, err := recordingGroupID(AuditorGroup)
	if err != nil {
		return err
	}
	if err := createIsolatedDirectory(base, int(base.Fd()), username, uid, gid); err != nil {
		return err
	}
	account, err := openArchiveSubdirectory(base, username, uid)
	if err != nil {
		return err
	}
	return account.Close()
}
