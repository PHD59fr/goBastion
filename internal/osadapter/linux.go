package osadapter

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils"
	"goBastion/internal/utils/validation"
)

// LinuxAdapter is the real implementation of SystemAdapter for Linux.
type LinuxAdapter struct{}

// NewLinuxAdapter returns a production-ready SystemAdapter.
func NewLinuxAdapter() SystemAdapter {
	return &LinuxAdapter{}
}

func (l *LinuxAdapter) CreateUser(username string) error {
	username = utils.NormalizeUsername(username)
	if !validation.IsValidUsername(username) {
		return fmt.Errorf("invalid username: %s", username)
	}
	out, err := l.ExecCommand("/usr/bin/sudo", "/usr/local/sbin/gobastion-adduser", username)
	if err != nil {
		return fmt.Errorf("error adding system user '%s': %s, output: %s", username, err, out)
	}
	out, err = l.ExecCommand("/usr/bin/sudo", "/usr/local/sbin/gobastion-passwd-delete", username)
	if err != nil {
		return fmt.Errorf("error deleting password for user '%s': %s, output: %s", username, err, out)
	}
	return nil
}

func (l *LinuxAdapter) DeleteUser(username string) error {
	username = utils.NormalizeUsername(username)
	if !validation.IsValidUsername(username) {
		return fmt.Errorf("invalid username: %s", username)
	}
	if _, err := l.ExecCommand("/usr/bin/sudo", "/usr/local/sbin/gobastion-deluser", username); err != nil {
		return fmt.Errorf("error deleting system user: %w", err)
	}
	return nil
}

func (l *LinuxAdapter) UpdateSudoers(user *models.User) error {
	username := utils.NormalizeUsername(user.Username)
	if !validation.IsValidUsername(username) {
		return fmt.Errorf("invalid username: %s", username)
	}
	action := "remove"
	if user.Role == models.RoleAdmin {
		action = "admin"
	}
	out, err := l.ExecCommand("/usr/bin/sudo", "/usr/local/sbin/gobastion-sudoers", username, action)
	if err != nil {
		return fmt.Errorf("error updating sudoers for user '%s': %w, output: %s", username, err, out)
	}
	return nil
}

func (l *LinuxAdapter) ChownDir(user models.User, dir string) error {
	userUsername := utils.NormalizeUsername(user.Username)
	if !validation.IsValidUsername(userUsername) {
		return fmt.Errorf("invalid username: %s", userUsername)
	}
	_, err := l.ExecCommand("chown", "-R", userUsername+":"+userUsername, dir)
	if err != nil {
		expectedSSHDir := filepath.Join(config.Get().Paths.HomeBaseDir, userUsername, ".ssh")
		if dir != expectedSSHDir {
			return fmt.Errorf("sudo chown denied for non-SSH directory '%s'", dir)
		}
		_, err = l.ExecCommand("/usr/bin/sudo", "/usr/local/sbin/gobastion-chown-ssh", userUsername)
		if err != nil {
			return fmt.Errorf("failed to set ownership on '%s': %w", dir, err)
		}
	}
	return nil
}

func (l *LinuxAdapter) ExecCommand(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

func (l *LinuxAdapter) UserHomeExists(username string) bool {
	userDir := filepath.Join(config.Get().Paths.HomeBaseDir, utils.NormalizeUsername(username))
	_, err := os.Stat(userDir)
	return err == nil
}
