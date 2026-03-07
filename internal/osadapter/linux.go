package osadapter

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"goBastion/internal/models"
	"goBastion/internal/utils"
)

// LinuxAdapter is the real implementation of SystemAdapter for Linux.
type LinuxAdapter struct{}

// NewLinuxAdapter returns a production-ready SystemAdapter.
func NewLinuxAdapter() SystemAdapter {
	return &LinuxAdapter{}
}

func (l *LinuxAdapter) CreateUser(username string) error {
	username = utils.NormalizeUsername(username)
	out, err := l.ExecCommand("/usr/bin/sudo", "adduser", "--disabled-password", "--gecos", "", username)
	if err != nil {
		return fmt.Errorf("error adding system user '%s': %s, output: %s", username, err, out)
	}
	out, err = l.ExecCommand("/usr/bin/sudo", "/usr/bin/passwd", "-d", username)
	if err != nil {
		return fmt.Errorf("error deleting password for user '%s': %s, output: %s", username, err, out)
	}
	return nil
}

func (l *LinuxAdapter) DeleteUser(username string) error {
	username = utils.NormalizeUsername(username)
	if _, err := l.ExecCommand("/usr/bin/sudo", "deluser", "--remove-home", username); err != nil {
		return fmt.Errorf("error deleting system user: %w", err)
	}
	return nil
}

func (l *LinuxAdapter) UpdateSudoers(user *models.User) error {
	sudoersPath := "/etc/sudoers.d/" + user.Username
	if user.Role == "admin" {
		sudoersConfig := fmt.Sprintf(`%s ALL=(ALL) NOPASSWD: /usr/sbin/adduser --disabled-password --gecos *
%s ALL=(ALL) NOPASSWD: /usr/bin/passwd -d *
%s ALL=(ALL) NOPASSWD: /usr/sbin/deluser --remove-home *
%s ALL=(ALL) NOPASSWD: /bin/chown -R *
`, user.Username, user.Username, user.Username, user.Username)
		if err := os.WriteFile(sudoersPath, []byte(sudoersConfig), 0440); err != nil {
			return fmt.Errorf("error writing sudoers file for user '%s': %s", user.Username, err)
		}
	} else {
		if _, err := os.Stat(sudoersPath); err == nil {
			if err := os.Remove(sudoersPath); err != nil {
				return fmt.Errorf("error removing sudoers file for user '%s': %s", user.Username, err)
			}
		}
	}
	return nil
}

func (l *LinuxAdapter) ChownDir(user models.User, dir string) error {
	_, err := l.ExecCommand("chown", "-R", user.Username+":"+user.Username, dir)
	if err != nil {
		_, err = l.ExecCommand("/usr/bin/sudo", "chown", "-R", user.Username+":"+user.Username, dir)
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
	userDir := filepath.Join("/home", utils.NormalizeUsername(username))
	_, err := os.Stat(userDir)
	return !os.IsNotExist(err)
}
