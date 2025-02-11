package system

import (
	"fmt"
	"os"
	"os/exec"

	"goBastion/models"
	"goBastion/utils"
)

func CreateUser(username string) error {
	username = utils.NormalizeUsername(username)
	output, err := ExecCommand("/usr/bin/sudo", "adduser", "--disabled-password", "--gecos", "", username)
	if err != nil {
		return fmt.Errorf("error adding system user '%s': %s, output: %s", username, err, output)
	}

	output, err = ExecCommand("/usr/bin/sudo", "/usr/bin/passwd", "-d", username)
	if err != nil {
		return fmt.Errorf("error deleting password for user '%s': %s, output: %s", username, err, output)
	}
	return nil
}

func DeleteUser(username string) error {
	username = utils.NormalizeUsername(username)
	if _, err := ExecCommand("/usr/bin/sudo", "deluser", "--remove-home", username); err != nil {
		return fmt.Errorf("error deleting system user: %w", err)
	}
	return nil
}

func ChownDir(user models.User, dir string) error {
	// Without sudo
	_, err := ExecCommand("chown", "-R", user.Username+":"+user.Username, dir)
	if err != nil {
		// if failed, with sudo
		_, err = ExecCommand("/usr/bin/sudo", "chown", "-R", user.Username+":"+user.Username, dir)
		if err != nil {
			return fmt.Errorf("failed to set ownership on '%s': %w", dir, err)
		}
	}
	return nil
}

func UpdateSudoers(user *models.User) error {
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

func ExecCommand(name string, arg ...string) (string, error) {
	cmd := exec.Command(name, arg...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}
