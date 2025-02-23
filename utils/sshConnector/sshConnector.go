package sshConnector

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"goBastion/models"

	"github.com/google/uuid"
)

func SshConnection(user models.User, access models.AccessRight) error {

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("error getting user home directory: %v", err)
	}
	tmpFilePath := filepath.Join(homeDir, ".tmp", fmt.Sprintf("sshkey-%s.pem", uuid.New().String()))

	if err = os.MkdirAll(filepath.Dir(tmpFilePath), 0700); err != nil {
		return fmt.Errorf("error creating ~/.tmp directory: %v", err)
	}

	privateKey := access.PrivateKey + "\n" // \n is required for ssh to work
	if err = os.WriteFile(tmpFilePath, []byte(privateKey), 0600); err != nil {
		return fmt.Errorf("error writing private key: %v", err)
	}

	defer func(name string) {
		if _, err = os.Stat(name); err == nil {
			_ = os.Remove(name)
		}
	}(tmpFilePath)

	timestamp := time.Now().Format("2006-01-02_15-04-05")

	ttyrecPath := fmt.Sprintf("/app/ttyrec/%s/%s/", user.Username, access.Server)
	if err = os.MkdirAll(filepath.Dir(ttyrecPath), 0777); err != nil {
		return fmt.Errorf("error creating %s: %v", ttyrecPath, err)
	}
	ttyrecFile := fmt.Sprintf("%s%s.%s:%d_%s.ttyrec", ttyrecPath, access.Username, access.Server, access.Port, timestamp)

	cmd := exec.Command(
		"ttyrec", "-f", ttyrecFile, "--",
		"ssh", "-i", tmpFilePath, access.Username+"@"+access.Server, "-p", strconv.FormatInt(access.Port, 10),
	)

	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	fmt.Println("Connecting ...")
	if err = cmd.Run(); err != nil {
		if err.Error() == "exit status 130" {
			return nil
		}
		return fmt.Errorf("error connecting SSH: %v", err)
	}
	return nil
}
