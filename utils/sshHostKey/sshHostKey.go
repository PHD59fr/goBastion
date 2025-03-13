package sshHostKey

import (
	"fmt"
	"path/filepath"

	"os"
	"os/exec"

	"goBastion/models"

	"gorm.io/gorm"
)

func sshKeysExist() bool {
	keyTypes := []string{"rsa", "dsa", "ecdsa", "ed25519"}

	for _, keyType := range keyTypes {
		privateKeyPath := fmt.Sprintf("/etc/ssh/ssh_host_%s_key", keyType)
		if _, err := os.Stat(privateKeyPath); err == nil {
			return true
		}
	}
	return false
}

func GenerateSSHHostKeys(db *gorm.DB, force bool) error {
	if sshKeysExist() && !force {
		return nil
	}

	if force {
		if err := removeSSHHostKeys(); err != nil {
			return fmt.Errorf("error removing existing SSH keys: %v", err)
		}
	}

	cmd := exec.Command("ssh-keygen", "-A")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	return saveSSHHostKeys(db)
}

func saveSSHHostKeys(db *gorm.DB) error {
	keyTypes := []string{"rsa", "dsa", "ecdsa", "ed25519"}

	for _, keyType := range keyTypes {
		privateKeyPath := fmt.Sprintf("/etc/ssh/ssh_host_%s_key", keyType)
		publicKeyPath := privateKeyPath + ".pub"

		privateKey, err := os.ReadFile(privateKeyPath)
		if err != nil {
			continue
		}
		publicKey, err := os.ReadFile(publicKeyPath)
		if err != nil {
			continue
		}

		sshKey := models.SshHostKey{
			Type:       keyType,
			PrivateKey: privateKey,
			PublicKey:  publicKey,
		}

		db.Save(&sshKey)
	}
	return nil
}

func removeSSHHostKeys() error {
	pattern := "/etc/ssh/ssh_host_*"

	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("error finding SSH host key files: %v", err)
	}

	for _, file := range files {
		if err = os.Remove(file); err != nil {
			return fmt.Errorf("error deleting %s: %v", file, err)
		}
	}

	return nil
}

func RestoreSSHHostKeys(db *gorm.DB) error {
	var keys []models.SshHostKey
	result := db.Find(&keys)

	if result.Error != nil {
		return result.Error
	}

	if len(keys) == 0 {
		return GenerateSSHHostKeys(db, false)
	}

	for _, key := range keys {
		privateKeyPath := fmt.Sprintf("/etc/ssh/ssh_host_%s_key", key.Type)
		publicKeyPath := privateKeyPath + ".pub"

		err := os.WriteFile(privateKeyPath, key.PrivateKey, 0600)
		if err != nil {
			return err
		}

		err = os.WriteFile(publicKeyPath, key.PublicKey, 0644)
		if err != nil {
			return err
		}
	}
	return nil
}
