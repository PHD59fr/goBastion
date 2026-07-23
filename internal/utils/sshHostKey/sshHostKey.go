package sshHostKey

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"strings"

	"os"
	"os/exec"

	"goBastion/internal/config"
	"goBastion/internal/models"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

const sftpProxyHostKeyType = "sftp-proxy-ed25519"

// sshKeysExist returns true if the SSH host key files are present on disk.
func sshKeysExist() bool {
	sshHostKeyDir := config.Get().Paths.SshHostKeyDir
	keyTypes := []string{"rsa", "dsa", "ecdsa", "ed25519"}

	for _, keyType := range keyTypes {
		privateKeyPath := fmt.Sprintf("%s/ssh_host_%s_key", sshHostKeyDir, keyType)
		if _, err := os.Stat(privateKeyPath); err == nil {
			return true
		}
	}
	return false
}

// GenerateSSHHostKeys creates new SSH host key files, persisting them to the database.
func GenerateSSHHostKeys(db *gorm.DB, force bool) error {
	if sshKeysExist() && !force {
		return nil
	}

	if force {
		if err := removeSSHHostKeys(); err != nil {
			return fmt.Errorf("error removing existing SSH keys: %w", err)
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

// EnsureSFTPProxyHostKey creates or loads the stable host key used by the
// in-band sftp-session proxy server. The key is persisted in the same table as
// the bastion SSH host keys, but under a dedicated type.
func EnsureSFTPProxyHostKey(db *gorm.DB, force bool) (ssh.Signer, string, string, error) {
	key, err := loadOrCreateSFTPProxyHostKey(db, force)
	if err != nil {
		return nil, "", "", err
	}

	signer, err := ssh.ParsePrivateKey(key.PrivateKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("parse persisted SFTP proxy host key: %w", err)
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(key.PublicKey)
	if err != nil {
		return nil, "", "", fmt.Errorf("parse persisted SFTP proxy public key: %w", err)
	}
	publicKey := strings.TrimSpace(string(key.PublicKey))
	fingerprint := ssh.FingerprintSHA256(pub)
	return signer, publicKey, fingerprint, nil
}

func loadOrCreateSFTPProxyHostKey(db *gorm.DB, force bool) (*models.SshHostKey, error) {
	var key models.SshHostKey
	err := db.Where("type = ?", sftpProxyHostKeyType).First(&key).Error
	switch {
	case err == nil && !force:
		return &key, nil
	case err != nil && err != gorm.ErrRecordNotFound:
		return nil, fmt.Errorf("load SFTP proxy host key: %w", err)
	}

	pub, priv, err := generateSFTPProxyHostKeyMaterial()
	if err != nil {
		return nil, err
	}
	key = models.SshHostKey{
		Type:       sftpProxyHostKeyType,
		PrivateKey: priv,
		PublicKey:  pub,
	}
	if err := db.Save(&key).Error; err != nil {
		return nil, fmt.Errorf("save SFTP proxy host key: %w", err)
	}
	return &key, nil
}

func generateSFTPProxyHostKeyMaterial() ([]byte, []byte, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ed25519 host key: %w", err)
	}

	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private host key: %w", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	pub, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal public host key: %w", err)
	}
	return ssh.MarshalAuthorizedKey(pub), privatePEM, nil
}

// saveSSHHostKeys reads generated key files and stores them in the database.
func saveSSHHostKeys(db *gorm.DB) error {
	sshHostKeyDir := config.Get().Paths.SshHostKeyDir
	keyTypes := []string{"rsa", "dsa", "ecdsa", "ed25519"}

	for _, keyType := range keyTypes {
		privateKeyPath := fmt.Sprintf("%s/ssh_host_%s_key", sshHostKeyDir, keyType)
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

		if err := db.Save(&sshKey).Error; err != nil {
			return fmt.Errorf("error saving SSH host key %s: %w", keyType, err)
		}
	}
	return nil
}

// removeSSHHostKeys deletes the SSH host key files from disk.
func removeSSHHostKeys() error {
	pattern := config.Get().Paths.SshHostKeyDir + "/ssh_host_*"

	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("error finding SSH host key files: %w", err)
	}

	for _, file := range files {
		if err = os.Remove(file); err != nil {
			return fmt.Errorf("error deleting %s: %w", file, err)
		}
	}

	return nil
}

// RestoreSSHHostKeys writes SSH host keys from the database back to disk.
func RestoreSSHHostKeys(db *gorm.DB) error {
	var keys []models.SshHostKey
	result := db.Where("type != ?", sftpProxyHostKeyType).Find(&keys)

	if result.Error != nil {
		return result.Error
	}

	if len(keys) == 0 {
		return GenerateSSHHostKeys(db, false)
	}

	for _, key := range keys {
		privateKeyPath := fmt.Sprintf("%s/ssh_host_%s_key", config.Get().Paths.SshHostKeyDir, key.Type)
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
