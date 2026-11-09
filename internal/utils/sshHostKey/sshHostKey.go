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
	"goBastion/internal/utils/cryptokey"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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

	private, err := cryptokey.Decrypt(string(key.PrivateKey))
	if err != nil {
		return nil, "", "", fmt.Errorf("decrypt persisted SFTP proxy host key: %w", err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(private))
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
	encrypted, err := cryptokey.Encrypt(string(priv))
	if err != nil {
		return nil, err
	}
	key = models.SshHostKey{
		Type:       sftpProxyHostKeyType,
		PrivateKey: []byte(encrypted),
		PublicKey:  pub,
	}
	query := db
	if !force {
		query = query.Clauses(clause.OnConflict{DoNothing: true})
	}
	if force {
		query = query.Save(&key)
	} else {
		query = query.Create(&key)
	}
	if err := query.Error; err != nil {
		return nil, fmt.Errorf("save SFTP proxy host key: %w", err)
	}
	// Another instance may have won creation. Always use the persisted winner.
	if err := db.Where("type = ?", sftpProxyHostKeyType).First(&key).Error; err != nil {
		return nil, err
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
		encrypted, err := cryptokey.Encrypt(string(privateKey))
		if err != nil {
			return err
		}

		sshKey := models.SshHostKey{
			Type:       keyType,
			PrivateKey: []byte(encrypted),
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
		// Database content must never select an arbitrary root write path.
		switch key.Type {
		case "rsa", "dsa", "ecdsa", "ed25519":
		default:
			return fmt.Errorf("unsupported persisted SSH host key type")
		}
		private, err := cryptokey.Decrypt(string(key.PrivateKey))
		if err != nil {
			return fmt.Errorf("decrypt persisted SSH host key: %w", err)
		}
		privateKeyPath := fmt.Sprintf("%s/ssh_host_%s_key", config.Get().Paths.SshHostKeyDir, key.Type)
		publicKeyPath := privateKeyPath + ".pub"

		err = writeHostKeyFile(privateKeyPath, []byte(private), 0600)
		if err != nil {
			return err
		}

		err = writeHostKeyFile(publicKeyPath, key.PublicKey, 0644)
		if err != nil {
			return err
		}
	}
	return nil
}

// Replace a complete file atomically, without following a pre-existing symlink
// or retaining permissions from an older, overly permissive private key file.
func writeHostKeyFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".gobastion-host-key-*")
	if err != nil {
		return err
	}
	defer func() { _ = f.Close(); _ = os.Remove(f.Name()) }()
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
