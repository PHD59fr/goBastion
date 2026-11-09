package authkeys

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/utils/sshkey"
	"goBastion/internal/utils/validation"
)

const DefaultDBConfPath = "/run/gobastion/db.conf"

// LoadDBBootstrapFromConf reads DB_DRIVER and DB_DSN from the root-only bootstrap
// file when they are not already present in the environment. This supports
// sshd's AuthorizedKeysCommand, which invokes the binary directly without the
// session wrapper environment.
func LoadDBBootstrapFromConf() error {
	if os.Getenv("DB_DRIVER") != "" && os.Getenv("DB_DSN") != "" {
		return nil
	}
	f, err := os.Open(DefaultDBConfPath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	return loadDBBootstrap(f)
}

func loadDBBootstrap(r io.Reader) error {
	scanner := bufio.NewScanner(r)
	// Match the session bootstrap limit; an unrelated historical keyring may
	// exceed Scanner's 64 KiB default without affecting DB authentication.
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	values := map[string]string{"DB_DRIVER": os.Getenv("DB_DRIVER"), "DB_DSN": os.Getenv("DB_DSN")}
	for scanner.Scan() {
		k, v, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		if existing, allowed := values[k]; allowed && existing == "" {
			if strings.ContainsRune(v, '\x00') {
				return errors.New("invalid DB bootstrap value")
			}
			values[k] = v
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	for key, value := range values {
		if err := os.Setenv(key, value); err != nil {
			return errors.New("cannot load DB bootstrap value")
		}
	}
	return nil
}

// LookupIngressKeys returns authorized_keys-formatted lines for an enabled,
// non-system user. The result is empty (not an error) when the user is unknown,
// disabled, system, or has no valid keys. Database/query errors are returned and
// callers must fail closed.
func LookupIngressKeys(ctx context.Context, db *gorm.DB, username string, now time.Time) ([]string, error) {
	if !validation.IsValidManagedUsername(username) {
		return nil, nil
	}
	var user models.User
	if err := db.WithContext(ctx).Where("username = ?", username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if user.SystemUser || !user.Enabled || user.Username != username {
		return nil, nil
	}
	var keys []models.IngressKey
	if err := db.WithContext(ctx).Where("user_id = ? AND (expires_at IS NULL OR expires_at > ?)", user.ID, now).Order("created_at ASC, id ASC").Find(&keys).Error; err != nil {
		return nil, err
	}
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		canonical, _, err := sshkey.CanonicalIngressKey(key.Key, key.PIVAttested)
		if err != nil {
			continue
		}
		out = append(out, canonical+" #ID:"+key.ID.String())
	}
	return out, nil
}

// WriteIngressKeys writes one authorized key per line.
func WriteIngressKeys(w io.Writer, lines []string) error {
	for _, line := range lines {
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return nil
}
