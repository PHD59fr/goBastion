// Package secretstore implements the persistent-secrets-v2 offline migration.
// It deliberately uses an explicit inventory, including soft-deleted records.
package secretstore

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"goBastion/internal/utils/cryptokey"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

const MigrationVersion = "persistent-secrets-v2"

type column struct {
	table, primary, name string
	binary, required     bool
}

// Order is fixed so concurrent operators acquire locks consistently. Operators
// must still drain every instance before migration or key retirement.
var columns = []column{
	{"group_db_accesses", "id", "password", false, false},
	{"group_egress_keys", "id", "priv_key", false, true},
	{"group_guest_db_accesses", "id", "password", false, false},
	{"self_db_accesses", "id", "password", false, false},
	{"self_egress_keys", "id", "priv_key", false, true},
	{"ssh_host_keys", "type", "private_key", true, true},
	{"users", "id", "totp_secret", false, false},
}

type record struct {
	ID    string `gorm:"column:secret_id"`
	Value []byte `gorm:"column:secret_value"`
}

type Result struct {
	Version string `json:"version"`
	Checked int    `json:"checked"`
	Changed int    `json:"changed"`
	Applied bool   `json:"applied"`
}

type Options struct {
	Apply bool
	// AllowPlaintext is an explicit offline upgrade decision. It never permits
	// marked ciphertext or ambiguous base64 legacy blobs to bypass validation.
	AllowPlaintext bool
}

// ValidateStored authenticates every nonempty persisted secret. It is used
// before root startup and inside import transactions; it never writes data.
func ValidateStored(db *gorm.DB) error {
	_, err := Migrate(db, Options{})
	return err
}

// Migrate upgrades authenticated legacy/historical ciphertext or explicitly
// allowed plaintext. All writes commit together; failure leaves no partial
// migration. Re-running with the active key leaves ciphertext unchanged.
func Migrate(db *gorm.DB, options Options) (Result, error) {
	result := Result{Version: MigrationVersion}
	if err := cryptokey.Validate(); err != nil {
		return result, err
	}
	// SQL diagnostics can contain bound secret values. Never use caller logging
	// for this sensitive transaction, even when a statement fails.
	err := db.Session(&gorm.Session{Logger: logger.Default.LogMode(logger.Silent)}).Transaction(func(tx *gorm.DB) error {
		for _, c := range columns {
			var records []record
			query := tx.Table(c.table).Select(c.primary + " AS secret_id, " + c.name + " AS secret_value").Order(c.primary)
			if options.Apply {
				query = query.Clauses(clause.Locking{Strength: "UPDATE"})
			}
			if err := query.Find(&records).Error; err != nil {
				return fmt.Errorf("inspect %s.%s failed", c.table, c.name)
			}
			for _, row := range records {
				if len(row.Value) == 0 {
					if c.required {
						return fmt.Errorf("empty required secret in %s.%s", c.table, c.name)
					}
					continue
				}
				result.Checked++
				raw := string(row.Value)
				plain, err := cryptokey.Decrypt(raw)
				if err != nil {
					if !options.AllowPlaintext || strings.HasPrefix(raw, "gob:") || ambiguousLegacy(raw) {
						return fmt.Errorf("unreadable or plaintext secret in %s.%s; use offline migration with the required keys", c.table, c.name)
					}
					plain = raw
				}
				if err == nil && !cryptokey.NeedsRotation(raw) {
					continue
				}
				result.Changed++
				if !options.Apply {
					continue
				}
				encrypted, err := cryptokey.Encrypt(plain)
				if err != nil {
					return errors.New("encrypt migrated secret failed")
				}
				var value any = encrypted
				if c.binary {
					value = []byte(encrypted)
				}
				// A compare-and-swap protects against an accidental concurrent writer
				// on engines that cannot hold row locks. Any conflict rolls back all.
				var old any = raw
				if c.binary {
					old = row.Value
				}
				update := tx.Table(c.table).Where(c.primary+" = ? AND "+c.name+" = ?", row.ID, old).UpdateColumn(c.name, value)
				if update.Error != nil || update.RowsAffected != 1 {
					return fmt.Errorf("concurrent change or write failure in %s.%s", c.table, c.name)
				}
			}
		}
		return nil
	})
	if err != nil {
		result.Changed = 0
		return result, err
	}
	result.Applied = options.Apply
	return result, nil
}

// Unmarked base64 may be old authenticated ciphertext with a wrong/missing key.
// Never reinterpret such a value as a password after authentication failure.
func ambiguousLegacy(raw string) bool {
	b, err := base64.StdEncoding.DecodeString(raw)
	return err == nil && len(b) >= 28
}
