package account

import (
	"bytes"
	"flag"
	"fmt"
	"strings"

	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/utils/console"
)

// Delete removes a user account from the system.
func Delete(db *gorm.DB, adapter osadapter.SystemAdapter, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountDelete", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to delete")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountDelete --user <username>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "accountDelete", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to delete this account."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	if err := DeleteUser(db, adapter, username); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{err.Error()}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Delete",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("User '%s' deleted successfully.", username)}}},
	})
	return nil
}

// DeleteUser soft-deletes the DB record first, then removes the OS user.
// This ensures the DB (source of truth) is updated before any irreversible
// OS changes. If OS deletion fails, it attempts to restore the DB record.
func DeleteUser(db *gorm.DB, adapter osadapter.SystemAdapter, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))

	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	// DB first: soft-delete the audit trail before touching the OS.
	if err := deleteDBUser(db, &user); err != nil {
		return fmt.Errorf("error deleting user from database: %w", err)
	}

	// Then remove the OS user. If this fails, restore the DB record.
	if err := adapter.DeleteUser(username); err != nil {
		if restoreErr := restoreDBUser(db, &user); restoreErr != nil {
			return fmt.Errorf("OS deletion failed: %v; DB restore also failed: %v", err, restoreErr)
		}
		return fmt.Errorf("OS deletion failed, DB record restored: %w", err)
	}
	return nil
}

// deleteDBUser soft-deletes the user record from the database.
func deleteDBUser(db *gorm.DB, user *models.User) error {
	if err := db.Delete(user).Error; err != nil {
		return fmt.Errorf("error deleting user: %w", err)
	}
	return nil
}

// restoreDBUser un-deletes a soft-deleted user and their group memberships.
func restoreDBUser(db *gorm.DB, user *models.User) error {
	return db.Transaction(func(tx *gorm.DB) error {
		// Un-delete the user record.
		if err := tx.Unscoped().Model(&models.User{}).Where("id = ?", user.ID).Update("deleted_at", nil).Error; err != nil {
			return fmt.Errorf("error restoring user: %w", err)
		}
		// Un-delete all UserGroup memberships that were cascade-soft-deleted.
		if err := tx.Unscoped().Model(&models.UserGroup{}).Where("user_id = ?", user.ID).Update("deleted_at", nil).Error; err != nil {
			return fmt.Errorf("error restoring group memberships: %w", err)
		}
		return nil
	})
}
