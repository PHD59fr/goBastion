package account

import (
	"bytes"
	"flag"
	"fmt"
	"log/slog"
	"strings"

	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/utils/console"
	gosync "goBastion/internal/utils/sync"
)

// AccountDelete removes a user account from the system.
func AccountDelete(db *gorm.DB, adapter osadapter.SystemAdapter, currentUser *models.User, args []string) error {
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
		return nil
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

// DeleteUser removes the user from the OS first, then soft-deletes the DB record.
// If DB deletion fails after OS deletion, it attempts to restore the OS user from DB.
func DeleteUser(db *gorm.DB, adapter osadapter.SystemAdapter, username string) error {
	username = strings.ToLower(strings.TrimSpace(username))

	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}

	if err := adapter.DeleteUser(username); err != nil {
		return err
	}
	if err := deleteDBUser(db, username); err != nil {
		syncer := gosync.New(db, adapter, *slog.Default())
		if restoreErr := syncer.CreateUserFromDB(user); restoreErr != nil {
			return fmt.Errorf("delete failed after OS removal: %v; restore also failed: %v", err, restoreErr)
		}
		return fmt.Errorf("delete failed and OS user was restored: %w", err)
	}
	return nil
}

// deleteDBUser soft-deletes the user record from the database.
func deleteDBUser(db *gorm.DB, username string) error {
	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		return fmt.Errorf("user not found: %w", err)
	}
	if err := db.Delete(&user).Error; err != nil {
		return fmt.Errorf("error deleting user: %w", err)
	}
	return nil
}
