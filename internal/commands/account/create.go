package account

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/utils/console"
	gosync "goBastion/internal/utils/sync"
	"goBastion/internal/utils/validation"
)

// AccountCreate creates a new user account with an SSH ingress key.
func AccountCreate(db *gorm.DB, adapter osadapter.SystemAdapter, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountCreate", flag.ContinueOnError)
	var username string
	var oshOnly bool
	var superOwner bool
	fs.StringVar(&username, "user", "", "Username to create")
	fs.BoolVar(&oshOnly, "osh-only", false, "Restrict this account to -osh command execution only")
	fs.BoolVar(&superOwner, "superowner", false, "Grant implicit owner rights on all groups")
	var flagOut strings.Builder
	fs.SetOutput(&flagOut)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountCreate --user <username> [--osh-only] [--superowner]"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "accountCreate", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to create an account."}}},
		})
		return nil
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the complete public SSH key: ")
	pubKeyStr, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(pubKeyStr) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Key", Body: []string{"The provided SSH public key is invalid or missing."}}},
		})
		return fmt.Errorf("invalid or missing SSH key")
	}
	if _, _, _, _, err = ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(pubKeyStr))); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Key Format", Body: []string{"The provided SSH public key is invalid."}}},
		})
		return fmt.Errorf("invalid SSH key: %v", err)
	}

	if err = CreateUser(db, adapter, username, pubKeyStr); err != nil {
		title := "Error"
		if strings.Contains(err.Error(), "exists") {
			title = "User Exists"
		}
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: title, Body: []string{err.Error()}}},
		})
		return err
	}

	if oshOnly || superOwner {
		if err = db.Model(&models.User{}).Where("username = ?", strings.ToLower(strings.TrimSpace(username))).
			Updates(map[string]any{"osh_only": oshOnly, "super_owner": superOwner}).Error; err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Account Create",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{fmt.Sprintf("User created but failed to set flags: %v", err)}}},
			})
			return err
		}
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Create",
		BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{
			fmt.Sprintf("User '%s' created successfully.", username),
			fmt.Sprintf("osh-only: %t", oshOnly),
			fmt.Sprintf("superowner: %t", superOwner),
		}}},
	})
	return nil
}

// CreateUser creates the DB record, registers the ingress key and creates the OS user.
func CreateUser(db *gorm.DB, adapter osadapter.SystemAdapter, username string, pubKey string) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if !validation.IsValidUsername(username) {
		return fmt.Errorf("invalid username: %s", username)
	}

	var count int64
	if err := db.Model(&models.User{}).Where("username = ? AND deleted_at IS NULL", username).Count(&count).Error; err != nil {
		return validation.WrapDBError(err, "error querying database")
	}
	if count > 0 {
		return fmt.Errorf("user '%s' already exists", username)
	}

	var (
		newUser *models.User
		err     error
	)
	if err = db.Transaction(func(tx *gorm.DB) error {
		newUser, err = createDBUser(tx, username)
		if err != nil {
			return err
		}
		if err = CreateDBIngressKey(tx, newUser, pubKey); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return err
	}

	syncer := gosync.New(db, adapter, *slog.Default())
	if err = syncer.CreateUserFromDB(*newUser); err != nil {
		// Compensate DB changes when OS sync fails to avoid DB/OS drift.
		_ = db.Unscoped().Where("user_id = ?", newUser.ID).Delete(&models.IngressKey{}).Error
		_ = db.Unscoped().Delete(&models.User{}, "id = ?", newUser.ID).Error
		return err
	}
	return nil
}

// createDBUser inserts a new user record into the database.
func createDBUser(db *gorm.DB, username string) (*models.User, error) {
	username = strings.ToLower(strings.TrimSpace(username))

	var existing models.User
	if err := db.Where("username = ?", username).First(&existing).Error; err == nil {
		return &existing, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, validation.WrapDBError(err, "error checking user existence")
	}

	newUser := models.User{Username: username, Role: models.RoleUser, Enabled: true}
	if err := db.Create(&newUser).Error; err != nil {
		return nil, validation.WrapDBError(err, "error creating user")
	}
	return &newUser, nil
}
