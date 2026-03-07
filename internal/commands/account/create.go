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
)

// AccountCreate creates a new user account with an SSH ingress key.
func AccountCreate(db *gorm.DB, adapter osadapter.SystemAdapter, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountCreate", flag.ContinueOnError)
	var username string
	fs.StringVar(&username, "user", "", "Username to create")
	var flagOut strings.Builder
	fs.SetOutput(&flagOut)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountCreate --user <username>"}}},
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

	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Create",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("User '%s' created successfully.", username)}}},
	})
	return nil
}

// CreateUser creates the DB record, registers the ingress key and creates the OS user.
func CreateUser(db *gorm.DB, adapter osadapter.SystemAdapter, username string, pubKey string) error {
	username = strings.ToLower(strings.TrimSpace(username))

	var count int64
	if err := db.Model(&models.User{}).Where("username = ? AND deleted_at IS NULL", username).Count(&count).Error; err != nil {
		return fmt.Errorf("error querying database: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("user '%s' already exists", username)
	}

	newUser, err := createDBUser(db, username)
	if err != nil {
		return err
	}
	if err = CreateDBIngressKey(db, newUser, pubKey); err != nil {
		return err
	}

	syncer := gosync.New(db, adapter, *slog.Default())
	return syncer.CreateUserFromDB(*newUser)
}

// createDBUser inserts a new user record into the database.
func createDBUser(db *gorm.DB, username string) (*models.User, error) {
	username = strings.ToLower(strings.TrimSpace(username))

	var existing models.User
	if err := db.Where("username = ?", username).First(&existing).Error; err == nil {
		return &existing, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("error checking user existence: %w", err)
	}

	newUser := models.User{Username: username, Role: models.RoleUser, Enabled: true}
	if err := db.Create(&newUser).Error; err != nil {
		return nil, err
	}
	return &newUser, nil
}
