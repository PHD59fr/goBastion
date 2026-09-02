package account

import (
	"bufio"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/utils/console"
	gosync "goBastion/internal/utils/sync"
	"goBastion/internal/utils/validation"
)

// Create creates a new user account with an SSH ingress key.
func Create(db *gorm.DB, adapter osadapter.SystemAdapter, currentUser *models.User, args []string) error {
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
		if err != nil {
			return err
		}
		return fmt.Errorf("missing required arguments")
	}

	if !currentUser.CanDo(db, "accountCreate", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to create an account."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter the complete public SSH key: ")
	pubKey, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(pubKey) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Key", Body: []string{"The provided SSH public key is invalid or missing."}}},
		})
		return fmt.Errorf("invalid or missing SSH key")
	}
	if _, _, _, _, err = ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(pubKey))); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Key Format", Body: []string{"The provided SSH public key is invalid."}}},
		})
		return fmt.Errorf("invalid SSH key: %w", err)
	}

	if err = CreateUser(db, adapter, username, pubKey, UserCreationOptions{
		Role:       models.RoleUser,
		Enabled:    true,
		OSHOnly:    oshOnly,
		SuperOwner: superOwner,
	}); err != nil {
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
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{
			fmt.Sprintf("User '%s' created successfully.", username),
			fmt.Sprintf("osh-only: %t", oshOnly),
			fmt.Sprintf("superowner: %t", superOwner),
		}}},
	})
	return nil
}

// UserCreationOptions are persisted atomically with a new account row.
type UserCreationOptions struct {
	Role       string
	Enabled    bool
	OSHOnly    bool
	SuperOwner bool
}

// CreateUser creates the DB record, registers the ingress key and creates the OS user.
func CreateUser(db *gorm.DB, adapter osadapter.SystemAdapter, username string, pubKey string, options UserCreationOptions) error {
	username = strings.ToLower(strings.TrimSpace(username))
	if !validation.IsValidUsername(username) {
		return fmt.Errorf("invalid username: %s", username)
	}

	if options.Role != models.RoleUser && options.Role != models.RoleAdmin {
		return fmt.Errorf("invalid account role: %s", options.Role)
	}

	var (
		newUser *models.User
		err     error
	)
	if err = db.Transaction(func(tx *gorm.DB) error {
		newUser, err = createDBUser(tx, username, options)
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
		if delErr := db.Unscoped().Where("user_id = ?", newUser.ID).Delete(&models.IngressKey{}).Error; delErr != nil {
			slog.Error("compensation_failed", slog.String("event", "cleanup_ingress_keys"), slog.Any("error", delErr))
		}
		if delErr := db.Unscoped().Delete(&models.User{}, "id = ?", newUser.ID).Error; delErr != nil {
			slog.Error("compensation_failed", slog.String("event", "cleanup_user"), slog.Any("error", delErr))
		}
		return err
	}
	return nil
}

// createDBUser performs an insert-only account creation.
func createDBUser(db *gorm.DB, username string, options UserCreationOptions) (*models.User, error) {
	username = strings.ToLower(strings.TrimSpace(username))
	now := time.Now()
	newUser := models.User{
		ID:         uuid.New(),
		Username:   username,
		Role:       options.Role,
		Enabled:    options.Enabled,
		OSHOnly:    options.OSHOnly,
		SuperOwner: options.SuperOwner,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	// A map insert preserves explicit false values despite GORM default tags.
	err := db.Model(&models.User{}).Create(map[string]any{
		"id":          newUser.ID,
		"username":    newUser.Username,
		"role":        newUser.Role,
		"enabled":     newUser.Enabled,
		"osh_only":    newUser.OSHOnly,
		"super_owner": newUser.SuperOwner,
		"created_at":  newUser.CreatedAt,
		"updated_at":  newUser.UpdatedAt,
	}).Error
	if err != nil {
		if validation.IsDuplicateKeyError(err) {
			return nil, fmt.Errorf("user '%s' already exists", username)
		}
		return nil, validation.WrapDBError(err, "error creating user")
	}
	return &newUser, nil
}
