package account

import (
	"bytes"
	"flag"
	"fmt"
	"log/slog"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/system"

	"gorm.io/gorm"
)

// Modify updates the system role of a user account.
func Modify(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountModify", flag.ContinueOnError)
	var username, newRole, oshOnlyRaw, superOwnerRaw string
	fs.StringVar(&username, "user", "", "Username to modify")
	fs.StringVar(&newRole, "sysrole", "", "New system role (admin or user)")
	fs.StringVar(&oshOnlyRaw, "oshOnly", "", "Set osh-only mode: true or false")
	fs.StringVar(&superOwnerRaw, "superOwner", "", "Set superowner mode: true or false")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountModify --user <username> [--sysrole <admin|user>] [--oshOnly <true|false>] [--superOwner <true|false>]"}}},
		})
		return err
	}

	if strings.TrimSpace(username) == "" || (strings.TrimSpace(newRole) == "" && strings.TrimSpace(oshOnlyRaw) == "" && strings.TrimSpace(superOwnerRaw) == "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountModify --user <username> [--sysrole <admin|user>] [--oshOnly <true|false>] [--superOwner <true|false>]"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "accountModify", username) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to modify this account."}}},
		})
		return nil
	}

	newRole = strings.ToLower(strings.TrimSpace(newRole))
	if newRole != "" && newRole != "admin" && newRole != "user" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid System Role", Body: []string{"System role must be 'admin' or 'user'."}}},
		})
		return nil
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found. Check spelling or run accountList.", username)}}},
		})
		return err
	}

	// Prevent demoting the last admin (count all admins, not just enabled ones)
	// because a disabled admin can be re-enabled and still has admin role.
	if newRole != "" && u.Role == models.RoleAdmin && newRole == models.RoleUser {
		var adminCount int64
		if err := db.Model(&models.User{}).Where("role = ? AND deleted_at IS NULL", models.RoleAdmin).Count(&adminCount).Error; err != nil {
			return fmt.Errorf("error counting admins: %w", err)
		}
		if adminCount <= 1 {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Account Modify",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Blocked", Body: []string{"Cannot demote the last remaining admin."}}},
			})
			return fmt.Errorf("cannot demote the last remaining admin")
		}
	}

	if newRole != "" {
		u.Role = newRole
	}
	if strings.TrimSpace(oshOnlyRaw) != "" {
		v, err := parseBoolFlag(oshOnlyRaw)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Account Modify",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Invalid oshOnly", Body: []string{"--oshOnly must be true or false"}}},
			})
			return nil
		}
		u.OSHOnly = v
	}
	if strings.TrimSpace(superOwnerRaw) != "" {
		v, err := parseBoolFlag(superOwnerRaw)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Account Modify",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Invalid superOwner", Body: []string{"--superOwner must be true or false"}}},
			})
			return nil
		}
		u.SuperOwner = v
	}

	if err := db.Save(&u).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to update user system role."}}},
		})
		return err
	}

	if err := system.UpdateSudoers(&u); err != nil {
		log := slog.Default()
		log.Error("sudoers_update_failed", slog.String("user", u.Username), slog.String("error", err.Error()))
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "warning",
			Sections:  []console.SectionContent{{SubTitle: "Warning", Body: []string{fmt.Sprintf("User role updated but sudoers file could not be updated: %v. Contact your admin.", err)}}},
		})
		return err
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Account Modify",
		BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{
			fmt.Sprintf("User '%s' updated.", username),
			fmt.Sprintf("system role: %s", u.Role),
			fmt.Sprintf("osh-only: %t", u.OSHOnly),
			fmt.Sprintf("superowner: %t", u.SuperOwner),
		}}},
	})

	return nil
}

func parseBoolFlag(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "true", "1", "yes", "on":
		return true, nil
	case "false", "0", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid boolean value: %s", value)
	}
}
