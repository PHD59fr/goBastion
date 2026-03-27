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

// AccountModify updates the system role of a user account.
func AccountModify(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("accountModify", flag.ContinueOnError)
	var username, newRole string
	fs.StringVar(&username, "user", "", "Username to modify")
	fs.StringVar(&newRole, "sysrole", "", "New system role (admin or user)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: accountModify --user <username> --sysrole <admin|user>"}}},
		})
		return err
	}

	if strings.TrimSpace(username) == "" || strings.TrimSpace(newRole) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Account Modify",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: accountModify --user <username> --sysrole <admin|user>"}}},
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

	newRole = strings.ToLower(newRole)
	if newRole != "admin" && newRole != "user" {
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
	if u.Role == models.RoleAdmin && newRole == models.RoleUser {
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

	u.Role = newRole
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
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("User '%s' system role updated to '%s'.", username, newRole)}}},
	})

	return nil
}
