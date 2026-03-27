package group

import (
	"bytes"
	"flag"
	"fmt"
	"log/slog"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
)

// GroupSetMFA enables or disables JIT MFA requirement for a group.
// When enabled, users connecting via this group must pass a TOTP challenge even if TOTP is not globally enabled.
func GroupSetMFA(db *gorm.DB, currentUser *models.User, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("groupSetMFA", flag.ContinueOnError)
	var groupName string
	var required, optional bool
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.BoolVar(&required, "required", false, "Require MFA for this group")
	fs.BoolVar(&optional, "optional", false, "Remove MFA requirement for this group")
	var buf bytes.Buffer
	fs.SetOutput(&buf)

	if err := fs.Parse(args); err != nil || groupName == "" || (!required && !optional) || (required && optional) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Set MFA",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"groupSetMFA --group <name> --required|--optional"}}},
		})
		return nil
	}

	if !currentUser.CanDo(db, "groupSetMFA", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Set MFA",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"Only group owners or admins can set MFA policy."}}},
		})
		return nil
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Set MFA",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.", groupName)}}},
		})
		return err
	}

	mfaRequired := required && !optional
	if err := db.Model(&group).Update("mfa_required", mfaRequired).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Set MFA",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to update MFA setting."}}},
		})
		return err
	}

	status := "disabled"
	if mfaRequired {
		status = "enabled"
	}
	log.Info("group mfa policy updated",
		slog.String("admin", currentUser.Username),
		slog.String("group", groupName),
		slog.Bool("mfa_required", mfaRequired),
	)
	console.DisplayBlock(console.ContentBlock{
		Title:     "Group Set MFA",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{"JIT MFA " + status + " for group " + groupName}}},
	})
	return nil
}
