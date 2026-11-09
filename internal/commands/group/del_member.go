package group

import (
	"bytes"
	"database/sql"
	"flag"
	"fmt"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// DelMember removes a user from a group.
func DelMember(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupDelMember", flag.ContinueOnError)
	var groupName, username string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&username, "user", "", "Username to remove")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" || strings.TrimSpace(username) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupDelMember --group <groupName> --user <username>"}}},
		})
		if err != nil {
			return err
		}
		return fmt.Errorf("invalid or missing arguments")
	}

	if !currentUser.CanDo(db, "groupDelMember", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to remove members from this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	var u models.User
	err := db.Transaction(func(tx *gorm.DB) error {
		db := tx

		var g models.Group
		if err := db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("name = ?", groupName).First(&g).Error; err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Remove Member",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found. Check spelling or run groupList.", groupName)}}},
			})
			return err
		}

		var actor models.User
		if err := db.First(&actor, "id = ?", currentUser.ID).Error; err != nil {
			return err
		}
		if !actor.Enabled || actor.SystemUser || !actor.CanDo(db, "groupDelMember", groupName) {
			return fmt.Errorf("group membership authority was revoked")
		}

		if err := db.Where("username = ?", username).First(&u).Error; err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Remove Member",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"User \"" + username + "\" not found. Check spelling or run accountList."}}},
			})
			return err
		}

		// Check membership exists
		var membership models.UserGroup
		if err := db.Where("user_id = ? AND group_id = ?", u.ID, g.ID).First(&membership).Error; err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Remove Member",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' is not a member of group '%s'.", username, groupName)}}},
			})
			return err
		}

		// Prevent removing the last owner
		if membership.Role == models.GroupRoleOwner {
			var ownerCount int64
			if err := db.Model(&models.UserGroup{}).Where("group_id = ? AND role = ? AND deleted_at IS NULL", g.ID, models.GroupRoleOwner).Count(&ownerCount).Error; err != nil {
				return fmt.Errorf("failed to count group owners: %w", err)
			}
			if ownerCount <= 1 {
				console.DisplayBlock(console.ContentBlock{
					Title:     "Remove Member",
					BlockType: "error",
					Sections:  []console.SectionContent{{SubTitle: "Blocked", Body: []string{"Cannot remove the last owner of the group. Promote another member to owner first."}}},
				})
				return fmt.Errorf("cannot remove the last owner of group '%s'", groupName)
			}
		}

		if err := db.Delete(&membership).Error; err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Remove Member",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to remove member from group."}}},
			})
			return err
		}
		// Revoke guest grants together with the membership so that re-adding the
		// user does not silently restore access. Soft deletion keeps the audit
		// trail and stays inside the membership transaction.
		if err := db.Where("user_id = ? AND group_id = ?", u.ID, g.ID).Delete(&models.GroupGuestAccess{}).Error; err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Remove Member",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to revoke the member's guest accesses."}}},
			})
			return fmt.Errorf("revoke guest accesses: %w", err)
		}
		if err := db.Where("user_id = ? AND group_id = ?", u.ID, g.ID).Delete(&models.GroupGuestDBAccess{}).Error; err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Remove Member",
				BlockType: "error",
				Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to revoke the member's guest DB accesses."}}},
			})
			return fmt.Errorf("revoke guest DB accesses: %w", err)
		}
		return nil
	}, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}

	models.InvalidateGroupsCache(currentUser.ID)
	models.InvalidateGroupsCache(u.ID)

	console.DisplayBlock(console.ContentBlock{
		Title:     "Remove Member",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("User '%s' removed from group '%s'.", username, groupName)}}},
	})
	return nil
}
