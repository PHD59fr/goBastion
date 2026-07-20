package group

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"strconv"
	"time"

	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/validation"

	"gorm.io/gorm"
)

// AddGuestAccess grants a guest-role user granular access to a specific
// server within a group, using the group's egress key.
func AddGuestAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddGuestAccess", flag.ContinueOnError)
	var groupName, account, server, remoteUser, comment, allowedFrom, protocol string
	var port int64
	var ttlDays int
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&account, "account", "", "Username to grant guest access to")
	fs.StringVar(&server, "host", "", "Server to grant access for")
	fs.StringVar(&remoteUser, "user", "", "Remote username on the target server")
	fs.Int64Var(&port, "port", 22, "Remote port")
	fs.StringVar(&comment, "comment", "", "Comment")
	fs.StringVar(&allowedFrom, "from", "", "Allowed source CIDRs (comma-separated)")
	fs.IntVar(&ttlDays, "ttl", 0, "Access expiry in days (0 = never)")
	fs.StringVar(&protocol, "protocol", "ssh", "Protocol: ssh, scpupload, scpdownload, sftp, rsync")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || groupName == "" || account == "" || server == "" || remoteUser == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest Access",
			BlockType: "error",
			Sections: []console.SectionContent{{SubTitle: "Usage", Body: []string{
				"Usage: groupAddGuestAccess --group <group> --account <user> --host <server> --user <remote_user> [--port <port>] [--protocol <proto>] [--ttl <days>] [--comment <text>] [--from <CIDRs>]",
			}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupAddGuestAccess", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to manage guest accesses for this group."}}},
		})
		return fmt.Errorf("access denied for %s", currentUser.Username)
	}

	if !validation.IsValidHost(server) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Server", Body: []string{"Server hostname/IP contains invalid characters."}}},
		})
		return nil
	}
	if !validation.IsValidPort(port) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Port", Body: []string{"Port must be between 1 and 65535"}}},
		})
		return nil
	}
	if !validation.IsValidProtocol(protocol) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid Protocol", Body: []string{"Protocol must be one of: ssh, scpupload, scpdownload, sftp, rsync"}}},
		})
		return nil
	}
	if !validation.IsValidCIDRs(allowedFrom) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid CIDRs", Body: []string{"--from must be a comma-separated list of valid CIDRs"}}},
		})
		return nil
	}
	if ttlDays < 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid TTL", Body: []string{"TTL must be zero (never) or positive"}}},
		})
		return nil
	}

	// TCP connectivity check (private targets only).
	addr := net.JoinHostPort(server, strconv.FormatInt(port, 10))
	if validation.IsPrivateOrReservedTarget(server) {
		conn, err := net.DialTimeout("tcp", addr, config.Get().Proxy.TCPConnectTimeout)
		if err != nil {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Add Guest Access",
				BlockType: "warning",
				Sections: []console.SectionContent{{
					SubTitle: "Connectivity Warning",
					Body:     []string{fmt.Sprintf("Could not reach %s: %v. Access saved anyway.", addr, err)},
				}},
			})
		} else {
			_ = conn.Close()
		}
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group '%s' not found.", groupName)}}},
		})
		return err
	}

	var targetUser models.User
	if err := db.Where("username = ?", account).First(&targetUser).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User '%s' not found.", account)}}},
		})
		return err
	}

	// Verify the target user is a guest in this group.
	var ug models.UserGroup
	if err := db.Where("user_id = ? AND group_id = ? AND deleted_at IS NULL", targetUser.ID, group.ID).First(&ug).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not a Member", Body: []string{fmt.Sprintf("User '%s' is not a member of group '%s'. Add them first with groupAddMember.", account, groupName)}}},
		})
		return err
	}
	if ug.Role != models.GroupRoleGuest {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Wrong Role", Body: []string{fmt.Sprintf("User '%s' has role '%s' in group '%s', not 'guest'. Guest access grants only apply to guest-role users.", account, ug.Role, groupName)}}},
		})
		return nil
	}

	// Check for duplicate.
	var existing models.GroupGuestAccess
	if err := db.Where("group_id = ? AND user_id = ? AND server = ? AND port = ? AND username = ? AND deleted_at IS NULL",
		group.ID, targetUser.ID, server, port, remoteUser).First(&existing).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest Access",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Already Exists", Body: []string{"This guest access grant already exists."}}},
		})
		return nil
	}

	guestAccess := models.GroupGuestAccess{
		GroupID:     group.ID,
		UserID:      targetUser.ID,
		Username:    remoteUser,
		Server:      server,
		Port:        port,
		Protocol:    protocol,
		Comment:     comment,
		AllowedFrom: allowedFrom,
	}
	if ttlDays > 0 {
		t := time.Now().AddDate(0, 0, ttlDays)
		guestAccess.ExpiresAt = &t
	}

	if err := db.Create(&guestAccess).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Guest Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Failed to create guest access grant."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Guest Access",
		BlockType: "success",
		Sections: []console.SectionContent{{SubTitle: "Success", Body: []string{
			fmt.Sprintf("Guest access granted to '%s' for %s@%s:%d in group '%s'.", account, remoteUser, server, port, groupName),
			"Use groupListGuestAccesses to review.",
		}}},
	})
	return nil
}
