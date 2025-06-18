package commands

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"goBastion/utils/console"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"text/tabwriter"

	"goBastion/utils"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"goBastion/models"
	"goBastion/utils/sshkey"

	"gorm.io/gorm"
)

func GroupInfo(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupInfo", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Info",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupInfo --group <groupName>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupInfo", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Info",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to view group information."}}},
		})
		return fmt.Errorf("access denied for" + currentUser.Username)
	}

	var g models.Group
	if err := db.Where("name = ?", groupName).First(&g).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Info",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"Group not found."}}},
		})
		return err
	}

	var userGroups []models.UserGroup
	db.Preload("User").Where("group_id = ?", g.ID).Find(&userGroups)

	infoLines := []string{
		fmt.Sprintf("Group ID: %s", g.ID.String()),
		fmt.Sprintf("Name: %s", g.Name),
	}

	if len(userGroups) > 0 {
		infoLines = append(infoLines, "Members:")
		for _, ug := range userGroups {
			myRoles := utils.GetRoles(ug)
			roleColored := utils.BgBlueB("Member")
			if myRoles == "Owner" {
				roleColored = utils.BgRedB("Owner")
			}
			if myRoles == "ACL Keeper" {
				roleColored = utils.BgYellowB("ACL Keeper")
			}
			if myRoles == "Gate Keeper" {
				roleColored = utils.BgGreenB("Gate Keeper")
			}

			infoLines = append(infoLines, fmt.Sprintf(" - %s - %s", ug.User.Username, roleColored))
		}
	} else {
		infoLines = append(infoLines, "Members: None")
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Group Info",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Details", Body: infoLines}},
	})
	return nil
}

func GroupList(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("groupList", flag.ContinueOnError)
	all := fs.Bool("all", false, "List all groups")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage Error", Body: []string{"Usage: groupList [--all]"}}},
		})
		return err
	}

	if !user.CanDo(db, "groupList", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group List",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to list groups."}}},
		})
		return fmt.Errorf("access denied for " + user.Username)
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "#\tID\tName")

	if *all {
		var groups []models.Group
		db.Unscoped().Find(&groups)
		if len(groups) == 0 {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Group List",
				BlockType: "info",
				Sections:  []console.SectionContent{{SubTitle: "Information", Body: []string{"No groups found."}}},
			})
			return nil
		}
		for i, g := range groups {
			_, _ = fmt.Fprintf(w, "%d\t%s\t%s\n", i+1, g.ID.String(), g.Name)
		}
	} else {
		var userGroups []models.UserGroup
		db.Preload("Group").Where("user_id = ?", user.ID).Find(&userGroups)
		if len(userGroups) == 0 {
			console.DisplayBlock(console.ContentBlock{
				Title:     "Group List",
				BlockType: "info",
				Sections:  []console.SectionContent{{SubTitle: "Information", Body: []string{"You are not part of any groups."}}},
			})
			return nil
		}
		for i, ug := range userGroups {
			_, _ = fmt.Fprintf(w, "%d\t%s\t%s\n", i+1, ug.Group.ID.String(), ug.Group.Name)
		}
	}
	_ = w.Flush()

	console.DisplayBlock(console.ContentBlock{
		Title:     "Group List",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Groups", Body: strings.Split(strings.TrimSpace(buf.String()), "\n")}},
	})
	return nil
}

func GroupCreate(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupCreate", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupCreate --group <groupName>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupCreate", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to create groups."}}},
		})
		return fmt.Errorf("access denied for " + currentUser.Username)
	}

	var existingGroup models.Group
	if err := db.Unscoped().Where("name = ? AND deleted_at IS NULL", groupName).First(&existingGroup).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Exists", Body: []string{fmt.Sprintf("Group '%s' already exists.", groupName)}}},
		})
		return nil
	}

	g := models.Group{Name: groupName}
	if err := db.Create(&g).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Create",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Error creating group."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Group Create",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Group '%s' created successfully.", groupName)}}},
	})
	return nil
}

func GroupDelete(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupDelete", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupDelete --group <groupName>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupDelete", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Group Delete",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to delete groups."}}},
		})
		return fmt.Errorf("access denied for " + currentUser.Username)
	}

	db.Where("name = ?", groupName).Delete(&models.Group{})
	console.DisplayBlock(console.ContentBlock{
		Title:     "Group Delete",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Group '%s' deleted successfully.", groupName)}}},
	})
	return nil
}

func GroupAddMember(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddMember", flag.ContinueOnError)
	var groupName, username, role string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&username, "user", "", "Username to add")
	fs.StringVar(&role, "role", "", "Role (owner, aclkeeper, gatekeeper, member, guest)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" || strings.TrimSpace(username) == "" || strings.TrimSpace(role) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupAddMember --group <groupName> --user <username> --role <role>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupAddMember", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to add members to this group."}}},
		})
		return fmt.Errorf("access denied for " + currentUser.Username)
	}

	var g models.Group
	if err := db.Where("name = ?", groupName).First(&g).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("Group not found: %s", groupName)}}},
		})
		return err
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{fmt.Sprintf("User not found: %s", username)}}},
		})
		return err
	}

	var existingUG models.UserGroup
	if err := db.Where("user_id = ? AND group_id = ?", u.ID, g.ID).First(&existingUG).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Already Exists", Body: []string{fmt.Sprintf("User '%s' is already in group '%s'.", username, groupName)}}},
		})
		return nil
	}

	newUG := models.UserGroup{UserID: u.ID, GroupID: g.ID, Role: role}
	if err := db.Create(&newUG).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to add member to group."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Member",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("User '%s' added to group '%s' as '%s'.", username, groupName, role)}}},
	})
	return nil
}

func GroupDelMember(db *gorm.DB, currentUser *models.User, args []string) error {
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
		return err
	}

	if !currentUser.CanDo(db, "groupDelMember", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to remove members from this group."}}},
		})
		return fmt.Errorf("access denied for " + currentUser.Username)
	}

	var g models.Group
	if err := db.Where("name = ?", groupName).First(&g).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"Group not found."}}},
		})
		return err
	}

	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"User not found."}}},
		})
		return err
	}

	if err := db.Where("user_id = ? AND group_id = ?", u.ID, g.ID).Delete(&models.UserGroup{}).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Remove Member",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Failed to remove member from group."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Remove Member",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("User '%s' removed from group '%s'.", username, groupName)}}},
	})
	return nil
}

func GroupGenerateEgressKey(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupGenerateEgressKey", flag.ContinueOnError)
	var groupName, keyType string
	var keySize int

	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&keyType, "type", "ed25519", "Key type (e.g., rsa, ed25519)")
	fs.IntVar(&keySize, "size", 256, "Key size (e.g., 2048)")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupGenerateEgressKey --group <groupName> --type <keyType> --size <keySize>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupGenerateEgressKey", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to generate egress keys for this group."}}},
		})
		return fmt.Errorf("access denied for " + currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"Group not found."}}},
		})
		return err
	}

	tmpDir := fmt.Sprintf("/home/%s/.tmp", currentUser.Username)
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		return fmt.Errorf("error creating temporary directory: %v", err)
	}
	tmpFile := fmt.Sprintf("%s/sshkey_%s.pem", tmpDir, uuid.New().String())
	hostname, _ := os.Hostname()
	cmd := exec.Command("ssh-keygen", "-t", keyType, "-b", strconv.Itoa(keySize), "-C", groupName+"@"+hostname+":GROUP", "-f", tmpFile, "-N", "")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("error generating SSH key: %v, %s", err, stderr.String())
	}

	privKeyBytes, err := os.ReadFile(tmpFile)
	pubKeyBytes, errPub := os.ReadFile(tmpFile + ".pub")
	if err != nil || errPub != nil {
		return fmt.Errorf("error reading keys: %v %v", err, errPub)
	}

	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid SSH key: %v", err)
	}

	sha256Fingerprint := sha256.Sum256(parsedKey.Marshal())
	fingerprint := base64.StdEncoding.EncodeToString(sha256Fingerprint[:])
	keySize = sshkey.GetKeySize(parsedKey)
	_ = os.RemoveAll(tmpDir)

	newKey := models.GroupEgressKey{
		GroupID:     group.ID,
		PubKey:      strings.TrimSpace(string(pubKeyBytes)),
		PrivKey:     strings.TrimSpace(string(privKeyBytes)),
		Type:        keyType,
		Size:        keySize,
		Fingerprint: fingerprint,
	}
	if err = db.Create(&newKey).Error; err != nil {
		return fmt.Errorf("error storing group egress key in database: %v", err)
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Generate Egress Key",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Egress key successfully generated for group '%s'.", groupName)}}},
	})
	return nil
}

func GroupListEgressKeys(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupListEgressKeys", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Egress Keys",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupListEgressKeys --group <groupName>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupListEgressKeys", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Egress Keys",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to list egress keys for this group."}}},
		})
		return fmt.Errorf("access denied for " + currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Egress Keys",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"Group not found."}}},
		})
		return err
	}

	var keys []models.GroupEgressKey
	if err := db.Where("group_id = ?", group.ID).Find(&keys).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Egress Keys",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Error", Body: []string{"Error fetching egress keys."}}},
		})
		return err
	}

	if len(keys) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Egress Keys",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "No Keys", Body: []string{fmt.Sprintf("No egress keys found for group '%s'.", groupName)}}},
		})
		return nil
	}

	var sections []console.SectionContent
	for _, key := range keys {
		section := console.SectionContent{
			SubTitle: fmt.Sprintf("Key ID: %s", key.ID.String()),
			Body: []string{
				fmt.Sprintf("Type: %s", key.Type),
				fmt.Sprintf("Fingerprint: %s", key.Fingerprint),
				fmt.Sprintf("Size: %d", key.Size),
				fmt.Sprintf("Created At: %s", key.CreatedAt.Format("2006-01-02 15:04:05")),
				fmt.Sprintf("Public Key: %s", key.PubKey),
			},
		}
		sections = append(sections, section)
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "List Egress Keys",
		BlockType: "success",
		Sections:  sections,
	})
	return nil
}

func GroupAddAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddAccess", flag.ContinueOnError)
	var groupName, server, username, comment string
	var port int64
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&server, "server", "", "Server to add access for")
	fs.Int64Var(&port, "port", 22, "Port number")
	fs.StringVar(&username, "username", "", "Connection username")
	fs.StringVar(&comment, "comment", "", "Comment")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || groupName == "" || server == "" || username == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupAddAccess --group <groupName> --server <server> --port <port> --username <connection username> --comment <comment>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupAddAccess", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to add access for this group."}}},
		})
		return fmt.Errorf("access denied for " + currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"Group not found."}}},
		})
		return err
	}

	var existingAccess models.GroupAccess
	if err := db.Where("group_id = ? AND server = ? AND port = ? AND username = ?", group.ID, server, port, username).First(&existingAccess).Error; err == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Access",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "Info", Body: []string{"Access already exists for this group with the given server, port, and username."}}},
		})
		return nil
	}

	access := models.GroupAccess{
		GroupID:  group.ID,
		Server:   server,
		Port:     port,
		Username: username,
		Comment:  comment,
	}
	if err := db.Create(&access).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Failed to create group access."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Group Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Group access added for group '%s'.", groupName)}}},
	})
	return nil
}

func GroupDelAccess(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupDelAccess", flag.ContinueOnError)
	var groupName, accessIDStr string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&accessIDStr, "access", "", "Access ID to remove")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || groupName == "" || accessIDStr == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupDelAccess --group <groupName> --access <access_id>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupDelAccess", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to delete access for this group."}}},
		})
		return fmt.Errorf("access denied for " + currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"Group not found."}}},
		})
		return err
	}

	accessID, err := uuid.Parse(accessIDStr)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid ID", Body: []string{"Invalid access ID format."}}},
		})
		return err
	}

	if err := db.Where("id = ? AND group_id = ?", accessID, group.ID).Delete(&models.GroupAccess{}).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error deleting group access."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Group Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{fmt.Sprintf("Group access removed for group '%s'.", groupName)}}},
	})
	return nil
}

func GroupListAccesses(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupListAccesses", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupListAccesses --group <groupName>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupListAccesses", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to list accesses for this group."}}},
		})
		return fmt.Errorf("access denied for " + currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"Group not found."}}},
		})
		return err
	}

	var accesses []models.GroupAccess
	if err := db.Where("group_id = ?", group.ID).Find(&accesses).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Access",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error fetching group accesses."}}},
		})
		return err
	}

	if len(accesses) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Access",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "No Access", Body: []string{"No accesses found for this group."}}},
		})
		return nil
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tUsername\tServer\tPort\tComment\tLast Used\tCreated At")
	for _, access := range accesses {
		lastUsed := "Never"
		if !access.LastConnection.IsZero() {
			lastUsed = access.LastConnection.Format("2006-01-02 15:04:05")
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%d\t%s\t%s\t%s\n",
			access.ID.String(),
			access.Username,
			access.Server,
			access.Port,
			access.Comment,
			lastUsed,
			access.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush()

	console.DisplayBlock(console.ContentBlock{
		Title:     "List Group Access",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Accesses", Body: strings.Split(buf.String(), "\n")}},
	})
	return nil
}

func GroupAddAlias(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupAddAlias", flag.ContinueOnError)
	var groupName, alias, hostname string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&alias, "alias", "", "Alias")
	fs.StringVar(&hostname, "hostname", "", "Host name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" || strings.TrimSpace(alias) == "" || strings.TrimSpace(hostname) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupAddAlias --group <group_name> --alias <alias> --hostname <host_name>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupAddAlias", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to add aliases for this group."}}},
		})
		return fmt.Errorf("access denied for " + currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"Group not found."}}},
		})
		return err
	}

	newHost := models.Aliases{
		ResolveFrom: alias,
		Host:        hostname,
		GroupID:     &group.ID,
		UserID:      nil,
	}

	if err := db.Create(&newHost).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Add Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error adding alias."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Add Group Alias",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{"Alias added successfully."}}},
	})
	return nil
}

func GroupDelAlias(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupDelAlias", flag.ContinueOnError)
	var groupName, hostID string
	fs.StringVar(&groupName, "group", "", "Group name")
	fs.StringVar(&hostID, "id", "", "Alias ID")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" || strings.TrimSpace(hostID) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupDelAlias --group <group_name> --id <alias_id>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupDelAlias", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to delete aliases for this group."}}},
		})
		return fmt.Errorf("access denied for " + currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"Group not found."}}},
		})
		return err
	}

	parsedID, err := uuid.Parse(hostID)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Invalid ID", Body: []string{"Invalid alias ID format."}}},
		})
		return err
	}

	var host models.Aliases
	if err := db.Where("id = ? AND group_id = ?", parsedID, group.ID).First(&host).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"No alias found with the given ID for the current group."}}},
		})
		return err
	}

	if err := db.Delete(&host).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Delete Group Alias",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error deleting alias."}}},
		})
		return err
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "Delete Group Alias",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Success", Body: []string{"Alias deleted successfully."}}},
	})
	return nil
}

func GroupListAliases(db *gorm.DB, currentUser *models.User, args []string) error {
	fs := flag.NewFlagSet("groupListAliases", flag.ContinueOnError)
	var groupName string
	fs.StringVar(&groupName, "group", "", "Group name")
	var flagOutput bytes.Buffer
	fs.SetOutput(&flagOutput)

	if err := fs.Parse(args); err != nil || strings.TrimSpace(groupName) == "" {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Aliases",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Usage", Body: []string{"Usage: groupListAliases --group <group_name>"}}},
		})
		return err
	}

	if !currentUser.CanDo(db, "groupListAliases", groupName) {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Aliases",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Access Denied", Body: []string{"You do not have permission to list aliases for this group."}}},
		})
		return fmt.Errorf("access denied for " + currentUser.Username)
	}

	var group models.Group
	if err := db.Where("name = ?", groupName).First(&group).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Aliases",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Not Found", Body: []string{"Group not found."}}},
		})
		return err
	}

	var aliases []models.Aliases
	if err := db.Where("group_id = ?", group.ID).Find(&aliases).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Aliases",
			BlockType: "error",
			Sections:  []console.SectionContent{{SubTitle: "Database Error", Body: []string{"Error fetching aliases."}}},
		})
		return err
	}

	if len(aliases) == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "List Group Aliases",
			BlockType: "info",
			Sections:  []console.SectionContent{{SubTitle: "No Aliases", Body: []string{"No aliases found for this group."}}},
		})
		return nil
	}

	var buf bytes.Buffer
	w := tabwriter.NewWriter(&buf, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "ID\tAlias\tHostname\tAdded At")
	for _, alias := range aliases {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			alias.ID.String(),
			alias.ResolveFrom,
			alias.Host,
			alias.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}
	_ = w.Flush()

	console.DisplayBlock(console.ContentBlock{
		Title:     "List Group Aliases",
		BlockType: "success",
		Sections:  []console.SectionContent{{SubTitle: "Aliases", Body: strings.Split(buf.String(), "\n")}},
	})
	return nil
}
