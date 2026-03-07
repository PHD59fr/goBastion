package group

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/sshkey"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// GroupGenerateEgressKey generates a new SSH egress key pair for a group.
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
		return fmt.Errorf("access denied for %s", currentUser.Username)
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
