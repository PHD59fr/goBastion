package self

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
	"goBastion/internal/utils/cryptokey"
	"goBastion/internal/utils/sshkey"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
	"gorm.io/gorm"
)

// SelfGenerateEgressKey generates a new SSH egress key pair for the current user.
func SelfGenerateEgressKey(db *gorm.DB, user *models.User, args []string) error {
	fs := flag.NewFlagSet("selfGenerateEgressKey", flag.ContinueOnError)
	var keyType string
	var keySize int
	fs.StringVar(&keyType, "type", "ed25519", "Default: ed25519 - Key type")
	fs.IntVar(&keySize, "size", 256, "Default: 256 - Key size")
	if err := fs.Parse(args); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage Error", Body: []string{"Error parsing flags. Usage: selfGenerateEgressKey --type <keytype> --size <keysize>"}},
			},
		})
		return err
	}
	if strings.TrimSpace(keyType) == "" || keySize <= 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Usage", Body: []string{"selfGenerateEgressKey --type <keytype> --size <keysize>"}},
			},
		})
		return nil
	}
	validKeyTypes := map[string]bool{"ed25519": true, "rsa": true, "ecdsa": true}
	if !validKeyTypes[keyType] {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Invalid Key Type", Body: []string{"Key type must be one of: ed25519, rsa, ecdsa"}},
			},
		})
		return nil
	}
	tmpDir := fmt.Sprintf("/home/%s/.tmp", user.Username)
	if err := os.MkdirAll(tmpDir, 0700); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to create temporary directory. Please contact admin."}},
			},
		})
		return fmt.Errorf("error creating .tmp directory: %w", err)
	}
	tmpFile := fmt.Sprintf("%s/sshkey_%s.pem", tmpDir, uuid.New().String())
	cmd := exec.Command("ssh-keygen", "-t", keyType, "-b", strconv.Itoa(keySize), "-f", tmpFile, "-N", "")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to generate SSH key. Please contact admin."}},
			},
		})
		return fmt.Errorf("error generating SSH key: %v, %s", err, stderr.String())
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()
	privKeyStr, err := os.ReadFile(tmpFile)
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to read private key. Please contact admin."}},
			},
		})
		return fmt.Errorf("error reading private key: %v", err)
	}
	pubKeyStr, err := os.ReadFile(tmpFile + ".pub")
	if err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to read public key. Please contact admin."}},
			},
		})
		return fmt.Errorf("error reading public key: %v", err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKeyStr)
	if err != nil || pubKey == nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Invalid SSH public key."}},
			},
		})
		return fmt.Errorf("invalid SSH key: %s", err)
	}
	sha256Fingerprint := sha256.Sum256(pubKey.Marshal())
	fingerprint := base64.StdEncoding.EncodeToString(sha256Fingerprint[:])
	keySize = sshkey.GetKeySize(pubKey)

	privKey := strings.TrimSpace(string(privKeyStr))
	encrypted, encErr := cryptokey.ReEncryptIfNeeded(privKey)
	if encErr != nil {
		return fmt.Errorf("error encrypting private key: %v", encErr)
	}

	newKey := models.SelfEgressKey{
		UserID:      user.ID,
		PubKey:      strings.TrimSpace(string(pubKeyStr)),
		PrivKey:     encrypted,
		Type:        keyType,
		Size:        keySize,
		Fingerprint: fingerprint,
	}
	if err := db.Create(&newKey).Error; err != nil {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Generate Egress Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Error", Body: []string{"Failed to store key in database. Please contact admin."}},
			},
		})
		return fmt.Errorf("error storing key in database: %v", err)
	}
	console.DisplayBlock(console.ContentBlock{
		Title:     "Generate Egress Key",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Success", Body: []string{"Egress key generated and stored in the database."}},
		},
	})
	return nil
}
