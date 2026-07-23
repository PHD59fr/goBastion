package config

import (
	"fmt"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/sshHostKey"

	"gorm.io/gorm"
)

// ShowSFTPProxyHostKey displays the stable host key used by sftp-session so
// administrators can distribute it to client teams.
func ShowSFTPProxyHostKey(db *gorm.DB, currentUser *models.User) error {
	if !currentUser.CanDo(db, "bastionConfig", "") {
		console.DisplayBlock(console.ContentBlock{
			Title:     "SFTP Proxy Host Key",
			BlockType: "error",
			Sections: []console.SectionContent{
				{SubTitle: "Access Denied", Body: []string{"You do not have permission to view the SFTP proxy host key."}},
			},
		})
		return nil
	}

	_, publicKey, fingerprint, err := sshHostKey.EnsureSFTPProxyHostKey(db, false)
	if err != nil {
		return fmt.Errorf("load SFTP proxy host key: %w", err)
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "SFTP Proxy Host Key",
		BlockType: "info",
		Sections: []console.SectionContent{
			{SubTitle: "Fingerprint", Body: []string{fingerprint}},
			{SubTitle: "Public Key", Body: []string{publicKey}},
			{SubTitle: "Admin Workflow", Body: []string{
				"Distribute this public key to client teams using sftp-session.",
				"Each client must pin it in known_hosts for the final SSH host alias they use with sftp, not the bastion hostname inside ProxyCommand.",
				"Rotate it with: /app/goBastion --regenerateSFTPProxyHostKey",
			}},
		},
	})
	return nil
}
