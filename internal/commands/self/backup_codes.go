package self

import (
	"fmt"
	"log/slog"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/totp"

	"gorm.io/gorm"
)

// SelfGenerateBackupCodes generates new TOTP backup codes for the current user.
// Any previously existing codes are invalidated.
func SelfGenerateBackupCodes(db *gorm.DB, user *models.User, log *slog.Logger) error {
	plainCodes, jsonHashes, err := totp.GenerateBackupCodes()
	if err != nil {
		return fmt.Errorf("failed to generate backup codes: %w", err)
	}

	if err := db.Model(user).Update("backup_codes", jsonHashes).Error; err != nil {
		return fmt.Errorf("failed to save backup codes: %w", err)
	}
	user.BackupCodes = jsonHashes

	log.Info("backup codes generated", slog.String("user", user.Username))

	// Display codes grouped in 2 columns
	var lines []string
	for i := 0; i < len(plainCodes); i += 2 {
		line := fmt.Sprintf("  %s", plainCodes[i])
		if i+1 < len(plainCodes) {
			line += fmt.Sprintf("    %s", plainCodes[i+1])
		}
		lines = append(lines, line)
	}

	console.DisplayBlock(console.ContentBlock{
		Title:     "TOTP Backup Codes",
		BlockType: "success",
		Sections: []console.SectionContent{
			{SubTitle: "Save these codes in a safe place", Body: lines},
			{SubTitle: "Warning", Body: []string{
				"Each code can only be used once.",
				"These codes will not be shown again.",
				"Generating new codes invalidates all previous codes.",
			}},
		},
	})
	return nil
}

// SelfShowBackupCodeCount shows how many backup codes remain.
func SelfShowBackupCodeCount(db *gorm.DB, user *models.User) error {
	count := totp.CountBackupCodes(user.BackupCodes)
	if count == 0 {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Backup Codes",
			BlockType: "info",
			Sections: []console.SectionContent{
				{SubTitle: "Status", Body: []string{strings.Repeat(" ", 2) + "No backup codes configured. Use selfGenerateBackupCodes to create them."}},
			},
		})
	} else {
		console.DisplayBlock(console.ContentBlock{
			Title:     "Backup Codes",
			BlockType: "info",
			Sections: []console.SectionContent{
				{SubTitle: "Status", Body: []string{fmt.Sprintf("  %d backup code(s) remaining.", count)}},
			},
		})
	}
	return nil
}
