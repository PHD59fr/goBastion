package commands

import (
	"fmt"
	"regexp"
	"strings"

	"goBastion/models"
	"goBastion/utils"
	"goBastion/utils/console"

	"gorm.io/gorm"
)

func stripANSI(s string) string {
	ansiRegex := regexp.MustCompile("\x1b\\[[0-9;]*m")
	return ansiRegex.ReplaceAllString(s, "")
}

func splitCommandLine(line string) (string, string) {
	re := regexp.MustCompile(`\s{2,}`)
	parts := re.Split(line, 2)
	if len(parts) < 2 {
		return line, ""
	}
	return parts[0], parts[1]
}

func DisplayHelp(db *gorm.DB, user models.User) {
	var sections []console.SectionContent

	// MANAGE YOUR ACCOUNT
	sections = append(sections, console.SectionContent{
		SubTitle:      "> MANAGE YOUR ACCOUNT",
		SubTitleColor: utils.FgYellowB,
		SubSubTitle:   " Ingress (you → bastion):",
		Body: []string{
			" " + utils.FgGreen("-") + " selfListIngressKeys       List your ingress keys",
			" " + utils.FgGreen("-") + " selfAddIngressKey         Add a new ingress key",
			" " + utils.FgGreen("-") + " selfDelIngressKey         Delete an ingress key",
		},
	})
	sections = append(sections, console.SectionContent{
		SubTitle:      "",
		SubTitleColor: utils.FgYellowB,
		SubSubTitle:   " Egress (bastion → server):",
		Body: []string{
			" " + utils.FgGreen("-") + " selfListEgressKeys             List your egress keys",
			" " + utils.FgGreen("-") + " selfGenerateEgressKey          Generate a new egress key",
			" " + utils.FgGreen("-") + " selfRemoveHostFromKnownHosts   Remove Host to Known_hosts file",
		},
	})
	sections = append(sections, console.SectionContent{
		SubTitle:      "",
		SubTitleColor: utils.FgYellowB,
		SubSubTitle:   " Server accesses (personal):",
		Body: []string{
			" " + utils.FgGreen("-") + " selfListAccesses          List your personal accesses",
			" " + utils.FgGreen("-") + " selfAddAccess             Add a personal access",
			" " + utils.FgGreen("-") + " selfDelAccess             Delete a personal access",
		},
	})
	sections = append(sections, console.SectionContent{
		SubTitle:      "",
		SubTitleColor: utils.FgYellowB,
		SubSubTitle:   " Server alias (personal):",
		Body: []string{
			" " + utils.FgGreen("-") + " selfListAliases           List your personal aliases",
			" " + utils.FgGreen("-") + " selfAddAlias              Add a personal alias",
			" " + utils.FgGreen("-") + " selfDelAlias              Delete a personal alias",
		},
	})

	// TTY SESSIONS
	sections = append(sections, console.SectionContent{
		SubTitle:      "> TTY SESSIONS",
		SubTitleColor: utils.FgCyanB,
		SubSubTitle:   "",
		Body: []string{
			" " + utils.FgGreen("-") + " ttyList                   List recorded tty sessions",
			" " + utils.FgGreen("-") + " ttyPlay                   Read a recorded tty session",
		},
	})

	// MANAGE OTHER ACCOUNTS (admin only)
	if user.IsAdmin() {
		sections = append(sections, console.SectionContent{
			SubTitle:      "> MANAGE OTHER ACCOUNTS (admin only)",
			SubTitleColor: utils.FgRedB,
			SubSubTitle:   " Accounts:",
			Body: []string{
				" " + utils.FgGreen("-") + " accountList             List all accounts",
				" " + utils.FgGreen("-") + " accountInfo             Show account info",
				" " + utils.FgGreen("-") + " accountCreate           Create a new account",
				" " + utils.FgGreen("-") + " accountModify           Modify an account",
				" " + utils.FgGreen("-") + " accountDelete           Delete an account",
			},
		})
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgRedB,
			SubSubTitle:   " Account keys:",
			Body: []string{
				" " + utils.FgGreen("-") + " accountListIngressKeys  List account ingress keys",
				" " + utils.FgGreen("-") + " accountListEgressKeys   List account egress keys",
			},
		})
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgRedB,
			SubSubTitle:   " Account accesses:",
			Body: []string{
				" " + utils.FgGreen("-") + " accountListAccess       List account accesses",
				" " + utils.FgGreen("-") + " accountAddAccess        Add access to an account",
				" " + utils.FgGreen("-") + " accountDelAccess        Remove access from an account",
				" " + utils.FgGreen("-") + " whoHasAccessTo          List accounts with access to a server",
			},
		})
	}

	// MANAGE GROUPS
	sections = append(sections, console.SectionContent{
		SubTitle:      "> MANAGE GROUPS",
		SubTitleColor: utils.FgMagentaB,
		SubSubTitle:   " Groups:",
		Body: []string{
			" " + utils.FgGreen("-") + " groupInfo               Show group info",
			" " + utils.FgGreen("-") + " groupList               List groups",
		},
	})
	if user.IsAdmin() {
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgMagentaB,
			SubSubTitle:   "",
			Body: []string{
				" " + utils.FgGreen("-") + " groupCreate             Create a new group",
				" " + utils.FgGreen("-") + " groupDelete             Delete a group",
			},
		})
	}
	if user.IsAdmin() || isGroupManager(db, user) {
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgWhiteB,
			SubSubTitle:   " Group member management:",
			Body: []string{
				" " + utils.FgGreen("-") + " groupAddMember          Add a member to a group",
				" " + utils.FgGreen("-") + " groupDelMember          Remove a member from a group",
			},
		})
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgWhiteB,
			SubSubTitle:   " Group egress keys:",
			Body: []string{
				" " + utils.FgGreen("-") + " groupGenerateEgressKey  Generate a new group egress key",
				" " + utils.FgGreen("-") + " groupListEgressKeys     List group egress keys",
			},
		})
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgWhiteB,
			SubSubTitle:   " Group accesses:",
			Body: []string{
				" " + utils.FgGreen("-") + " groupListAccess         List access of the group",
				" " + utils.FgGreen("-") + " groupAddAccess          Add access to a group",
				" " + utils.FgGreen("-") + " groupDelAccess          Remove access from a group",
			},
		})
	}

	// GROUP ALIASES
	bodyGroupAlias := []string{}

	if isGroupManager(db, user) {
		bodyGroupAlias = append(bodyGroupAlias,
			" "+utils.FgGreen("-")+" groupAddAlias           Add a group alias",
			" "+utils.FgGreen("-")+" groupDelAlias           Delete a group alias",
			" "+utils.FgGreen("-")+" groupListAliases        List group aliases",
		)
	} else if isGroupMember(db, user) {
		bodyGroupAlias = append(bodyGroupAlias,
			" "+utils.FgGreen("-")+" groupListAliases        List group aliases",
		)
	}

	if len(bodyGroupAlias) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgWhiteB,
			SubSubTitle:   " Group alias (group):",
			Body:          bodyGroupAlias,
		})
	}

	// MISC COMMANDS
	sections = append(sections, console.SectionContent{
		SubTitle:      "> MISC COMMANDS",
		SubTitleColor: utils.FgWhiteB,
		SubSubTitle:   " Basic commands:",
		Body: []string{
			" " + utils.FgGreen("-") + " help                   Display this help message",
			" " + utils.FgGreen("-") + " info                   Show application info",
			" " + utils.FgGreen("-") + " exit                   Exit the application",
		},
	})

	globalMaxCmdLen := 0
	for _, section := range sections {
		for _, line := range section.Body {
			cmd, _ := splitCommandLine(line)
			visibleCmd := strings.TrimSpace(stripANSI(cmd))
			if len(visibleCmd) > globalMaxCmdLen {
				globalMaxCmdLen = len(visibleCmd)
			}
		}
	}

	for i, section := range sections {
		for j, line := range section.Body {
			cmd, desc := splitCommandLine(line)
			visibleCmd := strings.TrimSpace(stripANSI(cmd))
			pad := globalMaxCmdLen - len(visibleCmd)
			alignedLine := cmd + strings.Repeat(" ", pad) + "  " + desc
			sections[i].Body[j] = alignedLine
		}
	}

	helpBlock := console.ContentBlock{
		Title:     "▶ help",
		BlockType: "help",
		Sections:  sections,
		Footer:    "",
	}
	console.DisplayBlock(helpBlock)
}

func isGroupManager(db *gorm.DB, user models.User) bool {
	var userGroup models.UserGroup
	if err := db.Where("user_id = ?", user.ID).First(&userGroup).Error; err != nil {
		return false
	}
	return userGroup.IsOwner() || userGroup.IsACLKeeper() || userGroup.IsGateKeeper()
}

func isGroupMember(db *gorm.DB, user models.User) bool {
	var userGroup models.UserGroup
	if err := db.Where("user_id = ?", user.ID).First(&userGroup).Error; err != nil {
		return false
	}
	return userGroup.IsMember() || userGroup.IsOwner() || userGroup.IsACLKeeper() || userGroup.IsGateKeeper()
}

func DisplayInfo() {
	fmt.Println("goBastion - Version 1.0")
}
