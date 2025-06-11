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

var (
	ansiRegex  = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	spaceRegex = regexp.MustCompile(`\s{2,}`)
)

func stripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

func splitCommandLine(line string) (string, string) {
	parts := spaceRegex.Split(line, 2)
	if len(parts) < 2 {
		return line, ""
	}
	return parts[0], parts[1]
}

func DisplayHelp(db *gorm.DB, user models.User) {
	var sections []console.SectionContent

	hasPerm := func(perm string) bool {
		return user.CanDo(db, perm, "")
	}

	// MANAGE YOUR ACCOUNT
	var manageyouraccountBody []string
	if hasPerm("selfListIngressKeys") {
		manageyouraccountBody = append(manageyouraccountBody, " "+utils.FgGreen("-")+" selfListIngressKeys       List your ingress keys")
	}
	if hasPerm("selfAddIngressKey") {
		manageyouraccountBody = append(manageyouraccountBody, " "+utils.FgGreen("-")+" selfAddIngressKey         Add a new ingress key")
	}
	if hasPerm("selfDelIngressKey") {
		manageyouraccountBody = append(manageyouraccountBody, " "+utils.FgGreen("-")+" selfDelIngressKey         Delete an ingress key")
	}
	if len(manageyouraccountBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "> MANAGE YOUR ACCOUNT",
			SubTitleColor: utils.FgYellowB,
			SubSubTitle:   " Ingress (you → bastion):",
			Body:          manageyouraccountBody,
		})
	}

	// EGRESS KEYS
	var egressBody []string
	if hasPerm("selfListEgressKeys") {
		egressBody = append(egressBody, " "+utils.FgGreen("-")+" selfListEgressKeys             List your egress keys")
	}
	if hasPerm("selfGenerateEgressKey") {
		egressBody = append(egressBody, " "+utils.FgGreen("-")+" selfGenerateEgressKey          Generate a new egress key")
	}
	if hasPerm("selfRemoveHostFromKnownHosts") {
		egressBody = append(egressBody, " "+utils.FgGreen("-")+" selfRemoveHostFromKnownHosts   Remove host from Known_hosts file")
	}
	if len(egressBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgYellowB,
			SubSubTitle:   " Egress (bastion → server):",
			Body:          egressBody,
		})
	}

	// Server accesses (personal)
	var accessesBody []string
	if hasPerm("selfListAccesses") {
		accessesBody = append(accessesBody, " "+utils.FgGreen("-")+" selfListAccesses          List your personal accesses")
	}
	if hasPerm("selfAddAccess") {
		accessesBody = append(accessesBody, " "+utils.FgGreen("-")+" selfAddAccess             Add a personal access")
	}
	if hasPerm("selfDelAccess") {
		accessesBody = append(accessesBody, " "+utils.FgGreen("-")+" selfDelAccess             Delete a personal access")
	}
	if len(accessesBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgYellowB,
			SubSubTitle:   " Server accesses (personal):",
			Body:          accessesBody,
		})
	}

	// Server alias (personal)
	var aliasesBody []string
	if hasPerm("selfListAliases") {
		aliasesBody = append(aliasesBody, " "+utils.FgGreen("-")+" selfListAliases           List your personal aliases")
	}
	if hasPerm("selfAddAlias") {
		aliasesBody = append(aliasesBody, " "+utils.FgGreen("-")+" selfAddAlias              Add a personal alias")
	}
	if hasPerm("selfDelAlias") {
		aliasesBody = append(aliasesBody, " "+utils.FgGreen("-")+" selfDelAlias              Delete a personal alias")
	}
	if len(aliasesBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgYellowB,
			SubSubTitle:   " Server alias (personal):",
			Body:          aliasesBody,
		})
	}

	// TTY SESSIONS
	var ttyBody []string
	if hasPerm("ttyList") {
		ttyBody = append(ttyBody, " "+utils.FgGreen("-")+" ttyList                   List recorded tty sessions")
	}
	if hasPerm("ttyPlay") {
		ttyBody = append(ttyBody, " "+utils.FgGreen("-")+" ttyPlay                   Replay a recorded tty session")
	}
	if len(ttyBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "> TTY SESSIONS",
			SubTitleColor: utils.FgCyanB,
			SubSubTitle:   "",
			Body:          ttyBody,
		})
	}

	// MANAGE OTHER ACCOUNTS
	var manageAccountsBody []string
	if hasPerm("accountList") {
		manageAccountsBody = append(manageAccountsBody, " "+utils.FgGreen("-")+" accountList             List all accounts")
	}
	if hasPerm("accountInfo") {
		manageAccountsBody = append(manageAccountsBody, " "+utils.FgGreen("-")+" accountInfo             Show account info")
	}
	if hasPerm("accountCreate") {
		manageAccountsBody = append(manageAccountsBody, " "+utils.FgGreen("-")+" accountCreate           Create a new account")
	}
	if hasPerm("accountModify") {
		manageAccountsBody = append(manageAccountsBody, " "+utils.FgGreen("-")+" accountModify           Modify an account")
	}
	if hasPerm("accountDelete") {
		manageAccountsBody = append(manageAccountsBody, " "+utils.FgGreen("-")+" accountDelete           Delete an account")
	}
	if len(manageAccountsBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "> MANAGE OTHER ACCOUNTS",
			SubTitleColor: utils.FgRedB,
			SubSubTitle:   " Accounts:",
			Body:          manageAccountsBody,
		})
	}

	// ACCOUNT KEYS
	var accountKeysBody []string
	if hasPerm("accountListIngressKeys") {
		accountKeysBody = append(accountKeysBody, " "+utils.FgGreen("-")+" accountListIngressKeys  List account ingress keys")
	}
	if hasPerm("accountListEgressKeys") {
		accountKeysBody = append(accountKeysBody, " "+utils.FgGreen("-")+" accountListEgressKeys   List account egress keys")
	}
	if len(accountKeysBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgRedB,
			SubSubTitle:   " Account keys:",
			Body:          accountKeysBody,
		})
	}

	// ACCOUNT ACCESSES
	var accountAccessBody []string
	if hasPerm("accountListAccess") {
		accountAccessBody = append(accountAccessBody, " "+utils.FgGreen("-")+" accountListAccess       List account accesses")
	}
	if hasPerm("accountAddAccess") {
		accountAccessBody = append(accountAccessBody, " "+utils.FgGreen("-")+" accountAddAccess        Add access to an account")
	}
	if hasPerm("accountDelAccess") {
		accountAccessBody = append(accountAccessBody, " "+utils.FgGreen("-")+" accountDelAccess        Remove access from an account")
	}
	if hasPerm("whoHasAccessTo") {
		accountAccessBody = append(accountAccessBody, " "+utils.FgGreen("-")+" whoHasAccessTo          List accounts with access to a server")
	}
	if len(accountAccessBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgRedB,
			SubSubTitle:   " Account accesses:",
			Body:          accountAccessBody,
		})
	}

	// MANAGE GROUPS
	var groupBody []string
	if hasPerm("groupInfo") {
		groupBody = append(groupBody, " "+utils.FgGreen("-")+" groupInfo               Show group info")
	}
	if hasPerm("groupList") {
		groupBody = append(groupBody, " "+utils.FgGreen("-")+" groupList               List groups")
	}
	if len(groupBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "> MANAGE GROUPS",
			SubTitleColor: utils.FgMagentaB,
			SubSubTitle:   " Groups:",
			Body:          groupBody,
		})
	}

	var groupManageBody []string
	if hasPerm("groupCreate") {
		groupManageBody = append(groupManageBody, " "+utils.FgGreen("-")+" groupCreate             Create a new group")
	}
	if hasPerm("groupDelete") {
		groupManageBody = append(groupManageBody, " "+utils.FgGreen("-")+" groupDelete             Delete a group")
	}
	if len(groupManageBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgMagentaB,
			SubSubTitle:   "",
			Body:          groupManageBody,
		})
	}

	// GROUP MEMBER MANAGEMENT
	var groupMemberBody []string
	if hasPerm("groupAddMember") {
		groupMemberBody = append(groupMemberBody, " "+utils.FgGreen("-")+" groupAddMember          Add a member to a group")
	}
	if hasPerm("groupDelMember") {
		groupMemberBody = append(groupMemberBody, " "+utils.FgGreen("-")+" groupDelMember          Remove a member from a group")
	}
	if len(groupMemberBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgWhiteB,
			SubSubTitle:   " Group member management:",
			Body:          groupMemberBody,
		})
	}

	// GROUP EGRESS KEYS
	var groupEgressBody []string
	if hasPerm("groupGenerateEgressKey") {
		groupEgressBody = append(groupEgressBody, " "+utils.FgGreen("-")+" groupGenerateEgressKey  Generate a new group egress key")
	}
	if hasPerm("groupListEgressKeys") {
		groupEgressBody = append(groupEgressBody, " "+utils.FgGreen("-")+" groupListEgressKeys     List group egress keys")
	}
	if len(groupEgressBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgWhiteB,
			SubSubTitle:   " Group egress keys:",
			Body:          groupEgressBody,
		})
	}

	// GROUP ACCESSES
	var groupAccessBody []string
	if hasPerm("groupListAccesses") {
		groupAccessBody = append(groupAccessBody, " "+utils.FgGreen("-")+" groupListAccesses         List accesses of the group")
	}
	if hasPerm("groupAddAccess") {
		groupAccessBody = append(groupAccessBody, " "+utils.FgGreen("-")+" groupAddAccess          Add access to a group")
	}
	if hasPerm("groupDelAccess") {
		groupAccessBody = append(groupAccessBody, " "+utils.FgGreen("-")+" groupDelAccess          Remove access from a group")
	}
	if len(groupAccessBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "",
			SubTitleColor: utils.FgWhiteB,
			SubSubTitle:   " Group accesses:",
			Body:          groupAccessBody,
		})
	}

	// GROUP ALIASES
	var bodyGroupAlias []string
	if hasPerm("groupAddAlias") {
		bodyGroupAlias = append(bodyGroupAlias, " "+utils.FgGreen("-")+" groupAddAlias           Add a group alias")
	}
	if hasPerm("groupDelAlias") {
		bodyGroupAlias = append(bodyGroupAlias, " "+utils.FgGreen("-")+" groupDelAlias           Delete a group alias")
	}
	if hasPerm("groupListAliases") {
		bodyGroupAlias = append(bodyGroupAlias, " "+utils.FgGreen("-")+" groupListAliases        List group aliases")
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
	var miscBody []string
	if hasPerm("help") {
		miscBody = append(miscBody, " "+utils.FgGreen("-")+" help                   Display this help message")
	}
	if hasPerm("info") {
		miscBody = append(miscBody, " "+utils.FgGreen("-")+" info                   Show application info")
	}
	if hasPerm("exit") {
		miscBody = append(miscBody, " "+utils.FgGreen("-")+" exit                   Exit the application")
	}
	if len(miscBody) > 0 {
		sections = append(sections, console.SectionContent{
			SubTitle:      "> MISC COMMANDS",
			SubTitleColor: utils.FgWhiteB,
			SubSubTitle:   " Basic commands:",
			Body:          miscBody,
		})
	}

	// Align lines for formatting
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
			sections[i].Body[j] = cmd + strings.Repeat(" ", pad) + "  " + desc
		}
	}

	// Display help
	console.DisplayBlock(console.ContentBlock{
		Title:     "▶ help",
		BlockType: "help",
		Sections:  sections,
	})
}

func DisplayInfo() {
	fmt.Println("goBastion - Version 1.0")
}
