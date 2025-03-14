package commands

import (
	"fmt"
	"goBastion/models"
	"goBastion/utils"

	"gorm.io/gorm"
)

func DisplayHelp(db *gorm.DB, user models.User) {
	fmt.Println(utils.FgCyan("╭───goBastion──────────────────────────────────────────────"))
	fmt.Println(utils.FgCyan("│ ") + utils.FgGreen("▶ help"))
	fmt.Println(utils.FgCyan("├──────────────────────────────────────────────────────────"))

	// Manage your account
	fmt.Println(utils.FgCyan("│") + utils.FgYellowB(" > MANAGE YOUR ACCOUNT"))
	fmt.Println(utils.FgCyan("│") + utils.FgWhite("    Ingress (you → bastion):"))
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "selfListIngressKeys", "List your ingress keys")
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "selfAddIngressKey", "Add a new ingress key")
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "selfDelIngressKey", "Delete an ingress key")

	fmt.Println(utils.FgCyan("│") + utils.FgWhite("    Egress (bastion → server):"))
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "selfListEgressKeys", "List your egress keys")
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "selfGenerateEgressKey", "Generate a new egress key")

	fmt.Println(utils.FgCyan("│") + utils.FgWhite("    Server accesses (personal):"))
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "selfListAccesses", "List your personal accesses")
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "selfAddAccess", "Add a personal access")
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "selfDelAccess", "Delete a personal access")

	fmt.Println(utils.FgCyan("│") + utils.FgWhite("    Server alias (personal):"))
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "selfListAliases", "List your personal aliases")
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "selfAddAlias", "Add a personal alias")
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "selfDelAlias", "Delete a personal alias")

	fmt.Println(utils.FgCyan("│") + utils.FgWhite("    TTY sessions:"))
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "ttyList", "List recorded tty sessions")
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "ttyPlay", "Read a recorded tty session")

	// Account Management
	if user.IsAdmin() {
		fmt.Println(utils.FgCyan("│"))
		fmt.Println(utils.FgCyan("│") + utils.FgRedB(" > MANAGE OTHER ACCOUNTS (admin only)"))
		fmt.Println(utils.FgCyan("│") + utils.FgWhite("    Accounts:"))
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "accountList", "List all accounts")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "accountInfo", "Show account info")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "accountCreate", "Create a new account")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "accountModify", "Modify to admin or user an account")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "accountDelete", "Delete an account")
		fmt.Println(utils.FgCyan("│") + utils.FgWhite("    Account keys:"))
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "accountListIngressKeys", "List account ingress keys")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "accountListEgressKeys", "List account egress keys")
		fmt.Println(utils.FgCyan("│") + utils.FgWhite("    Account accesses:"))
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "accountListAccess", "List account accesses")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "accountAddAccess", "Add access to an account")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "accountDelAccess", "Remove access from an account")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "whoHasAccessTo", "List accounts with access to a server")
	}

	// Groups Management
	fmt.Println(utils.FgCyan("│"))
	fmt.Println(utils.FgCyan("│") + utils.FgMagentaB(" > MANAGE GROUPS"))
	fmt.Println(utils.FgCyan("│") + utils.FgWhite("    Groups:"))
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupInfo", "Show group info")
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupList", "List groups")
	if user.IsAdmin() {
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupCreate", "Create a new group")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupDelete", "Delete a group")
	}
	if user.IsAdmin() || isGroupManager(db, user) {
		fmt.Println(utils.FgCyan("│") + utils.FgWhite("    Group member management:"))
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupAddMember", "Add a member to a group")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupDelMember", "Remove a member from a group")
		fmt.Println(utils.FgCyan("│") + utils.FgWhite("    Group egress keys:"))
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupGenerateEgressKey", "Generate a new group egress key")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupListEgressKeys", "List group egress keys")
		fmt.Println(utils.FgCyan("│") + utils.FgWhite("    Group accesses:"))
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupListAccess", "List access of the group")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupAddAccess", "Add access to a group")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupDelAccess", "Remove access from a group")
		fmt.Println(utils.FgCyan("│") + utils.FgWhite("    Group alias (group):"))
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupAddAlias", "Add a group alias")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupDelAlias", "Delete a group alias")
		fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "groupListAliases", "List group aliases")
	}

	// Misc commands
	fmt.Println(utils.FgCyan("│"))
	fmt.Println(utils.FgCyan("│") + utils.FgYellowB(" > MISC COMMANDS"))
	fmt.Println(utils.FgCyan("│") + utils.FgWhite("    Basic commands:"))
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "help", "Display this help message")
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "info", "Show application info")
	fmt.Printf(utils.FgCyan("│ %s %-25s %s\n"), utils.FgGreen("     -"), "exit", "Exit the application")

	fmt.Println(utils.FgCyan("╰──────────────────────────────────────────────────────────"))
}

func isGroupManager(db *gorm.DB, user models.User) bool {
	var userGroup models.UserGroup
	if err := db.Where("user_id = ?", user.ID).First(&userGroup).Error; err != nil {
		return false
	}
	return userGroup.IsOwner() || userGroup.IsACLKeeper() || userGroup.IsGateKeeper()
}

func DisplayInfo() {
	fmt.Println("goBastion - Version 1.0")
}
