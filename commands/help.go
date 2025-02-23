package commands

import (
	"fmt"
	"goBastion/models"

	"github.com/fatih/color"
	"gorm.io/gorm"
)

func DisplayHelp(db *gorm.DB, user models.User) {
	fgCyan := color.New(color.FgCyan, color.Bold).SprintFunc()
	fgGreen := color.New(color.FgGreen).SprintFunc()
	fgYellow := color.New(color.FgYellow).SprintFunc()
	fgWhite := color.New(color.FgWhite).SprintFunc()
	fgMagenta := color.New(color.FgMagenta, color.Bold).SprintFunc()

	fmt.Println(fgCyan("╭───goBastion──────────────────────────────────────────────"))
	fmt.Println(fgCyan("│ ") + fgGreen("▶ help"))
	fmt.Println(fgCyan("├──────────────────────────────────────────────────────────"))

	// Manage your account
	fmt.Println(fgCyan("│") + fgYellow(" > MANAGE YOUR ACCOUNT"))
	fmt.Println(fgCyan("│") + fgWhite("    Ingress (you → bastion):"))
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "selfListIngressKeys", "List your ingress keys")
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "selfAddIngressKey", "Add a new ingress key")
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "selfDelIngressKey", "Delete an ingress key")

	fmt.Println(fgCyan("│") + fgWhite("    Egress (bastion → server):"))
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "selfListEgressKeys", "List your egress keys")
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "selfGenerateEgressKey", "Generate a new egress key")

	fmt.Println(fgCyan("│") + fgWhite("    Server accesses (personal):"))
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "selfListAccesses", "List your personal accesses")
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "selfAddAccess", "Add a personal access")
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "selfDelAccess", "Delete a personal access")

	fmt.Println(fgCyan("│") + fgWhite("    Server alias (personal):"))
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "selfListAliases", "List your personal aliases")
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "selfAddAlias", "Add a personal alias")
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "selfDelAlias", "Delete a personal alias")

	// Account Management
	if user.IsAdmin() {
		fmt.Println(fgCyan("│"))
		fmt.Println(fgCyan("│") + fgMagenta(" > MANAGE OTHER ACCOUNTS (admin only)"))
		fmt.Println(fgCyan("│") + fgWhite("    Accounts:"))
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "accountList", "List all accounts")
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "accountInfo", "Show account info")
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "accountCreate", "Create a new account")
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "accountModify", "Modify to admin or user an account")
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "accountDelete", "Delete an account")
		fmt.Println(fgCyan("│") + fgWhite("    Account keys:"))
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "accountListIngressKeys", "List account ingress keys")
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "accountListEgressKeys", "List account egress keys")
		fmt.Println(fgCyan("│") + fgWhite("    Account accesses:"))
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "accountListAccess", "List account accesses")
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "accountAddAccess", "Add access to an account")
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "accountDelAccess", "Remove access from an account")
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "whoHasAccessTo", "List accounts with access to a server")
	}

	// Groups Management
	fmt.Println(fgCyan("│"))
	fmt.Println(fgCyan("│") + fgMagenta(" > MANAGE GROUPS"))
	fmt.Println(fgCyan("│") + fgWhite("    Groups:"))
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "groupInfo", "Show group info")
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "groupList", "List groups")
	if user.IsAdmin() {
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "groupCreate", "Create a new group")
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "groupDelete", "Delete a group")
	}
	if user.IsAdmin() || isGroupManager(db, user) {
		fmt.Println(fgCyan("│") + fgWhite("    Group member management:"))
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "groupAddMember", "Add a member to a group")
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "groupDelMember", "Remove a member from a group")
		fmt.Println(fgCyan("│") + fgWhite("    Group egress keys:"))
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "groupGenerateEgressKey", "Generate a new group egress key")
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "groupListEgressKeys", "List group egress keys")
		fmt.Println(fgCyan("│") + fgWhite("    Group accesses:"))
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "groupListAccess", "List access of the group")
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "groupAddAccess", "Add access to a group")
		fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "groupDelAccess", "Remove access from a group")

	}

	// Misc commands
	fmt.Println(fgCyan("│"))
	fmt.Println(fgCyan("│") + fgYellow(" > MISC COMMANDS"))
	fmt.Println(fgCyan("│") + fgWhite("    Basic commands:"))
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "help", "Display this help message")
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "info", "Show application info")
	fmt.Printf(fgCyan("│ %s %-25s %s\n"), fgGreen("     -"), "exit", "Exit the application")

	fmt.Println(fgCyan("╰──────────────────────────────────────────────────────────"))
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
