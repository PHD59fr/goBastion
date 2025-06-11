package autocomplete

import (
	"sort"
	"strings"

	"goBastion/models"

	"github.com/c-bata/go-prompt"
	"gorm.io/gorm"
)

func Completion(d prompt.Document, user *models.User, db *gorm.DB) []prompt.Suggest {
	hasPerm := func(perm string) bool {
		return user.CanDo(db, perm, "")
	}

	text := d.TextBeforeCursor()
	tokens := strings.Fields(text)

	filterAlreadyUsed := func(sugs []prompt.Suggest) []prompt.Suggest {
		var result []prompt.Suggest
		for _, s := range sugs {
			if !contains(tokens, s.Text) {
				result = append(result, s)
			}
		}
		return result
	}

	if len(tokens) > 0 {
		cmd := tokens[0]

		cmdOptions := map[string][]prompt.Suggest{
			"selfAddIngressKey": {
				{Text: "--key", Description: "SSH public key"},
			},
			"selfDelIngressKey": {
				{Text: "--id", Description: "SSH public key ID"},
			},
			"selfGenerateEgressKey": {
				{Text: "--type", Description: "Key type (e.g., rsa, ed25519)"},
				{Text: "--size", Description: "Key size"},
			},
			"selfAddAccess": {
				{Text: "--server", Description: "Server name"},
				{Text: "--username", Description: "SSH username"},
				{Text: "--port", Description: "Port number"},
				{Text: "--comment", Description: "Comment"},
			},
			"selfDelAccess": {
				{Text: "--id", Description: "Access ID"},
			},
			"selfAddAlias": {
				{Text: "--alias", Description: "Alias"},
				{Text: "--hostname", Description: "Host name"},
			},
			"selfDelAlias": {
				{Text: "--id", Description: "Alias ID"},
			},
			"selfRemoveHostFromKnownHosts": {
				{Text: "--host", Description: "Host to remove from known_hosts"},
			},
			"accountInfo": {
				{Text: "--user", Description: "Username"},
			},
			"accountCreate": {
				{Text: "--user", Description: "Username to create"},
			},
			"accountModify": {
				{Text: "--user", Description: "Username to modify"},
				{Text: "--role", Description: "New role (admin or user)"},
			},
			"accountDelete": {
				{Text: "--user", Description: "Username to delete"},
			},
			"accountListIngressKeys": {
				{Text: "--user", Description: "Username"},
			},
			"accountListEgressKeys": {
				{Text: "--user", Description: "Username"},
			},
			"accountListAccess": {
				{Text: "--user", Description: "Username"},
			},
			"accountAddAccess": {
				{Text: "--user", Description: "Username"},
				{Text: "--server", Description: "SSH Server"},
				{Text: "--port", Description: "SSH Port"},
				{Text: "--username", Description: "SSH Username"},
				{Text: "--comment", Description: "Comment"},
			},
			"accountDelAccess": {
				{Text: "--access", Description: "Access ID"},
			},
			"groupInfo": {
				{Text: "--group", Description: "Group name"},
			},
			"groupList": {
				{Text: "--all", Description: "Show all groups"},
			},
			"groupCreate": {
				{Text: "--group", Description: "Group name"},
			},
			"groupDelete": {
				{Text: "--group", Description: "Group name"},
			},
			"groupAddAccess": {
				{Text: "--group", Description: "Group name"},
				{Text: "--server", Description: "SSH Server"},
				{Text: "--port", Description: "SSH Port"},
				{Text: "--username", Description: "SSH username"},
				{Text: "--comment", Description: "Comment"},
			},
			"groupDelAccess": {
				{Text: "--group", Description: "Group name"},
				{Text: "--access", Description: "Access ID to remove"},
			},
			"groupListAccesses": {
				{Text: "--group", Description: "Group name"},
			},
			"groupAddMember": {
				{Text: "--group", Description: "Group name"},
				{Text: "--user", Description: "Username to add"},
				{Text: "--grade", Description: "Grade (owner, aclkeeper, gatekeeper, member, guest)"},
			},
			"groupDelMember": {
				{Text: "--group", Description: "Group name"},
				{Text: "--user", Description: "Username to remove"},
			},
			"groupGenerateEgressKey": {
				{Text: "--group", Description: "Group name"},
				{Text: "--type", Description: "Key type"},
				{Text: "--size", Description: "Key size"},
				{Text: "--comment", Description: "Key comment"},
			},
			"groupAddAlias": {
				{Text: "--group", Description: "Group name"},
				{Text: "--alias", Description: "Alias"},
				{Text: "--hostname", Description: "Host name"},
			},
			"groupDelAlias": {
				{Text: "--group", Description: "Group name"},
				{Text: "--id", Description: "Alias ID"},
			},
			"groupListAliases": {
				{Text: "--group", Description: "Group name"},
			},
			"ttyList": {
				{Text: "--startDate", Description: "Start date"},
				{Text: "--endDate", Description: "End date"},
				{Text: "--user", Description: "Username (optional)"},
			},
			"ttyPlay": {
				{Text: "--user", Description: "Username (optional)"},
				{Text: "--file", Description: "File name"},
			},
			"whoHasAccessTo": {
				{Text: "--server", Description: "Server"},
			},
		}

		if opts, ok := cmdOptions[cmd]; ok {
			if !hasPerm(cmd) {
				return []prompt.Suggest{}
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(opts), d.GetWordBeforeCursor(), true)
		}
	}

	allCommands := []prompt.Suggest{
		{Text: "selfListIngressKeys", Description: "List your ingress keys"},
		{Text: "selfAddIngressKey", Description: "Add an ingress key"},
		{Text: "selfDelIngressKey", Description: "Delete an ingress key"},
		{Text: "selfListEgressKeys", Description: "List your egress keys"},
		{Text: "selfGenerateEgressKey", Description: "Generate a new egress key"},
		{Text: "selfListAccesses", Description: "List your personal accesses"},
		{Text: "selfAddAccess", Description: "Add a personal access"},
		{Text: "selfDelAccess", Description: "Delete a personal access"},
		{Text: "selfAddAlias", Description: "Add an alias"},
		{Text: "selfDelAlias", Description: "Delete an alias"},
		{Text: "selfListAliases", Description: "List your aliases"},
		{Text: "selfRemoveHostFromKnownHosts", Description: "Remove a host from known_hosts"},
		{Text: "accountInfo", Description: "Show account info"},
		{Text: "accountList", Description: "List all accounts"},
		{Text: "accountCreate", Description: "Create an account"},
		{Text: "accountModify", Description: "Modify an account"},
		{Text: "accountDelete", Description: "Delete an account"},
		{Text: "accountListIngressKeys", Description: "List account ingress keys"},
		{Text: "accountListEgressKeys", Description: "List account egress keys"},
		{Text: "accountListAccess", Description: "List account accesses"},
		{Text: "accountAddAccess", Description: "Add access to an account"},
		{Text: "accountDelAccess", Description: "Remove access from an account"},
		{Text: "groupInfo", Description: "Show group info"},
		{Text: "groupList", Description: "List groups"},
		{Text: "groupCreate", Description: "Create a new group"},
		{Text: "groupDelete", Description: "Delete a group"},
		{Text: "groupAddMember", Description: "Add a member to a group"},
		{Text: "groupDelMember", Description: "Remove a member from a group"},
		{Text: "groupGenerateEgressKey", Description: "Generate group egress key"},
		{Text: "groupAddAccess", Description: "Add access to a group"},
		{Text: "groupDelAccess", Description: "Remove access from a group"},
		{Text: "groupListAccesses", Description: "List group accesses"},
		{Text: "groupAddAlias", Description: "Add an alias to a group"},
		{Text: "groupDelAlias", Description: "Delete an alias from a group"},
		{Text: "groupListAliases", Description: "List group aliases"},
		{Text: "ttyList", Description: "List recorded tty sessions"},
		{Text: "ttyPlay", Description: "Read a recorded tty session"},
		{Text: "whoHasAccessTo", Description: "List access for a server"},
		{Text: "help", Description: "Display this help message"},
		{Text: "info", Description: "Show application info"},
		{Text: "exit", Description: "Exit the application"},
	}

	var suggestions []prompt.Suggest
	for _, cmd := range allCommands {
		if hasPerm(cmd.Text) {
			suggestions = append(suggestions, cmd)
		}
	}

	sort.Slice(suggestions, func(i, j int) bool {
		return suggestions[i].Text < suggestions[j].Text
	})
	return prompt.FilterHasPrefix(filterAlreadyUsed(suggestions), d.GetWordBeforeCursor(), true)
}

func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
