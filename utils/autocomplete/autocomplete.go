package autocomplete

import (
	"sort"
	"strings"

	"goBastion/models"

	"github.com/c-bata/go-prompt"
)

func Completion(d prompt.Document, user *models.User) []prompt.Suggest {
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
		switch cmd {

		// Self commands
		case "selfListIngressKeys":
			return []prompt.Suggest{}
		case "selfAddIngressKey":
			sugs := []prompt.Suggest{
				{Text: "--key", Description: "SSH public key"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "selfDelIngressKey":
			sugs := []prompt.Suggest{
				{Text: "--id", Description: "SSH public key ID"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "selfGenerateEgressKey":
			sugs := []prompt.Suggest{
				{Text: "--type", Description: "Key type (e.g., rsa, ed25519)"},
				{Text: "--size", Description: "Key size (e.g., 2048)"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "selfListEgressKeys":
			return []prompt.Suggest{}
		case "selfListAccesses":
			return []prompt.Suggest{}
		case "selfAddAccess":
			sugs := []prompt.Suggest{
				{Text: "--server", Description: "Server name"},
				{Text: "--username", Description: "SSH username"},
				{Text: "--port", Description: "Port number"},
				{Text: "--comment", Description: "Comment"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "selfDelAccess":
			sugs := []prompt.Suggest{
				{Text: "--id", Description: "Access ID"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "selfAddAlias":
			sugs := []prompt.Suggest{
				{Text: "--alias", Description: "Alias"},
				{Text: "--hostname", Description: "Host name"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "selfDelAlias":
			sugs := []prompt.Suggest{
				{Text: "--id", Description: "Alias ID"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "selfListAliases":
			return []prompt.Suggest{}

		// Account commands
		case "accountList":
			return []prompt.Suggest{}
		case "accountInfo":
			sugs := []prompt.Suggest{
				{Text: "--user", Description: "Username"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "accountCreate":
			if user.Role != "admin" {
				return []prompt.Suggest{}
			}
			sugs := []prompt.Suggest{
				{Text: "--user", Description: "Username to create"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "accountModify":
			if user.Role != "admin" {
				return []prompt.Suggest{}
			}
			sugs := []prompt.Suggest{
				{Text: "--user", Description: "Username to modify"},
				{Text: "--role", Description: "New role (admin or user)"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "accountDelete":
			if user.Role != "admin" {
				return []prompt.Suggest{}
			}
			sugs := []prompt.Suggest{
				{Text: "--user", Description: "Username to delete"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "accountListIngressKeys":
			sugs := []prompt.Suggest{
				{Text: "--user", Description: "Username to list ingress keys"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "accountListEgressKeys":
			if user.Role != "admin" {
				return []prompt.Suggest{}
			}
			sugs := []prompt.Suggest{
				{Text: "--user", Description: "Username to list egress keys"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "accountListAccess":
			sugs := []prompt.Suggest{
				{Text: "--user", Description: "Username to list accesses"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "accountAddAccess":
			sugs := []prompt.Suggest{
				{Text: "--user", Description: "Username to add access"},
				{Text: "--server", Description: "SSH Server"},
				{Text: "--port", Description: "SSH Port"},
				{Text: "--username", Description: "SSH Username"},
				{Text: "--comment", Description: "Comment"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "accountDelAccess":
			sugs := []prompt.Suggest{
				{Text: "--access", Description: "Access ID"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)

		// Group commands
		case "groupInfo":
			sugs := []prompt.Suggest{
				{Text: "--group", Description: "Group name"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "groupList":
			sugs := []prompt.Suggest{
				{Text: "--all", Description: "Show all groups"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "groupCreate":
			if user.Role != "admin" {
				return []prompt.Suggest{}
			}
			sugs := []prompt.Suggest{
				{Text: "--group", Description: "Group name"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "groupDelete":
			if user.Role != "admin" {
				return []prompt.Suggest{}
			}
			sugs := []prompt.Suggest{
				{Text: "--group", Description: "Group name"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "groupAddAccess":
			sugs := []prompt.Suggest{
				{Text: "--group", Description: "Group name"},
				{Text: "--server", Description: "SSH Server"},
				{Text: "--port", Description: "SSH Port"},
				{Text: "--username", Description: "SSH username"},
				{Text: "--comment", Description: "Comment"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "groupDelAccess":
			sugs := []prompt.Suggest{
				{Text: "--group", Description: "Group name"},
				{Text: "--access", Description: "Access ID to remove"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "groupListAccess":
			sugs := []prompt.Suggest{
				{Text: "--group", Description: "Group name"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "groupAddMember":
			sugs := []prompt.Suggest{
				{Text: "--group", Description: "Group name"},
				{Text: "--user", Description: "Username to add"},
				{Text: "--grade", Description: "Grade (owner, aclkeeper, gatekeeper, member, guest)"},
			}
			if user.Role != "admin" && !isGroupManager(user) {
				return []prompt.Suggest{}
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "groupDelMember":
			sugs := []prompt.Suggest{
				{Text: "--group", Description: "Group name"},
				{Text: "--user", Description: "Username to remove"},
			}
			if user.Role != "admin" && !isGroupManager(user) {
				return []prompt.Suggest{}
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "groupGenerateEgressKey":
			sugs := []prompt.Suggest{
				{Text: "--group", Description: "Group name"},
				{Text: "--type", Description: "Key type (e.g., rsa, ed25519)"},
				{Text: "--size", Description: "Key size"},
				{Text: "--comment", Description: "Key comment"},
			}
			if user.Role != "admin" && !isGroupManager(user) {
				return []prompt.Suggest{}
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "groupListEgressKeys":
			sugs := []prompt.Suggest{
				{Text: "--group", Description: "Group name"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "groupAddAlias":
			sugs := []prompt.Suggest{
				{Text: "--group", Description: "Group name"},
				{Text: "--alias", Description: "Alias"},
				{Text: "--hostname", Description: "Host name"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "groupDelAlias":
			sugs := []prompt.Suggest{
				{Text: "--id", Description: "Alias ID"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "groupListAliases":
			sugs := []prompt.Suggest{
				{Text: "--group", Description: "Group name"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)

		// TTY commands
		case "ttyList":
			var sugs []prompt.Suggest
			sugs = append(sugs, prompt.Suggest{Text: "--startDate", Description: "Start date"})
			sugs = append(sugs, prompt.Suggest{Text: "--endDate", Description: "End date"})
			if user.Role == "admin" {
				sugs = append(sugs, prompt.Suggest{Text: "--user", Description: "Username (admin only)"})
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)
		case "ttyPlay":
			var sugs2 []prompt.Suggest
			if user.Role == "admin" {
				sugs2 = append(sugs2, prompt.Suggest{Text: "--user", Description: "Username (admin only)"})
			}
			sugs2 = append(sugs2, prompt.Suggest{Text: "--file", Description: "File name"})
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs2), d.GetWordBeforeCursor(), true)
		case "whoHasAccessTo":
			sugs := []prompt.Suggest{
				{Text: "--server", Description: "Server"},
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(sugs), d.GetWordBeforeCursor(), true)

		// Miscellanous commands
		case "help":
			return []prompt.Suggest{}
		case "info":
			return []prompt.Suggest{}
		case "exit":
			return []prompt.Suggest{}
		}
	}
	defaultSuggestions := []prompt.Suggest{
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
		{Text: "accountInfo", Description: "Show account info"},
		{Text: "accountList", Description: "List all accounts"},
		{Text: "accountListIngressKeys", Description: "List account ingress keys"},
		{Text: "groupInfo", Description: "Show group info"},
		{Text: "groupList", Description: "List groups"},
		{Text: "groupListEgressKeys", Description: "List group egress keys"},
		{Text: "help", Description: "Display this help message"},
		{Text: "info", Description: "Show application info"},
		{Text: "exit", Description: "Exit the application"},
	}
	var groupSuggestions []prompt.Suggest
	if user.Role == "admin" {
		groupSuggestions = []prompt.Suggest{
			{Text: "groupCreate", Description: "Create a new group"},
			{Text: "groupDelete", Description: "Delete a group"},
			{Text: "groupAddMember", Description: "Add a member to a group"},
			{Text: "groupDelMember", Description: "Remove a member from a group"},
			{Text: "groupGenerateEgressKey", Description: "Generate group egress key"},
			{Text: "groupAddAccess", Description: "Add access to a group"},
			{Text: "groupDelAccess", Description: "Remove access from a group"},
			{Text: "groupListAccess", Description: "List group accesses"},
		}
	} else if isGroupMember(user) {
		groupSuggestions = []prompt.Suggest{
			{Text: "groupInfo", Description: "Show group info"},
			{Text: "groupList", Description: "List groups"},
		}
		if isGroupManager(user) {
			groupSuggestions = append(groupSuggestions, []prompt.Suggest{
				{Text: "groupAddAccess", Description: "Add access to a group"},
				{Text: "groupDelAccess", Description: "Remove access from a group"},
				{Text: "groupListAccess", Description: "List group accesses"},
				{Text: "groupAddMember", Description: "Add a member to a group"},
				{Text: "groupDelMember", Description: "Remove a member from a group"},
				{Text: "groupGenerateEgressKey", Description: "Generate group egress key"},
			}...)
		}
	}
	suggestions := append(defaultSuggestions, groupSuggestions...)
	if user.Role == "admin" {
		adminSuggestions := []prompt.Suggest{
			{Text: "accountListAccess", Description: "List account accesses"},
			{Text: "accountCreate", Description: "Create an account"},
			{Text: "accountModify", Description: "Modify an account"},
			{Text: "accountDelete", Description: "Delete an account"},
			{Text: "accountListEgressKeys", Description: "List account egress keys"},
			{Text: "accountAddAccess", Description: "Add access to an account"},
			{Text: "accountDelAccess", Description: "Remove access from an account"},
			{Text: "ttyList", Description: "List recorded tty sessions"},
			{Text: "ttyPlay", Description: "Read a recorded tty session"},
			{Text: "whoHasAccessTo", Description: "List access for a server"},
		}
		suggestions = append(suggestions, adminSuggestions...)
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

func isGroupMember(user *models.User) bool {
	if gm, ok := interface{}(user).(interface{ IsGroupMember() bool }); ok {
		return gm.IsGroupMember()
	}
	return false
}

func isGroupManager(user *models.User) bool {
	if gm, ok := interface{}(user).(interface{ IsGroupManager() bool }); ok {
		return gm.IsGroupManager()
	}
	return false
}
