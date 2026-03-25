package autocomplete

import (
	"sort"
	"strings"

	"goBastion/internal/models"

	"github.com/c-bata/go-prompt"
	"gorm.io/gorm"
)

// Completion returns autocomplete suggestions based on the current input and user permissions.
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
				{Text: "--expires", Description: "Key expiry in days"},
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
				{Text: "--from", Description: "Allowed source CIDRs (comma-separated)"},
				{Text: "--ttl", Description: "Access expiry in days"},
				{Text: "--protocol", Description: "Protocol restriction: ssh, scpupload, scpdownload, sftp, rsync"},
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
			"selfReplaceKnownHost": {
				{Text: "--host", Description: "Host whose key changed"},
			},
			"accountInfo": {
				{Text: "--user", Description: "Username"},
			},
			"accountCreate": {
				{Text: "--user", Description: "Username to create"},
			},
			"accountModify": {
				{Text: "--user", Description: "Username to modify"},
				{Text: "--sysrole", Description: "New system role (admin or user)"},
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
				{Text: "--from", Description: "Allowed source CIDRs (comma-separated)"},
				{Text: "--ttl", Description: "Access expiry in days"},
				{Text: "--protocol", Description: "Protocol restriction: ssh, scpupload, scpdownload, sftp, rsync"},
			},
			"accountDelAccess": {
				{Text: "--access", Description: "Access ID"},
			},
			"accountDisableTOTP": {
				{Text: "--user", Description: "Username"},
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
				{Text: "--from", Description: "Allowed source CIDRs (comma-separated)"},
				{Text: "--ttl", Description: "Access expiry in days"},
				{Text: "--protocol", Description: "Protocol restriction: ssh, scpupload, scpdownload, sftp, rsync"},
				{Text: "--force", Description: "Skip connectivity check"},
			},
			"groupDelAccess": {
				{Text: "--group", Description: "Group name"},
				{Text: "--access", Description: "Access ID to remove"},
			},
			"groupListAccesses": {
				{Text: "--group", Description: "Group name"},
			},
			"groupListEgressKeys": {
				{Text: "--group", Description: "Group name"},
			},
			"groupAddMember": {
				{Text: "--group", Description: "Group name"},
				{Text: "--user", Description: "Username to add"},
				{Text: "--role", Description: "Role (owner, aclkeeper, gatekeeper, member, guest)"},
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
			"groupSetMFA": {
				{Text: "--group", Description: "Group name"},
				{Text: "--required", Description: "Require MFA for this group"},
				{Text: "--optional", Description: "Remove MFA requirement for this group"},
			},
			"selfSetPassword":    {},
			"selfChangePassword": {},
			"accountSetPassword": {
				{Text: "--user", Description: "Target username"},
				{Text: "--clear", Description: "Clear/remove password MFA"},
			},
			"whoHasAccessTo": {
				{Text: "--server", Description: "Server"},
			},
			"pivAddTrustAnchor": {
				{Text: "--name", Description: "Friendly name for this trust anchor"},
				{Text: "--cert", Description: "Path to PEM certificate file"},
			},
			"pivRemoveTrustAnchor": {
				{Text: "--name", Description: "Name of the trust anchor to remove"},
			},
			"selfAddIngressKeyPIV": {
				{Text: "--attest", Description: "Path to PIV attestation certificate (PEM)"},
				{Text: "--intermediate", Description: "Path to intermediate certificate (PEM)"},
				{Text: "--comment", Description: "Comment for this key"},
			},
		}

		// ttyList and ttyPlay: --user only available to admins
		if cmd == "ttyList" || cmd == "ttyPlay" {
			if !hasPerm(cmd) {
				return []prompt.Suggest{}
			}
			var opts []prompt.Suggest
			if cmd == "ttyList" {
				opts = []prompt.Suggest{
					{Text: "--startDate", Description: "Start date"},
					{Text: "--endDate", Description: "End date"},
					{Text: "--host", Description: "Filter by server hostname"},
				}
			} else {
				opts = []prompt.Suggest{
					{Text: "--file", Description: "File name"},
				}
			}
			if user.IsAdmin() {
				opts = append(opts, prompt.Suggest{Text: "--user", Description: "Username (Admin only)"})
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(opts), d.GetWordBeforeCursor(), true)
		}

		if opts, ok := cmdOptions[cmd]; ok {
			if !hasPerm(cmd) {
				return []prompt.Suggest{}
			}
			return prompt.FilterHasPrefix(filterAlreadyUsed(opts), d.GetWordBeforeCursor(), true)
		}
	}

	allCommands := []prompt.Suggest{
		{Text: "accountAddAccess", Description: "Add access to an account"},
		{Text: "accountCreate", Description: "Create an account"},
		{Text: "accountDelAccess", Description: "Remove access from an account"},
		{Text: "accountDelete", Description: "Delete an account"},
		{Text: "accountInfo", Description: "Show account info"},
		{Text: "accountList", Description: "List all accounts"},
		{Text: "accountListAccess", Description: "List account accesses"},
		{Text: "accountListEgressKeys", Description: "List account egress keys"},
		{Text: "accountListIngressKeys", Description: "List account ingress keys"},
		{Text: "accountModify", Description: "Modify an account"},
		{Text: "accountDisableTOTP", Description: "Disable TOTP for an account (admin)"},
		{Text: "accountSetPassword", Description: "Set/clear password MFA for an account (admin)"},
		{Text: "pivAddTrustAnchor", Description: "Add a PIV/YubiKey trust anchor CA (admin)"},
		{Text: "pivListTrustAnchors", Description: "List PIV trust anchor CAs (admin)"},
		{Text: "pivRemoveTrustAnchor", Description: "Remove a PIV trust anchor CA (admin)"},
		{Text: "groupAddAccess", Description: "Add access to a group"},
		{Text: "groupAddAlias", Description: "Add an alias to a group"},
		{Text: "groupAddMember", Description: "Add a member to a group"},
		{Text: "groupCreate", Description: "Create a new group"},
		{Text: "groupDelAccess", Description: "Remove access from a group"},
		{Text: "groupDelAlias", Description: "Delete an alias from a group"},
		{Text: "groupDelMember", Description: "Remove a member from a group"},
		{Text: "groupDelete", Description: "Delete a group"},
		{Text: "groupGenerateEgressKey", Description: "Generate group egress key"},
		{Text: "groupInfo", Description: "Show group info"},
		{Text: "groupList", Description: "List groups"},
		{Text: "groupListAccesses", Description: "List group accesses"},
		{Text: "groupListAliases", Description: "List group aliases"},
		{Text: "groupListEgressKeys", Description: "List group egress keys"},
		{Text: "groupSetMFA", Description: "Enable/disable JIT MFA requirement for a group"},
		{Text: "selfAddAccess", Description: "Add a personal access"},
		{Text: "selfAddAlias", Description: "Add an alias"},
		{Text: "selfAddIngressKey", Description: "Add an ingress key"},
		{Text: "selfDelAccess", Description: "Delete a personal access"},
		{Text: "selfDelAlias", Description: "Delete an alias"},
		{Text: "selfDelIngressKey", Description: "Delete an ingress key"},
		{Text: "selfGenerateEgressKey", Description: "Generate a new egress key"},
		{Text: "selfListAccesses", Description: "List your personal accesses"},
		{Text: "selfListAliases", Description: "List your aliases"},
		{Text: "selfListEgressKeys", Description: "List your egress keys"},
		{Text: "selfListIngressKeys", Description: "List your ingress keys"},
		{Text: "selfRemoveHostFromKnownHosts", Description: "Remove a host from known hosts"},
		{Text: "selfReplaceKnownHost", Description: "Replace a changed host key (TOFU reset)"},
		{Text: "selfSetupTOTP", Description: "Enable TOTP two-factor authentication"},
		{Text: "selfDisableTOTP", Description: "Disable TOTP two-factor authentication"},
		{Text: "selfDisablePassword", Description: "Disable password MFA"},
		{Text: "selfAddIngressKeyPIV", Description: "Add a PIV/hardware-attested ingress key"},
		{Text: "selfSetPassword", Description: "Set a password MFA second factor"},
		{Text: "selfChangePassword", Description: "Change your password MFA"},
		{Text: "ttyList", Description: "List recorded tty sessions"},
		{Text: "ttyPlay", Description: "Read a recorded tty session"},
		{Text: "whoHasAccessTo", Description: "List access for a server (supports CIDR)"},
		{Text: "exit", Description: "Exit the application"},
		{Text: "help", Description: "Display this help message"},
		{Text: "info", Description: "Show application info"},
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

// contains reports whether a string slice contains the given value.
func contains(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
