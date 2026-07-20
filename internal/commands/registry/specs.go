package registry

// CommandMeta holds the static metadata for a command (everything except the Handler).
type CommandMeta struct {
	Name        string
	Description string
	Permission  string
	Category    string
	SubCategory string
	Args        []ArgSpec
}

// commandRegistry is the static registry of all command metadata.
// Handlers are injected at session time via BuildRegistry.
var commandRegistry = []CommandMeta{
	// --- Self: Ingress ---
	{Name: "selfListIngressKeys", Description: "List your ingress keys", Permission: "selfListIngressKeys",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "Ingress (you → bastion)"},
	{Name: "selfAddIngressKey", Description: "Add a new ingress key", Permission: "selfAddIngressKey",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "Ingress (you → bastion)",
		Args: []ArgSpec{{"--key", "SSH public key"}, {"--expires", "Key expiry in days"}}},
	{Name: "selfDelIngressKey", Description: "Delete an ingress key", Permission: "selfDelIngressKey",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "Ingress (you → bastion)",
		Args: []ArgSpec{{"--id", "SSH public key ID"}}},

	// --- Self: Egress ---
	{Name: "selfListEgressKeys", Description: "List your egress keys", Permission: "selfListEgressKeys",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "Egress (bastion → server)"},
	{Name: "selfGenerateEgressKey", Description: "Generate a new egress key", Permission: "selfGenerateEgressKey",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "Egress (bastion → server)",
		Args: []ArgSpec{{"--type", "Key type (e.g., rsa, ed25519)"}, {"--size", "Key size"}}},
	{Name: "selfRemoveHostFromKnownHosts", Description: "Remove a host from known hosts", Permission: "selfRemoveHostFromKnownHosts",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "Egress (bastion → server)",
		Args: []ArgSpec{{"--host", "Host to remove from known_hosts"}}},
	{Name: "selfReplaceKnownHost", Description: "Trust new host key (after key change)", Permission: "selfReplaceKnownHost",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "Egress (bastion → server)",
		Args: []ArgSpec{{"--host", "Host whose key changed"}}},

	// --- Self: Accesses ---
	{Name: "selfListAccesses", Description: "List your personal accesses", Permission: "selfListAccesses",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "Server accesses (personal)"},
	{Name: "selfAddAccess", Description: "Add a personal access", Permission: "selfAddAccess",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "Server accesses (personal)",
		Args: []ArgSpec{
			{"--server", "Server name"}, {"--username", "SSH username"}, {"--port", "Port number"},
			{"--comment", "Comment"}, {"--from", "Allowed source CIDRs (comma-separated)"},
			{"--ttl", "Access expiry in days"}, {"--protocol", "Protocol restriction: ssh, scpupload, scpdownload, sftp, rsync"},
		}},
	{Name: "selfDelAccess", Description: "Delete a personal access", Permission: "selfDelAccess",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "Server accesses (personal)",
		Args: []ArgSpec{{"--id", "Access ID"}}},

	// --- Self: Aliases ---
	{Name: "selfListAliases", Description: "List your personal aliases", Permission: "selfListAliases",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "Server alias (personal)"},
	{Name: "selfAddAlias", Description: "Add a personal alias", Permission: "selfAddAlias",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "Server alias (personal)",
		Args: []ArgSpec{{"--alias", "Alias"}, {"--hostname", "Host name"}}},
	{Name: "selfDelAlias", Description: "Delete a personal alias", Permission: "selfDelAlias",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "Server alias (personal)",
		Args: []ArgSpec{{"--id", "Alias ID"}}},

	// --- Self: MFA / TOTP / PIV ---
	{Name: "selfSetupTOTP", Description: "Enable TOTP two-factor authentication", Permission: "selfSetupTOTP",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV"},
	{Name: "selfDisableTOTP", Description: "Disable TOTP two-factor authentication", Permission: "selfDisableTOTP",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV"},
	{Name: "selfSetPassword", Description: "Set a password second factor (MFA)", Permission: "selfSetPassword",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV"},
	{Name: "selfChangePassword", Description: "Change your password second factor", Permission: "selfChangePassword",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV"},
	{Name: "selfDisablePassword", Description: "Disable password second factor (MFA)", Permission: "selfDisablePassword",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV"},
	{Name: "selfAddIngressKeyPIV", Description: "Add a PIV/hardware-attested SSH key (YubiKey)", Permission: "selfAddIngressKeyPIV",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV",
		Args: []ArgSpec{
			{"--attest", "Path to PIV attestation certificate (PEM)"},
			{"--intermediate", "Path to intermediate certificate (PEM)"},
			{"--comment", "Comment for this key"},
		}},
	{Name: "selfGenerateBackupCodes", Description: "Generate TOTP backup codes", Permission: "selfSetupTOTP",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV"},
	{Name: "selfShowBackupCodeCount", Description: "Show remaining backup codes count", Permission: "selfSetupTOTP",
		Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV"},

	// --- Account ---
	{Name: "accountList", Description: "List all accounts", Permission: "accountList",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Accounts"},
	{Name: "accountInfo", Description: "Show account info", Permission: "accountInfo",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Accounts",
		Args: []ArgSpec{{"--user", "Username"}}},
	{Name: "accountCreate", Description: "Create a new account", Permission: "accountCreate",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Accounts",
		Args: []ArgSpec{{"--user", "Username to create"}, {"--osh-only", "Restrict to -osh commands"}, {"--superowner", "Grant superowner privileges"}}},
	{Name: "accountModify", Description: "Modify an account", Permission: "accountModify",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Accounts",
		Args: []ArgSpec{
			{"--user", "Username to modify"},
			{"--sysrole", "New system role (admin or user)"},
			{"--oshOnly", "Set osh-only mode (true/false)"},
			{"--superOwner", "Set superowner mode (true/false)"},
		}},
	{Name: "accountDelete", Description: "Delete an account", Permission: "accountDelete",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Accounts",
		Args: []ArgSpec{{"--user", "Username to delete"}}},
	{Name: "accountListIngressKeys", Description: "List account ingress keys", Permission: "accountListIngressKeys",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account keys",
		Args: []ArgSpec{{"--user", "Username"}}},
	{Name: "accountListEgressKeys", Description: "List account egress keys", Permission: "accountListEgressKeys",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account keys",
		Args: []ArgSpec{{"--user", "Username"}}},
	{Name: "accountListAccess", Description: "List account accesses", Permission: "accountListAccess",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
		Args: []ArgSpec{{"--user", "Username"}}},
	{Name: "accountAddAccess", Description: "Add access to an account", Permission: "accountAddAccess",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
		Args: []ArgSpec{
			{"--user", "Username"}, {"--server", "SSH Server"}, {"--port", "SSH Port"},
			{"--username", "SSH Username"}, {"--comment", "Comment"},
			{"--from", "Allowed source CIDRs (comma-separated)"},
			{"--ttl", "Access expiry in days"},
			{"--protocol", "Protocol restriction: ssh, scpupload, scpdownload, sftp, rsync"},
		}},
	{Name: "accountDelAccess", Description: "Remove access from an account", Permission: "accountDelAccess",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
		Args: []ArgSpec{{"--access", "Access ID"}}},
	{Name: "whoHasAccessTo", Description: "List accounts with access to a server", Permission: "whoHasAccessTo",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
		Args: []ArgSpec{{"--server", "Server"}}},
	{Name: "accountDisableTOTP", Description: "Disable TOTP for an account (admin)", Permission: "accountDisableTOTP",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
		Args: []ArgSpec{{"--user", "Username"}}},
	{Name: "accountSetPassword", Description: "Set/clear password MFA for an account (admin)", Permission: "accountSetPassword",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
		Args: []ArgSpec{{"--user", "Target username"}, {"--clear", "Clear/remove password MFA"}}},
	{Name: "accountDisablePassword", Description: "Disable password MFA for an account (admin)", Permission: "accountSetPassword",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
		Args: []ArgSpec{{"--user", "Target username"}}},
	{Name: "accountUnexpire", Description: "Re-enable a disabled/inactive account", Permission: "accountUnexpire",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Accounts",
		Args: []ArgSpec{{"--user", "Username to re-enable"}}},
	{Name: "accountExpire", Description: "Immediately lock a user account (force disable)", Permission: "accountExpire",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Accounts",
		Args: []ArgSpec{{"--user", "Username to lock"}}},

	// --- PIV ---
	{Name: "pivAddTrustAnchor", Description: "Add a PIV/YubiKey CA trust anchor", Permission: "pivAddTrustAnchor",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
		Args: []ArgSpec{{"--name", "Friendly name for this trust anchor"}, {"--cert", "Path to PEM certificate file"}}},
	{Name: "pivListTrustAnchors", Description: "List PIV trust anchor CAs", Permission: "pivListTrustAnchors",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses"},
	{Name: "pivRemoveTrustAnchor", Description: "Remove a PIV trust anchor CA", Permission: "pivRemoveTrustAnchor",
		Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
		Args: []ArgSpec{{"--name", "Name of the trust anchor to remove"}}},

	// --- Realms ---
	{Name: "realmCreate", Description: "Create a trusted realm configuration", Permission: "realmCreate",
		Category: "RESTRICTED OPERATIONS", SubCategory: "Realms",
		Args: []ArgSpec{
			{"--realm", "Realm name"},
			{"--bastion", "Remote bastion host"},
			{"--port", "Remote bastion port (default: 22)"},
			{"--from", "Trusted source CIDRs"},
			{"--public-key", "Trusted realm SSH public key"},
		}},
	{Name: "realmList", Description: "List configured realms", Permission: "realmList",
		Category: "RESTRICTED OPERATIONS", SubCategory: "Realms"},
	{Name: "realmInfo", Description: "Show details for one realm", Permission: "realmInfo",
		Category: "RESTRICTED OPERATIONS", SubCategory: "Realms",
		Args: []ArgSpec{{"--realm", "Realm name"}}},
	{Name: "realmDelete", Description: "Delete a realm configuration", Permission: "realmDelete",
		Category: "RESTRICTED OPERATIONS", SubCategory: "Realms",
		Args: []ArgSpec{{"--realm", "Realm name"}}},

	// --- Restricted grants ---
	{Name: "restrictedGrantAdd", Description: "Grant a restricted command to a user", Permission: "restrictedGrantAdd",
		Category: "RESTRICTED OPERATIONS", SubCategory: "Command grants",
		Args: []ArgSpec{{"--user", "Target username"}, {"--command", "Restricted command name"}}},
	{Name: "restrictedGrantDel", Description: "Remove a restricted command grant", Permission: "restrictedGrantDel",
		Category: "RESTRICTED OPERATIONS", SubCategory: "Command grants",
		Args: []ArgSpec{{"--user", "Target username"}, {"--command", "Restricted command name"}}},
	{Name: "restrictedGrantList", Description: "List restricted command grants", Permission: "restrictedGrantList",
		Category: "RESTRICTED OPERATIONS", SubCategory: "Command grants",
		Args: []ArgSpec{{"--user", "Optional username filter"}}},

	// --- Groups: Overview ---
	{Name: "groupInfo", Description: "Show group info", Permission: "groupInfo",
		Category: "MANAGE GROUPS", SubCategory: "Groups",
		Args: []ArgSpec{{"--group", "Group name"}}},
	{Name: "groupList", Description: "List groups", Permission: "groupList",
		Category: "MANAGE GROUPS", SubCategory: "Groups",
		Args: []ArgSpec{{"--all", "Show all groups"}}},
	{Name: "groupCreate", Description: "Create a new group", Permission: "groupCreate",
		Category: "MANAGE GROUPS", SubCategory: "Groups",
		Args: []ArgSpec{{"--group", "Group name"}}},
	{Name: "groupDelete", Description: "Delete a group", Permission: "groupDelete",
		Category: "MANAGE GROUPS", SubCategory: "Groups",
		Args: []ArgSpec{{"--group", "Group name"}}},

	// --- Groups: Members ---
	{Name: "groupAddMember", Description: "Add a member to a group", Permission: "groupAddMember",
		Category: "MANAGE GROUPS", SubCategory: "Group member management",
		Args: []ArgSpec{
			{"--group", "Group name"}, {"--user", "Username to add"},
			{"--role", "Role (owner, aclkeeper, gatekeeper, member, guest)"},
		}},
	{Name: "groupDelMember", Description: "Remove a member from a group", Permission: "groupDelMember",
		Category: "MANAGE GROUPS", SubCategory: "Group member management",
		Args: []ArgSpec{{"--group", "Group name"}, {"--user", "Username to remove"}}},

	// --- Groups: Egress ---
	{Name: "groupListEgressKeys", Description: "List group egress keys", Permission: "groupListEgressKeys",
		Category: "MANAGE GROUPS", SubCategory: "Group egress (bastion → server)",
		Args: []ArgSpec{{"--group", "Group name"}}},
	{Name: "groupGenerateEgressKey", Description: "Generate a new group egress key", Permission: "groupGenerateEgressKey",
		Category: "MANAGE GROUPS", SubCategory: "Group egress (bastion → server)",
		Args: []ArgSpec{
			{"--group", "Group name"}, {"--type", "Key type"}, {"--size", "Key size"},
			{"--comment", "Key comment"},
		}},

	// --- Groups: Accesses ---
	{Name: "groupListAccesses", Description: "List accesses of the group", Permission: "groupListAccesses",
		Category: "MANAGE GROUPS", SubCategory: "Group accesses",
		Args: []ArgSpec{{"--group", "Group name"}}},
	{Name: "groupAddAccess", Description: "Add access to a group", Permission: "groupAddAccess",
		Category: "MANAGE GROUPS", SubCategory: "Group accesses",
		Args: []ArgSpec{
			{"--group", "Group name"}, {"--server", "SSH Server"}, {"--port", "SSH Port"},
			{"--username", "SSH username"}, {"--comment", "Comment"},
			{"--from", "Allowed source CIDRs (comma-separated)"},
			{"--ttl", "Access expiry in days"},
			{"--protocol", "Protocol restriction: ssh, scpupload, scpdownload, sftp, rsync"},
			{"--force", "Skip connectivity check"},
		}},
	{Name: "groupDelAccess", Description: "Remove access from a group", Permission: "groupDelAccess",
		Category: "MANAGE GROUPS", SubCategory: "Group accesses",
		Args: []ArgSpec{{"--group", "Group name"}, {"--access", "Access ID to remove"}}},
	{Name: "groupSetMFA", Description: "Enable/disable JIT MFA requirement for a group", Permission: "groupSetMFA",
		Category: "MANAGE GROUPS", SubCategory: "Group accesses",
		Args: []ArgSpec{
			{"--group", "Group name"}, {"--required", "Require MFA for this group"},
			{"--optional", "Remove MFA requirement for this group"},
		}},

	// --- Groups: Guest Accesses ---
	{Name: "groupAddGuestAccess", Description: "Grant guest access to a specific server in a group", Permission: "groupAddGuestAccess",
		Category: "MANAGE GROUPS", SubCategory: "Group guest accesses",
		Args: []ArgSpec{
			{"--group", "Group name"}, {"--account", "Username to grant access to"},
			{"--host", "Server hostname/IP"}, {"--user", "Remote username"},
			{"--port", "Remote port (default 22)"}, {"--protocol", "Protocol: ssh, scpupload, scpdownload, sftp, rsync"},
			{"--ttl", "Access expiry in days"}, {"--comment", "Comment"},
			{"--from", "Allowed source CIDRs"},
		}},
	{Name: "groupDelGuestAccess", Description: "Remove a guest access grant from a group", Permission: "groupDelGuestAccess",
		Category: "MANAGE GROUPS", SubCategory: "Group guest accesses",
		Args: []ArgSpec{{"--group", "Group name"}, {"--account", "Username"}, {"--grant", "Grant ID (optional, removes all if omitted)"}}},
	{Name: "groupListGuestAccesses", Description: "List guest accesses for a user in a group", Permission: "groupListGuestAccesses",
		Category: "MANAGE GROUPS", SubCategory: "Group guest accesses",
		Args: []ArgSpec{{"--group", "Group name"}, {"--account", "Username"}}},

	// --- Groups: Aliases ---
	{Name: "groupAddAlias", Description: "Add a group alias", Permission: "groupAddAlias",
		Category: "MANAGE GROUPS", SubCategory: "Group alias (group)",
		Args: []ArgSpec{{"--group", "Group name"}, {"--alias", "Alias"}, {"--hostname", "Host name"}}},
	{Name: "groupDelAlias", Description: "Delete a group alias", Permission: "groupDelAlias",
		Category: "MANAGE GROUPS", SubCategory: "Group alias (group)",
		Args: []ArgSpec{{"--group", "Group name"}, {"--id", "Alias ID"}}},
	{Name: "groupListAliases", Description: "List group aliases", Permission: "groupListAliases",
		Category: "MANAGE GROUPS", SubCategory: "Group alias (group)",
		Args: []ArgSpec{{"--group", "Group name"}}},

	// --- TTY ---
	{Name: "ttyList", Description: "List recorded tty sessions", Permission: "ttyList",
		Category: "TTY SESSIONS", SubCategory: "",
		Args: []ArgSpec{
			{"--startDate", "Start date"}, {"--endDate", "End date"},
			{"--host", "Filter by server hostname"},
		}},
	{Name: "ttyPlay", Description: "Replay a recorded tty session", Permission: "ttyPlay",
		Category: "TTY SESSIONS", SubCategory: "",
		Args: []ArgSpec{{"--file", "File name"}}},

	// --- Misc ---
	{Name: "help", Description: "Display this help message", Permission: "help",
		Category: "MISC COMMANDS", SubCategory: "Basic commands"},
	{Name: "info", Description: "Show application info", Permission: "info",
		Category: "MISC COMMANDS", SubCategory: "Basic commands"},
	{Name: "exit", Description: "Exit the application", Permission: "exit",
		Category: "MISC COMMANDS", SubCategory: "Basic commands"},

	// --- Bastion Config ---
	{Name: "bastionConfig", Description: "Interactive bastion configuration manager", Permission: "bastionConfig",
		Category: "BASTION CONFIG", SubCategory: "Configuration"},
}
