// Package registry provides the single source of truth for all bastion commands.
// Help, autocomplete, and executeCommand all read from this registry.
package registry

import (
	"log/slog"

	"github.com/c-bata/go-prompt"
	"gorm.io/gorm"

	cmdaccount "goBastion/internal/commands/account"
	cmdgroup "goBastion/internal/commands/group"
	cmdpiv "goBastion/internal/commands/piv"
	cmdrealm "goBastion/internal/commands/realm"
	cmdrestricted "goBastion/internal/commands/restricted"
	cmdself "goBastion/internal/commands/self"
	cmdtotp "goBastion/internal/commands/totp"
	cmdtty "goBastion/internal/commands/tty"
	"goBastion/internal/models"
	"goBastion/internal/osadapter"
)

// ArgSpec describes a command-line flag for autocomplete.
type ArgSpec struct {
	Name        string
	Description string
}

// CommandSpec is the canonical definition of a single bastion command.
type CommandSpec struct {
	Name        string
	Description string
	Permission  string
	Category    string
	SubCategory string
	Args        []ArgSpec
	Handler     func() error
}

// BuildRegistry constructs the command registry for a given session context.
// Each call creates fresh closures capturing the session's db, user, log, and args.
func BuildRegistry(db *gorm.DB, user *models.User, log *slog.Logger, adapter osadapter.SystemAdapter, args []string, exitFunc func()) []CommandSpec {
	return []CommandSpec{
		// --- Self: Ingress ---
		{
			Name: "selfListIngressKeys", Description: "List your ingress keys", Permission: "selfListIngressKeys",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "Ingress (you → bastion)",
			Handler: func() error { return cmdself.ListIngressKeys(db, user) },
		},
		{
			Name: "selfAddIngressKey", Description: "Add a new ingress key", Permission: "selfAddIngressKey",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "Ingress (you → bastion)",
			Args:    []ArgSpec{{"--key", "SSH public key"}, {"--expires", "Key expiry in days"}},
			Handler: func() error { return cmdself.AddIngressKey(db, user, args) },
		},
		{
			Name: "selfDelIngressKey", Description: "Delete an ingress key", Permission: "selfDelIngressKey",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "Ingress (you → bastion)",
			Args:    []ArgSpec{{"--id", "SSH public key ID"}},
			Handler: func() error { return cmdself.DelIngressKey(db, user, args) },
		},

		// --- Self: Egress ---
		{
			Name: "selfListEgressKeys", Description: "List your egress keys", Permission: "selfListEgressKeys",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "Egress (bastion → server)",
			Handler: func() error { return cmdself.ListEgressKeys(db, user) },
		},
		{
			Name: "selfGenerateEgressKey", Description: "Generate a new egress key", Permission: "selfGenerateEgressKey",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "Egress (bastion → server)",
			Args:    []ArgSpec{{"--type", "Key type (e.g., rsa, ed25519)"}, {"--size", "Key size"}},
			Handler: func() error { return cmdself.GenerateEgressKey(db, user, args) },
		},
		{
			Name: "selfRemoveHostFromKnownHosts", Description: "Remove a host from known hosts", Permission: "selfRemoveHostFromKnownHosts",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "Egress (bastion → server)",
			Args:    []ArgSpec{{"--host", "Host to remove from known_hosts"}},
			Handler: func() error { return cmdself.RemoveHostFromKnownHosts(db, user, args) },
		},
		{
			Name: "selfReplaceKnownHost", Description: "Trust new host key (after key change)", Permission: "selfReplaceKnownHost",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "Egress (bastion → server)",
			Args:    []ArgSpec{{"--host", "Host whose key changed"}},
			Handler: func() error { return cmdself.ReplaceKnownHost(db, user, args) },
		},

		// --- Self: Accesses ---
		{
			Name: "selfListAccesses", Description: "List your personal accesses", Permission: "selfListAccesses",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "Server accesses (personal)",
			Handler: func() error { return cmdself.ListAccesses(db, user) },
		},
		{
			Name: "selfAddAccess", Description: "Add a personal access", Permission: "selfAddAccess",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "Server accesses (personal)",
			Args: []ArgSpec{
				{"--server", "Server name"}, {"--username", "SSH username"}, {"--port", "Port number"},
				{"--comment", "Comment"}, {"--from", "Allowed source CIDRs (comma-separated)"},
				{"--ttl", "Access expiry in days"}, {"--protocol", "Protocol restriction: ssh, scpupload, scpdownload, sftp, rsync"},
			},
			Handler: func() error { return cmdself.AddAccess(db, user, args) },
		},
		{
			Name: "selfDelAccess", Description: "Delete a personal access", Permission: "selfDelAccess",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "Server accesses (personal)",
			Args:    []ArgSpec{{"--id", "Access ID"}},
			Handler: func() error { return cmdself.DelAccess(db, user, args) },
		},

		// --- Self: Aliases ---
		{
			Name: "selfListAliases", Description: "List your personal aliases", Permission: "selfListAliases",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "Server alias (personal)",
			Handler: func() error { return cmdself.ListAliases(db, user) },
		},
		{
			Name: "selfAddAlias", Description: "Add a personal alias", Permission: "selfAddAlias",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "Server alias (personal)",
			Args:    []ArgSpec{{"--alias", "Alias"}, {"--hostname", "Host name"}},
			Handler: func() error { return cmdself.AddAlias(db, user, args) },
		},
		{
			Name: "selfDelAlias", Description: "Delete a personal alias", Permission: "selfDelAlias",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "Server alias (personal)",
			Args:    []ArgSpec{{"--id", "Alias ID"}},
			Handler: func() error { return cmdself.DelAlias(db, user, args) },
		},

		// --- Self: MFA / TOTP / PIV ---
		{
			Name: "selfSetupTOTP", Description: "Enable TOTP two-factor authentication", Permission: "selfSetupTOTP",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV",
			Handler: func() error { return cmdtotp.SetupTOTP(db, user, log) },
		},
		{
			Name: "selfDisableTOTP", Description: "Disable TOTP two-factor authentication", Permission: "selfDisableTOTP",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV",
			Handler: func() error { return cmdtotp.DisableTOTP(db, user, log) },
		},
		{
			Name: "selfSetPassword", Description: "Set a password second factor (MFA)", Permission: "selfSetPassword",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV",
			Handler: func() error { return cmdself.SetPassword(db, user, log, args) },
		},
		{
			Name: "selfChangePassword", Description: "Change your password second factor", Permission: "selfChangePassword",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV",
			Handler: func() error { return cmdself.ChangePassword(db, user, log, args) },
		},
		{
			Name: "selfDisablePassword", Description: "Disable password second factor (MFA)", Permission: "selfDisablePassword",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV",
			Handler: func() error { return cmdself.DisablePassword(db, user, log, args) },
		},
		{
			Name: "selfAddIngressKeyPIV", Description: "Add a PIV/hardware-attested SSH key (YubiKey)", Permission: "selfAddIngressKeyPIV",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV",
			Args: []ArgSpec{
				{"--attest", "Path to PIV attestation certificate (PEM)"},
				{"--intermediate", "Path to intermediate certificate (PEM)"},
				{"--comment", "Comment for this key"},
			},
			Handler: func() error { return cmdself.AddIngressKeyPIV(db, user, args) },
		},
		{
			Name: "selfGenerateBackupCodes", Description: "Generate TOTP backup codes", Permission: "selfSetupTOTP",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV",
			Handler: func() error { return cmdself.GenerateBackupCodes(db, user, log) },
		},
		{
			Name: "selfShowBackupCodeCount", Description: "Show remaining backup codes count", Permission: "selfSetupTOTP",
			Category: "MANAGE YOUR ACCOUNT", SubCategory: "MFA / TOTP / PIV",
			Handler: func() error { return cmdself.ShowBackupCodeCount(db, user) },
		},

		// --- Account ---
		{
			Name: "accountList", Description: "List all accounts", Permission: "accountList",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Accounts",
			Handler: func() error { return cmdaccount.List(db, user) },
		},
		{
			Name: "accountInfo", Description: "Show account info", Permission: "accountInfo",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Accounts",
			Args:    []ArgSpec{{"--user", "Username"}},
			Handler: func() error { return cmdaccount.Info(db, user, args) },
		},
		{
			Name: "accountCreate", Description: "Create a new account", Permission: "accountCreate",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Accounts",
			Args:    []ArgSpec{{"--user", "Username to create"}, {"--osh-only", "Restrict to -osh commands"}, {"--superowner", "Grant superowner privileges"}},
			Handler: func() error { return cmdaccount.Create(db, adapter, user, args) },
		},
		{
			Name: "accountModify", Description: "Modify an account", Permission: "accountModify",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Accounts",
			Args: []ArgSpec{
				{"--user", "Username to modify"},
				{"--sysrole", "New system role (admin or user)"},
				{"--oshOnly", "Set osh-only mode (true/false)"},
				{"--superOwner", "Set superowner mode (true/false)"},
			},
			Handler: func() error { return cmdaccount.Modify(db, user, args) },
		},
		{
			Name: "accountDelete", Description: "Delete an account", Permission: "accountDelete",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Accounts",
			Args:    []ArgSpec{{"--user", "Username to delete"}},
			Handler: func() error { return cmdaccount.Delete(db, adapter, user, args) },
		},
		{
			Name: "accountListIngressKeys", Description: "List account ingress keys", Permission: "accountListIngressKeys",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account keys",
			Args:    []ArgSpec{{"--user", "Username"}},
			Handler: func() error { return cmdaccount.ListIngressKeys(db, user, args) },
		},
		{
			Name: "accountListEgressKeys", Description: "List account egress keys", Permission: "accountListEgressKeys",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account keys",
			Args:    []ArgSpec{{"--user", "Username"}},
			Handler: func() error { return cmdaccount.ListEgressKeys(db, user, args) },
		},
		{
			Name: "accountListAccess", Description: "List account accesses", Permission: "accountListAccess",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
			Args:    []ArgSpec{{"--user", "Username"}},
			Handler: func() error { return cmdaccount.ListAccess(db, user, args) },
		},
		{
			Name: "accountAddAccess", Description: "Add access to an account", Permission: "accountAddAccess",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
			Args: []ArgSpec{
				{"--user", "Username"}, {"--server", "SSH Server"}, {"--port", "SSH Port"},
				{"--username", "SSH Username"}, {"--comment", "Comment"},
				{"--from", "Allowed source CIDRs (comma-separated)"},
				{"--ttl", "Access expiry in days"},
				{"--protocol", "Protocol restriction: ssh, scpupload, scpdownload, sftp, rsync"},
			},
			Handler: func() error { return cmdaccount.AddAccess(db, user, args) },
		},
		{
			Name: "accountDelAccess", Description: "Remove access from an account", Permission: "accountDelAccess",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
			Args:    []ArgSpec{{"--access", "Access ID"}},
			Handler: func() error { return cmdaccount.DelAccess(db, user, args) },
		},
		{
			Name: "whoHasAccessTo", Description: "List accounts with access to a server", Permission: "whoHasAccessTo",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
			Args:    []ArgSpec{{"--server", "Server"}},
			Handler: func() error { return cmdaccount.WhoHasAccessTo(db, user, args) },
		},
		{
			Name: "accountDisableTOTP", Description: "Disable TOTP for an account (admin)", Permission: "accountDisableTOTP",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
			Args:    []ArgSpec{{"--user", "Username"}},
			Handler: func() error { return cmdaccount.DisableTOTP(db, user, log, args) },
		},
		{
			Name: "accountSetPassword", Description: "Set/clear password MFA for an account (admin)", Permission: "accountSetPassword",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
			Args:    []ArgSpec{{"--user", "Target username"}, {"--clear", "Clear/remove password MFA"}},
			Handler: func() error { return cmdaccount.SetPassword(db, user, log, args) },
		},
		{
			Name: "accountDisablePassword", Description: "Disable password MFA for an account (admin)", Permission: "accountSetPassword",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
			Args:    []ArgSpec{{"--user", "Target username"}},
			Handler: func() error { return cmdaccount.DisablePassword(db, user, log, args) },
		},

		// --- PIV ---
		{
			Name: "pivAddTrustAnchor", Description: "Add a PIV/YubiKey CA trust anchor", Permission: "pivAddTrustAnchor",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
			Args:    []ArgSpec{{"--name", "Friendly name for this trust anchor"}, {"--cert", "Path to PEM certificate file"}},
			Handler: func() error { return cmdpiv.AddTrustAnchor(db, user, args) },
		},
		{
			Name: "pivListTrustAnchors", Description: "List PIV trust anchor CAs", Permission: "pivListTrustAnchors",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
			Handler: func() error { return cmdpiv.ListTrustAnchors(db, user, args) },
		},
		{
			Name: "pivRemoveTrustAnchor", Description: "Remove a PIV trust anchor CA", Permission: "pivRemoveTrustAnchor",
			Category: "MANAGE OTHER ACCOUNTS", SubCategory: "Account accesses",
			Args:    []ArgSpec{{"--name", "Name of the trust anchor to remove"}},
			Handler: func() error { return cmdpiv.RemoveTrustAnchor(db, user, args) },
		},

		// --- Realms ---
		{
			Name: "realmCreate", Description: "Create a trusted realm configuration", Permission: "realmCreate",
			Category: "RESTRICTED OPERATIONS", SubCategory: "Realms",
			Args: []ArgSpec{
				{"--realm", "Realm name"},
				{"--bastion", "Remote bastion host"},
				{"--port", "Remote bastion port (default: 22)"},
				{"--from", "Trusted source CIDRs"},
				{"--public-key", "Trusted realm SSH public key"},
			},
			Handler: func() error { return cmdrealm.Create(db, user, args) },
		},
		{
			Name: "realmList", Description: "List configured realms", Permission: "realmList",
			Category: "RESTRICTED OPERATIONS", SubCategory: "Realms",
			Handler: func() error { return cmdrealm.List(db, user, args) },
		},
		{
			Name: "realmInfo", Description: "Show details for one realm", Permission: "realmInfo",
			Category: "RESTRICTED OPERATIONS", SubCategory: "Realms",
			Args:    []ArgSpec{{"--realm", "Realm name"}},
			Handler: func() error { return cmdrealm.Info(db, user, args) },
		},
		{
			Name: "realmDelete", Description: "Delete a realm configuration", Permission: "realmDelete",
			Category: "RESTRICTED OPERATIONS", SubCategory: "Realms",
			Args:    []ArgSpec{{"--realm", "Realm name"}},
			Handler: func() error { return cmdrealm.Delete(db, user, args) },
		},

		// --- Restricted grants ---
		{
			Name: "restrictedGrantAdd", Description: "Grant a restricted command to a user", Permission: "restrictedGrantAdd",
			Category: "RESTRICTED OPERATIONS", SubCategory: "Command grants",
			Args:    []ArgSpec{{"--user", "Target username"}, {"--command", "Restricted command name"}},
			Handler: func() error { return cmdrestricted.GrantAdd(db, user, args) },
		},
		{
			Name: "restrictedGrantDel", Description: "Remove a restricted command grant", Permission: "restrictedGrantDel",
			Category: "RESTRICTED OPERATIONS", SubCategory: "Command grants",
			Args:    []ArgSpec{{"--user", "Target username"}, {"--command", "Restricted command name"}},
			Handler: func() error { return cmdrestricted.GrantDel(db, user, args) },
		},
		{
			Name: "restrictedGrantList", Description: "List restricted command grants", Permission: "restrictedGrantList",
			Category: "RESTRICTED OPERATIONS", SubCategory: "Command grants",
			Args:    []ArgSpec{{"--user", "Optional username filter"}},
			Handler: func() error { return cmdrestricted.GrantList(db, user, args) },
		},

		// --- Groups: Overview ---
		{
			Name: "groupInfo", Description: "Show group info", Permission: "groupInfo",
			Category: "MANAGE GROUPS", SubCategory: "Groups",
			Args:    []ArgSpec{{"--group", "Group name"}},
			Handler: func() error { return cmdgroup.Info(db, user, args) },
		},
		{
			Name: "groupList", Description: "List groups", Permission: "groupList",
			Category: "MANAGE GROUPS", SubCategory: "Groups",
			Args:    []ArgSpec{{"--all", "Show all groups"}},
			Handler: func() error { return cmdgroup.List(db, user, args) },
		},
		{
			Name: "groupCreate", Description: "Create a new group", Permission: "groupCreate",
			Category: "MANAGE GROUPS", SubCategory: "Groups",
			Args:    []ArgSpec{{"--group", "Group name"}},
			Handler: func() error { return cmdgroup.Create(db, user, args) },
		},
		{
			Name: "groupDelete", Description: "Delete a group", Permission: "groupDelete",
			Category: "MANAGE GROUPS", SubCategory: "Groups",
			Args:    []ArgSpec{{"--group", "Group name"}},
			Handler: func() error { return cmdgroup.Delete(db, user, args) },
		},

		// --- Groups: Members ---
		{
			Name: "groupAddMember", Description: "Add a member to a group", Permission: "groupAddMember",
			Category: "MANAGE GROUPS", SubCategory: "Group member management",
			Args: []ArgSpec{
				{"--group", "Group name"}, {"--user", "Username to add"},
				{"--role", "Role (owner, aclkeeper, gatekeeper, member, guest)"},
			},
			Handler: func() error { return cmdgroup.AddMember(db, user, args) },
		},
		{
			Name: "groupDelMember", Description: "Remove a member from a group", Permission: "groupDelMember",
			Category: "MANAGE GROUPS", SubCategory: "Group member management",
			Args:    []ArgSpec{{"--group", "Group name"}, {"--user", "Username to remove"}},
			Handler: func() error { return cmdgroup.DelMember(db, user, args) },
		},

		// --- Groups: Egress ---
		{
			Name: "groupListEgressKeys", Description: "List group egress keys", Permission: "groupListEgressKeys",
			Category: "MANAGE GROUPS", SubCategory: "Group egress (bastion → server)",
			Args:    []ArgSpec{{"--group", "Group name"}},
			Handler: func() error { return cmdgroup.ListEgressKeys(db, user, args) },
		},
		{
			Name: "groupGenerateEgressKey", Description: "Generate a new group egress key", Permission: "groupGenerateEgressKey",
			Category: "MANAGE GROUPS", SubCategory: "Group egress (bastion → server)",
			Args: []ArgSpec{
				{"--group", "Group name"}, {"--type", "Key type"}, {"--size", "Key size"},
				{"--comment", "Key comment"},
			},
			Handler: func() error { return cmdgroup.GenerateEgressKey(db, user, args) },
		},

		// --- Groups: Accesses ---
		{
			Name: "groupListAccesses", Description: "List accesses of the group", Permission: "groupListAccesses",
			Category: "MANAGE GROUPS", SubCategory: "Group accesses",
			Args:    []ArgSpec{{"--group", "Group name"}},
			Handler: func() error { return cmdgroup.ListAccesses(db, user, args) },
		},
		{
			Name: "groupAddAccess", Description: "Add access to a group", Permission: "groupAddAccess",
			Category: "MANAGE GROUPS", SubCategory: "Group accesses",
			Args: []ArgSpec{
				{"--group", "Group name"}, {"--server", "SSH Server"}, {"--port", "SSH Port"},
				{"--username", "SSH username"}, {"--comment", "Comment"},
				{"--from", "Allowed source CIDRs (comma-separated)"},
				{"--ttl", "Access expiry in days"},
				{"--protocol", "Protocol restriction: ssh, scpupload, scpdownload, sftp, rsync"},
				{"--guest", "Allow guest role members to use this access"},
				{"--force", "Skip connectivity check"},
			},
			Handler: func() error { return cmdgroup.AddAccess(db, user, args) },
		},
		{
			Name: "groupDelAccess", Description: "Remove access from a group", Permission: "groupDelAccess",
			Category: "MANAGE GROUPS", SubCategory: "Group accesses",
			Args:    []ArgSpec{{"--group", "Group name"}, {"--access", "Access ID to remove"}},
			Handler: func() error { return cmdgroup.DelAccess(db, user, args) },
		},
		{
			Name: "groupSetMFA", Description: "Enable/disable JIT MFA requirement for a group", Permission: "groupSetMFA",
			Category: "MANAGE GROUPS", SubCategory: "Group accesses",
			Args: []ArgSpec{
				{"--group", "Group name"}, {"--required", "Require MFA for this group"},
				{"--optional", "Remove MFA requirement for this group"},
			},
			Handler: func() error { return cmdgroup.SetMFA(db, user, log, args) },
		},

		// --- Groups: Aliases ---
		{
			Name: "groupAddAlias", Description: "Add a group alias", Permission: "groupAddAlias",
			Category: "MANAGE GROUPS", SubCategory: "Group alias (group)",
			Args:    []ArgSpec{{"--group", "Group name"}, {"--alias", "Alias"}, {"--hostname", "Host name"}},
			Handler: func() error { return cmdgroup.AddAlias(db, user, args) },
		},
		{
			Name: "groupDelAlias", Description: "Delete a group alias", Permission: "groupDelAlias",
			Category: "MANAGE GROUPS", SubCategory: "Group alias (group)",
			Args:    []ArgSpec{{"--group", "Group name"}, {"--id", "Alias ID"}},
			Handler: func() error { return cmdgroup.DelAlias(db, user, args) },
		},
		{
			Name: "groupListAliases", Description: "List group aliases", Permission: "groupListAliases",
			Category: "MANAGE GROUPS", SubCategory: "Group alias (group)",
			Args:    []ArgSpec{{"--group", "Group name"}},
			Handler: func() error { return cmdgroup.ListAliases(db, user, args) },
		},

		// --- TTY ---
		{
			Name: "ttyList", Description: "List recorded tty sessions", Permission: "ttyList",
			Category: "TTY SESSIONS", SubCategory: "",
			Args: []ArgSpec{
				{"--startDate", "Start date"}, {"--endDate", "End date"},
				{"--host", "Filter by server hostname"},
			},
			Handler: func() error { return cmdtty.List(db, user, args) },
		},
		{
			Name: "ttyPlay", Description: "Replay a recorded tty session", Permission: "ttyPlay",
			Category: "TTY SESSIONS", SubCategory: "",
			Args:    []ArgSpec{{"--file", "File name"}},
			Handler: func() error { return cmdtty.Play(db, user, args) },
		},

		// --- Misc ---
		{
			Name: "help", Description: "Display this help message", Permission: "help",
			Category: "MISC COMMANDS", SubCategory: "Basic commands",
			Handler: nil, // handled specially in executeCommand
		},
		{
			Name: "info", Description: "Show application info", Permission: "info",
			Category: "MISC COMMANDS", SubCategory: "Basic commands",
			Handler: nil, // handled specially
		},
		{
			Name: "exit", Description: "Exit the application", Permission: "exit",
			Category: "MISC COMMANDS", SubCategory: "Basic commands",
			Handler: nil, // handled specially
		},
	}
}

// PromptSuggest converts the registry to go-prompt suggestions, filtered by permission.
func PromptSuggest(cmds []CommandSpec, hasPerm func(string) bool) []prompt.Suggest {
	var out []prompt.Suggest
	for _, c := range cmds {
		if c.Permission == "" || hasPerm(c.Permission) {
			out = append(out, prompt.Suggest{Text: c.Name, Description: c.Description})
		}
	}
	return out
}

// PromptArgs returns autocomplete suggestions for the given command's flags.
func PromptArgs(cmds []CommandSpec, cmdName string, hasPerm func(string) bool) []prompt.Suggest {
	for _, c := range cmds {
		if c.Name == cmdName {
			if c.Permission != "" && !hasPerm(c.Permission) {
				return nil
			}
			var out []prompt.Suggest
			for _, a := range c.Args {
				out = append(out, prompt.Suggest{Text: a.Name, Description: a.Description})
			}
			return out
		}
	}
	return nil
}
