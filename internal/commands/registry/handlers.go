package registry

import (
	"log/slog"

	"gorm.io/gorm"

	cmdaccount "goBastion/internal/commands/account"
	cmdconfig "goBastion/internal/commands/config"
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

// buildHandlers creates a map of command name to handler closure for the given session.
func buildHandlers(db *gorm.DB, user *models.User, log *slog.Logger, adapter osadapter.SystemAdapter, args []string, exitFunc func()) map[string]func() error {
	return map[string]func() error{
		// Self: Ingress
		"selfListIngressKeys": func() error { return cmdself.ListIngressKeys(db, user) },
		"selfAddIngressKey":    func() error { return cmdself.AddIngressKey(db, user, args) },
		"selfDelIngressKey":    func() error { return cmdself.DelIngressKey(db, user, args) },

		// Self: Egress
		"selfListEgressKeys":         func() error { return cmdself.ListEgressKeys(db, user) },
		"selfGenerateEgressKey":      func() error { return cmdself.GenerateEgressKey(db, user, args) },
		"selfRemoveHostFromKnownHosts": func() error { return cmdself.RemoveHostFromKnownHosts(db, user, args) },
		"selfReplaceKnownHost":       func() error { return cmdself.ReplaceKnownHost(db, user, args) },

		// Self: Accesses
		"selfListAccesses": func() error { return cmdself.ListAccesses(db, user) },
		"selfAddAccess":    func() error { return cmdself.AddAccess(db, user, args) },
		"selfDelAccess":    func() error { return cmdself.DelAccess(db, user, args) },

		// Self: Aliases
		"selfListAliases": func() error { return cmdself.ListAliases(db, user) },
		"selfAddAlias":    func() error { return cmdself.AddAlias(db, user, args) },
		"selfDelAlias":    func() error { return cmdself.DelAlias(db, user, args) },

		// Self: MFA / TOTP / PIV
		"selfSetupTOTP":           func() error { return cmdtotp.SetupTOTP(db, user, log) },
		"selfDisableTOTP":         func() error { return cmdtotp.DisableTOTP(db, user, log) },
		"selfSetPassword":         func() error { return cmdself.SetPassword(db, user, log, args) },
		"selfChangePassword":      func() error { return cmdself.ChangePassword(db, user, log, args) },
		"selfDisablePassword":     func() error { return cmdself.DisablePassword(db, user, log, args) },
		"selfAddIngressKeyPIV":    func() error { return cmdself.AddIngressKeyPIV(db, user, args) },
		"selfGenerateBackupCodes": func() error { return cmdself.GenerateBackupCodes(db, user, log) },
		"selfShowBackupCodeCount": func() error { return cmdself.ShowBackupCodeCount(db, user) },

		// Account
		"accountList":            func() error { return cmdaccount.List(db, user) },
		"accountInfo":            func() error { return cmdaccount.Info(db, user, args) },
		"accountCreate":          func() error { return cmdaccount.Create(db, adapter, user, args) },
		"accountModify":          func() error { return cmdaccount.Modify(db, user, args) },
		"accountDelete":          func() error { return cmdaccount.Delete(db, adapter, user, args) },
		"accountListIngressKeys": func() error { return cmdaccount.ListIngressKeys(db, user, args) },
		"accountListEgressKeys":  func() error { return cmdaccount.ListEgressKeys(db, user, args) },
		"accountListAccess":      func() error { return cmdaccount.ListAccess(db, user, args) },
		"accountAddAccess":       func() error { return cmdaccount.AddAccess(db, user, args) },
		"accountDelAccess":       func() error { return cmdaccount.DelAccess(db, user, args) },
		"whoHasAccessTo":         func() error { return cmdaccount.WhoHasAccessTo(db, user, args) },
		"accountDisableTOTP":     func() error { return cmdaccount.DisableTOTP(db, user, log, args) },
		"accountSetPassword":     func() error { return cmdaccount.SetPassword(db, user, log, args) },
		"accountDisablePassword": func() error { return cmdaccount.DisablePassword(db, user, log, args) },
		"accountUnexpire":        func() error { return cmdaccount.Unexpire(db, user, args) },
		"accountExpire":          func() error { return cmdaccount.Expire(db, user, args) },

		// PIV
		"pivAddTrustAnchor":    func() error { return cmdpiv.AddTrustAnchor(db, user, args) },
		"pivListTrustAnchors":  func() error { return cmdpiv.ListTrustAnchors(db, user, args) },
		"pivRemoveTrustAnchor": func() error { return cmdpiv.RemoveTrustAnchor(db, user, args) },

		// Realms
		"realmCreate": func() error { return cmdrealm.Create(db, user, args) },
		"realmList":   func() error { return cmdrealm.List(db, user, args) },
		"realmInfo":   func() error { return cmdrealm.Info(db, user, args) },
		"realmDelete": func() error { return cmdrealm.Delete(db, user, args) },

		// Restricted grants
		"restrictedGrantAdd":  func() error { return cmdrestricted.GrantAdd(db, user, args) },
		"restrictedGrantDel":  func() error { return cmdrestricted.GrantDel(db, user, args) },
		"restrictedGrantList": func() error { return cmdrestricted.GrantList(db, user, args) },

		// Groups: Overview
		"groupInfo":   func() error { return cmdgroup.Info(db, user, args) },
		"groupList":   func() error { return cmdgroup.List(db, user, args) },
		"groupCreate": func() error { return cmdgroup.Create(db, user, args) },
		"groupDelete": func() error { return cmdgroup.Delete(db, user, args) },

		// Groups: Members
		"groupAddMember": func() error { return cmdgroup.AddMember(db, user, args) },
		"groupDelMember": func() error { return cmdgroup.DelMember(db, user, args) },

		// Groups: Egress
		"groupListEgressKeys":    func() error { return cmdgroup.ListEgressKeys(db, user, args) },
		"groupGenerateEgressKey": func() error { return cmdgroup.GenerateEgressKey(db, user, args) },

		// Groups: Accesses
		"groupListAccesses": func() error { return cmdgroup.ListAccesses(db, user, args) },
		"groupAddAccess":    func() error { return cmdgroup.AddAccess(db, user, args) },
		"groupDelAccess":    func() error { return cmdgroup.DelAccess(db, user, args) },
		"groupSetMFA":       func() error { return cmdgroup.SetMFA(db, user, log, args) },

		// Groups: Guest Accesses
		"groupAddGuestAccess":    func() error { return cmdgroup.AddGuestAccess(db, user, args) },
		"groupDelGuestAccess":    func() error { return cmdgroup.DelGuestAccess(db, user, args) },
		"groupListGuestAccesses": func() error { return cmdgroup.ListGuestAccesses(db, user, args) },

		// Groups: Aliases
		"groupAddAlias":    func() error { return cmdgroup.AddAlias(db, user, args) },
		"groupDelAlias":    func() error { return cmdgroup.DelAlias(db, user, args) },
		"groupListAliases": func() error { return cmdgroup.ListAliases(db, user, args) },

		// TTY
		"ttyList": func() error { return cmdtty.List(db, user, args) },
		"ttyPlay": func() error { return cmdtty.Play(db, user, args) },

		// Misc (handled specially in executeCommand, but mapped here for completeness)
		"help": nil,
		"info": nil,
		"exit": nil,

		// Bastion Config
		"bastionConfig": func() error { return cmdconfig.BastionConfig(db, user) },
	}
}
