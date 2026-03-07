package session

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"github.com/c-bata/go-prompt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"gorm.io/gorm"

	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/utils"
	"goBastion/internal/utils/autocomplete"
	"goBastion/internal/utils/totp"

	cmdaccount "goBastion/internal/commands/account"
	cmdgroup "goBastion/internal/commands/group"
	cmdhelp "goBastion/internal/commands/help"
	cmdpiv "goBastion/internal/commands/piv"
	cmdself "goBastion/internal/commands/self"
	cmdssh "goBastion/internal/commands/ssh"
	cmdtotp "goBastion/internal/commands/totp"
	cmdtty "goBastion/internal/commands/tty"
)

// Run is the main entry point after DB init: it looks up the current user,
// runs the pre-connection checks, then dispatches to interactive or non-interactive mode.
func Run(db *gorm.DB, log *slog.Logger) {
	sysUser, err := currentSystemUser()
	if err != nil {
		log.Error("system user lookup failed", slog.String("error", err.Error()))
		return
	}

	var currentUser models.User
	if err = db.Where("username = ?", sysUser).First(&currentUser).Error; err != nil {
		ip := strings.Split(os.Getenv("SSH_CLIENT"), " ")[0]
		log.Warn("login rejected", slog.String("user", sysUser), slog.String("from", ip), slog.String("reason", "user not in database"))
		fmt.Printf("User %s not found in database. Exiting.\n", sysUser)
		return
	}

	if !preConnectionCheck(db, currentUser, log) {
		return
	}

	if len(os.Args) == 1 {
		if !checkTOTP(&currentUser, log) {
			return
		}
		log.Info("session_start", slog.String("user", currentUser.Username), slog.String("event", "session_start"), slog.String("cmd", "interactive"))
		runInteractiveMode(db, &currentUser, log)
	} else {
		cmd := os.Args[1]
		args := os.Args[2:]
		if strings.TrimSpace(cmd) == "" {
			if !checkTOTP(&currentUser, log) {
				return
			}
			log.Info("session_start", slog.String("user", currentUser.Username), slog.String("event", "session_start"), slog.String("cmd", "interactive"))
			runInteractiveMode(db, &currentUser, log)
		} else {
			// Skip TOTP for raw TCP proxy (-W) and sftp-session: no TTY, raw pipe only.
			_, _, isTCPProxy := parseTCPProxyRequest(cmd, args)
			isSftpSession := strings.HasPrefix(cmd, "sftp-session")
			if !isTCPProxy && !isSftpSession {
				if !checkTOTP(&currentUser, log) {
					return
				}
			}
			log.Info("session_start", slog.String("user", currentUser.Username), slog.String("event", "session_start"), slog.String("cmd", cmd))
			runNonInteractiveMode(db, &currentUser, log, cmd, args)
			log.Info("session_end", slog.String("user", currentUser.Username), slog.String("event", "session_end"))
		}
	}
}

// runNonInteractiveMode executes a single bastion command passed via -osh flag.
func runNonInteractiveMode(db *gorm.DB, currentUser *models.User, log *slog.Logger, command string, args []string) {
	if command == "-osh" {
		if len(args) < 1 {
			fmt.Println("Usage: -osh <command> <args>")
			fmt.Println("Entering interactive mode.")
			runInteractiveMode(db, currentUser, log)
			return
		}
	}

	if strings.HasPrefix(command, "-osh") {
		parts := strings.Split(command, "-osh")
		command = parts[1]
		commandParts := strings.Split(command, " ")
		if len(commandParts) > 1 {
			command = commandParts[1]
			args = commandParts[2:]
		}
		executeCommand(db, currentUser, log, command, args)
	} else if host, port, ok := parseTCPProxyRequest(command, args); ok {
		if err := cmdssh.TCPProxy(db, *currentUser, *log, host, port); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	} else if strings.HasPrefix(command, "sftp-session") {
		target := strings.TrimPrefix(strings.TrimPrefix(command, "sftp-session "), "sftp-session")
		if err := cmdssh.SftpSession(db, *currentUser, *log, target); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	} else if isMoshServerRequest(command, args) {
		runMoshServer(command, args, log)
	} else {
		if err := cmdssh.SSHConnect(db, *currentUser, *log, command); err != nil {
			fmt.Println(err)
		}
	}
}

// runInteractiveMode starts the interactive prompt loop for the user session.
func runInteractiveMode(db *gorm.DB, currentUser *models.User, log *slog.Logger) {
	defer resetStdIn()
	fmt.Println(utils.FgBlueB("Type 'help' to display available commands, 'tab' to autocomplete, 'exit' to quit."))

	showCompletions := false

	wrappedCompleter := func(d prompt.Document) []prompt.Suggest {
		if showCompletions {
			return autocomplete.Completion(d, currentUser, db)
		}
		return []prompt.Suggest{}
	}

	tabKeyBinding := prompt.KeyBind{
		Key: prompt.Tab,
		Fn: func(buf *prompt.Buffer) {
			showCompletions = true
			buf.InsertText("", false, true)
		},
	}

	escKeyBinding := prompt.KeyBind{
		Key: prompt.Escape,
		Fn: func(buf *prompt.Buffer) {
			if showCompletions {
				showCompletions = false
				buf.InsertText("", false, true)
			}
		},
	}

	promptSymbol := "$ "
	if currentUser.IsAdmin() {
		promptSymbol = "# "
	}

	bastionName, _ := os.Hostname()

	p := prompt.New(
		func(in string) {
			showCompletions = false
			tokens := strings.Fields(in)
			if len(tokens) == 0 {
				return
			}
			executeCommand(db, currentUser, log, tokens[0], tokens[1:])
		},
		wrappedCompleter,
		prompt.OptionPrefix(currentUser.Username+"@"+bastionName+":"+promptSymbol),
		prompt.OptionPrefixTextColor(prompt.DarkGreen),
		prompt.OptionAddKeyBind(tabKeyBinding),
		prompt.OptionAddKeyBind(escKeyBinding),
	)
	p.Run()
	log.Info("session_end", slog.String("user", currentUser.Username), slog.String("event", "session_end"), slog.String("reason", "disconnect"))
}

// executeCommand looks up and runs a command, enforcing permission checks.
func executeCommand(db *gorm.DB, currentUser *models.User, log *slog.Logger, cmd string, args []string) {
	resetStdIn() // Mandatory: prevents the terminal from being left in a broken state.

	// Attach user to all log records emitted during this command.
	log = log.With(slog.String("user", currentUser.Username))

	hasPerm := func(perm string) bool {
		return currentUser.CanDo(db, perm, "")
	}

	adapter := osadapter.NewLinuxAdapter()

	type entry struct {
		Perm    string
		Handler func()
	}

	commandsMap := map[string]entry{
		// Self
		"selfListIngressKeys": {"selfListIngressKeys", func() {
			if err := cmdself.SelfListIngressKeys(db, currentUser); err != nil {
				log.Error("command_error", slog.String("cmd", "selfListIngressKeys"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfAddIngressKey": {"selfAddIngressKey", func() {
			if err := cmdself.SelfAddIngressKey(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "selfAddIngressKey"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfDelIngressKey": {"selfDelIngressKey", func() {
			if err := cmdself.SelfDelIngressKey(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "selfDelIngressKey"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfGenerateEgressKey": {"selfGenerateEgressKey", func() {
			if err := cmdself.SelfGenerateEgressKey(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "selfGenerateEgressKey"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfListEgressKeys": {"selfListEgressKeys", func() {
			if err := cmdself.SelfListEgressKeys(db, currentUser); err != nil {
				log.Error("command_error", slog.String("cmd", "selfListEgressKeys"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfListAccesses": {"selfListAccesses", func() {
			if err := cmdself.SelfListAccesses(db, currentUser); err != nil {
				log.Error("command_error", slog.String("cmd", "selfListAccesses"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfAddAccess": {"selfAddAccess", func() {
			if err := cmdself.SelfAddAccess(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "selfAddAccess"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfDelAccess": {"selfDelAccess", func() {
			if err := cmdself.SelfDelAccess(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "selfDelAccess"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfAddAlias": {"selfAddAlias", func() {
			if err := cmdself.SelfAddAlias(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "selfAddAlias"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfDelAlias": {"selfDelAlias", func() {
			if err := cmdself.SelfDelAlias(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "selfDelAlias"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfListAliases": {"selfListAliases", func() {
			if err := cmdself.SelfListAliases(db, currentUser); err != nil {
				log.Error("command_error", slog.String("cmd", "selfListAliases"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfRemoveHostFromKnownHosts": {"selfRemoveHostFromKnownHosts", func() {
			if err := cmdself.SelfRemoveHostFromKnownHosts(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "selfRemoveHostFromKnownHosts"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfReplaceKnownHost": {"selfReplaceKnownHost", func() {
			if err := cmdself.SelfReplaceKnownHost(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "selfReplaceKnownHost"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfSetupTOTP": {"selfSetupTOTP", func() {
			if err := cmdtotp.SelfSetupTOTP(db, currentUser); err != nil {
				log.Error("command_error", slog.String("cmd", "selfSetupTOTP"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfDisableTOTP": {"selfDisableTOTP", func() {
			if err := cmdtotp.SelfDisableTOTP(db, currentUser); err != nil {
				log.Error("command_error", slog.String("cmd", "selfDisableTOTP"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},

		// Account
		"accountList": {"accountList", func() {
			if err := cmdaccount.AccountList(db, currentUser); err != nil {
				log.Error("command_error", slog.String("cmd", "accountList"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"accountInfo": {"accountInfo", func() {
			if err := cmdaccount.AccountInfo(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "accountInfo"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"accountCreate": {"accountCreate", func() {
			if err := cmdaccount.AccountCreate(db, adapter, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "accountCreate"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"accountListIngressKeys": {"accountListIngressKeys", func() {
			if err := cmdaccount.AccountListIngressKeys(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "accountListIngressKeys"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"accountListEgressKeys": {"accountListEgressKeys", func() {
			if err := cmdaccount.AccountListEgressKeys(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "accountListEgressKeys"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"accountModify": {"accountModify", func() {
			if err := cmdaccount.AccountModify(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "accountModify"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"accountDelete": {"accountDelete", func() {
			if err := cmdaccount.AccountDelete(db, adapter, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "accountDelete"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"accountAddAccess": {"accountAddAccess", func() {
			if err := cmdaccount.AccountAddAccess(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "accountAddAccess"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"accountDelAccess": {"accountDelAccess", func() {
			if err := cmdaccount.AccountDelAccess(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "accountDelAccess"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"accountListAccess": {"accountListAccess", func() {
			if err := cmdaccount.AccountListAccess(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "accountListAccess"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"accountDisableTOTP": {"accountDisableTOTP", func() {
			if err := cmdaccount.AccountDisableTOTP(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "accountDisableTOTP"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},

		// PIV attestation (admin)
		"pivAddTrustAnchor": {"pivAddTrustAnchor", func() {
			if err := cmdpiv.PivAddTrustAnchor(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "pivAddTrustAnchor"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"pivListTrustAnchors": {"pivListTrustAnchors", func() {
			if err := cmdpiv.PivListTrustAnchors(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "pivListTrustAnchors"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"pivRemoveTrustAnchor": {"pivRemoveTrustAnchor", func() {
			if err := cmdpiv.PivRemoveTrustAnchor(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "pivRemoveTrustAnchor"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},

		// PIV attestation (self)
		"selfAddIngressKeyPIV": {"selfAddIngressKeyPIV", func() {
			if err := cmdself.SelfAddIngressKeyPIV(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "selfAddIngressKeyPIV"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},

		// Group
		"groupInfo": {"groupInfo", func() {
			if err := cmdgroup.GroupInfo(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupInfo"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupList": {"groupList", func() {
			if err := cmdgroup.GroupList(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupList"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupCreate": {"groupCreate", func() {
			if err := cmdgroup.GroupCreate(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupCreate"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupDelete": {"groupDelete", func() {
			if err := cmdgroup.GroupDelete(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupDelete"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupAddAccess": {"groupAddAccess", func() {
			if err := cmdgroup.GroupAddAccess(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupAddAccess"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupDelAccess": {"groupDelAccess", func() {
			if err := cmdgroup.GroupDelAccess(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupDelAccess"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupAddMember": {"groupAddMember", func() {
			if err := cmdgroup.GroupAddMember(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupAddMember"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupDelMember": {"groupDelMember", func() {
			if err := cmdgroup.GroupDelMember(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupDelMember"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupGenerateEgressKey": {"groupGenerateEgressKey", func() {
			if err := cmdgroup.GroupGenerateEgressKey(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupGenerateEgressKey"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupListEgressKeys": {"groupListEgressKeys", func() {
			if err := cmdgroup.GroupListEgressKeys(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupListEgressKeys"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupListAccesses": {"groupListAccesses", func() {
			if err := cmdgroup.GroupListAccesses(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupListAccesses"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupAddAlias": {"groupAddAlias", func() {
			if err := cmdgroup.GroupAddAlias(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupAddAlias"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupDelAlias": {"groupDelAlias", func() {
			if err := cmdgroup.GroupDelAlias(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupDelAlias"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupListAliases": {"groupListAliases", func() {
			if err := cmdgroup.GroupListAliases(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupListAliases"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"groupSetMFA": {"groupSetMFA", func() {
			if err := cmdgroup.GroupSetMFA(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "groupSetMFA"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},

		// Password MFA
		"selfSetPassword": {"selfSetPassword", func() {
			if err := cmdself.SelfSetPassword(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "selfSetPassword"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"selfChangePassword": {"selfChangePassword", func() {
			if err := cmdself.SelfChangePassword(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "selfChangePassword"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"accountSetPassword": {"accountSetPassword", func() {
			if err := cmdaccount.AccountSetPassword(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "accountSetPassword"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},

		// TTY
		"ttyList": {"ttyList", func() {
			if err := cmdtty.TtyList(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "ttyList"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"ttyPlay": {"ttyPlay", func() {
			if err := cmdtty.TtyPlay(db, currentUser, args); err != nil {
				resetStdIn()
				log.Error("command_error", slog.String("cmd", "ttyPlay"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},
		"whoHasAccessTo": {"whoHasAccessTo", func() {
			if err := cmdaccount.WhoHasAccessTo(db, currentUser, args); err != nil {
				log.Error("command_error", slog.String("cmd", "whoHasAccessTo"), slog.String("event", "command_error"), slog.String("error", err.Error()))
			}
		}},

		// Misc
		"help": {"help", func() { cmdhelp.DisplayHelp(db, *currentUser) }},
		"info": {"info", func() { cmdhelp.DisplayInfo() }},
		"exit": {"exit", func() {
			log.Info("session end", slog.String("reason", "exit"))
			os.Exit(0)
		}},
	}
	if e, ok := commandsMap[cmd]; !ok {
		log.Warn("command_error", slog.String("cmd", cmd), slog.String("event", "command_error"), slog.String("reason", "unknown command"))
		fmt.Printf("Unknown command: %s\n", cmd)
	} else if !hasPerm(e.Perm) {
		log.Warn("command_error", slog.String("cmd", cmd), slog.String("event", "command_error"), slog.String("reason", "permission denied"))
		fmt.Printf("Permission denied: %s\n", cmd)
	} else {
		log.Info("command", slog.String("cmd", cmd), slog.String("event", "command"))
		e.Handler()
	}
}

// resetStdIn restores the terminal to canonical (cooked) mode.
func resetStdIn() {
	cmd := exec.Command("/bin/stty", "-raw", "echo")
	cmd.Stdin = os.Stdin
	_ = cmd.Run()
	_ = cmd.Wait()
}

// checkMFA prompts for TOTP and/or password second factors if configured.
// Returns false if any check fails, which should cause the session to be terminated immediately.
func checkMFA(user *models.User, log *slog.Logger) bool {
	ip := strings.Split(os.Getenv("SSH_CLIENT"), " ")[0]

	// Password MFA check (independent of TOTP)
	if user.PasswordHash != "" {
		log.Info("mfa_challenge", slog.String("event", "mfa_password"), slog.String("user", user.Username), slog.String("from", ip))
		fmt.Print("🔑 Enter password: ")
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Warn("mfa_error", slog.String("event", "mfa_password"), slog.String("user", user.Username), slog.String("error", err.Error()))
			fmt.Fprintln(os.Stderr, "⛔ Could not read password.")
			return false
		}
		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), pass) != nil {
			log.Warn("mfa_failure", slog.String("event", "mfa_password"), slog.String("user", user.Username), slog.String("from", ip))
			fmt.Println("⛔ Invalid password. Access denied.")
			return false
		}
		log.Info("mfa_success", slog.String("event", "mfa_password"), slog.String("user", user.Username), slog.String("from", ip))
	}

	// TOTP check
	if !user.TOTPEnabled || user.TOTPSecret == "" {
		return true
	}
	log.Info("mfa_challenge", slog.String("event", "mfa_totp"), slog.String("user", user.Username), slog.String("from", ip))
	fmt.Print("🔐 Enter TOTP code: ")
	reader := bufio.NewReader(os.Stdin)
	code, err := reader.ReadString('\n')
	if err != nil {
		log.Warn("mfa_error", slog.String("event", "mfa_totp"), slog.String("user", user.Username), slog.String("from", ip), slog.String("error", err.Error()))
		fmt.Fprintln(os.Stderr, "\n⛔ Could not read TOTP code.")
		return false
	}
	if !totp.Verify(user.TOTPSecret, strings.TrimSpace(code)) {
		log.Warn("mfa_failure", slog.String("event", "mfa_totp"), slog.String("user", user.Username), slog.String("from", ip))
		fmt.Println("⛔ Invalid TOTP code. Access denied.")
		return false
	}
	log.Info("mfa_success", slog.String("event", "mfa_totp"), slog.String("user", user.Username), slog.String("from", ip))
	return true
}

// checkTOTP is kept for backward compatibility; delegates to checkMFA.
func checkTOTP(user *models.User, log *slog.Logger) bool {
	return checkMFA(user, log)
}

// parseTCPProxyRequest detects an OpenSSH -W host:port proxy request and returns the target.
// The ForceCommand in sshd_config passes SSH_ORIGINAL_COMMAND as a single quoted argument,
// so "-W host:port" arrives as os.Args[1]. Two-arg form is also handled for safety.
func parseTCPProxyRequest(cmd string, args []string) (host, port string, ok bool) {
	var hostPort string
	if strings.HasPrefix(cmd, "-W ") {
		hostPort = strings.TrimPrefix(cmd, "-W ")
	} else if cmd == "-W" && len(args) > 0 {
		hostPort = args[0]
	} else {
		return "", "", false
	}
	h, p, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", "", false
	}
	return h, p, true
}

// currentSystemUser returns the username of the current OS process owner.
func currentSystemUser() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// isMoshServerRequest returns true when the SSH_ORIGINAL_COMMAND is a mosh-server invocation.
// The mosh client sends: mosh-server new -s -c <cols> -l LANG=... -- ...
func isMoshServerRequest(command string, args []string) bool {
	return command == "mosh-server" || strings.HasPrefix(command, "mosh-server ")
}

// runMoshServer exec's mosh-server directly, passing through all arguments.
// stdin/stdout/stderr are inherited so the mosh client can negotiate the UDP port.
func runMoshServer(command string, extraArgs []string, log *slog.Logger) {
	// Reconstruct the full argument list from the original command string + extra args.
	parts := strings.Fields(command)
	if len(parts) == 0 {
		fmt.Fprintln(os.Stderr, "mosh-server: empty command")
		return
	}
	// parts[0] is "mosh-server", parts[1:] are inline args from the command string.
	cmdArgs := append(parts[1:], extraArgs...)

	log.Info("mosh_server", slog.String("event", "mosh_server"))

	cmd := exec.Command("mosh-server", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Error("mosh_server", slog.String("event", "mosh_server"), slog.String("error", err.Error()))
	}
}
