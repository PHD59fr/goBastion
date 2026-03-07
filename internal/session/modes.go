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
		Handler func() error
	}

	commandsMap := map[string]entry{
		// Self
		"selfListIngressKeys":          {"selfListIngressKeys", func() error { return cmdself.SelfListIngressKeys(db, currentUser) }},
		"selfAddIngressKey":            {"selfAddIngressKey", func() error { return cmdself.SelfAddIngressKey(db, currentUser, args) }},
		"selfDelIngressKey":            {"selfDelIngressKey", func() error { return cmdself.SelfDelIngressKey(db, currentUser, args) }},
		"selfGenerateEgressKey":        {"selfGenerateEgressKey", func() error { return cmdself.SelfGenerateEgressKey(db, currentUser, args) }},
		"selfListEgressKeys":           {"selfListEgressKeys", func() error { return cmdself.SelfListEgressKeys(db, currentUser) }},
		"selfListAccesses":             {"selfListAccesses", func() error { return cmdself.SelfListAccesses(db, currentUser) }},
		"selfAddAccess":                {"selfAddAccess", func() error { return cmdself.SelfAddAccess(db, currentUser, args) }},
		"selfDelAccess":                {"selfDelAccess", func() error { return cmdself.SelfDelAccess(db, currentUser, args) }},
		"selfAddAlias":                 {"selfAddAlias", func() error { return cmdself.SelfAddAlias(db, currentUser, args) }},
		"selfDelAlias":                 {"selfDelAlias", func() error { return cmdself.SelfDelAlias(db, currentUser, args) }},
		"selfListAliases":              {"selfListAliases", func() error { return cmdself.SelfListAliases(db, currentUser) }},
		"selfRemoveHostFromKnownHosts": {"selfRemoveHostFromKnownHosts", func() error { return cmdself.SelfRemoveHostFromKnownHosts(db, currentUser, args) }},
		"selfReplaceKnownHost":         {"selfReplaceKnownHost", func() error { return cmdself.SelfReplaceKnownHost(db, currentUser, args) }},
		"selfSetupTOTP":                {"selfSetupTOTP", func() error { return cmdtotp.SelfSetupTOTP(db, currentUser) }},
		"selfDisableTOTP":              {"selfDisableTOTP", func() error { return cmdtotp.SelfDisableTOTP(db, currentUser) }},
		"selfSetPassword":              {"selfSetPassword", func() error { return cmdself.SelfSetPassword(db, currentUser, args) }},
		"selfChangePassword":           {"selfChangePassword", func() error { return cmdself.SelfChangePassword(db, currentUser, args) }},
		"selfAddIngressKeyPIV":         {"selfAddIngressKeyPIV", func() error { return cmdself.SelfAddIngressKeyPIV(db, currentUser, args) }},

		// Account
		"accountList":            {"accountList", func() error { return cmdaccount.AccountList(db, currentUser) }},
		"accountInfo":            {"accountInfo", func() error { return cmdaccount.AccountInfo(db, currentUser, args) }},
		"accountCreate":          {"accountCreate", func() error { return cmdaccount.AccountCreate(db, adapter, currentUser, args) }},
		"accountListIngressKeys": {"accountListIngressKeys", func() error { return cmdaccount.AccountListIngressKeys(db, currentUser, args) }},
		"accountListEgressKeys":  {"accountListEgressKeys", func() error { return cmdaccount.AccountListEgressKeys(db, currentUser, args) }},
		"accountModify":          {"accountModify", func() error { return cmdaccount.AccountModify(db, currentUser, args) }},
		"accountDelete":          {"accountDelete", func() error { return cmdaccount.AccountDelete(db, adapter, currentUser, args) }},
		"accountAddAccess":       {"accountAddAccess", func() error { return cmdaccount.AccountAddAccess(db, currentUser, args) }},
		"accountDelAccess":       {"accountDelAccess", func() error { return cmdaccount.AccountDelAccess(db, currentUser, args) }},
		"accountListAccess":      {"accountListAccess", func() error { return cmdaccount.AccountListAccess(db, currentUser, args) }},
		"accountDisableTOTP":     {"accountDisableTOTP", func() error { return cmdaccount.AccountDisableTOTP(db, currentUser, args) }},
		"accountSetPassword":     {"accountSetPassword", func() error { return cmdaccount.AccountSetPassword(db, currentUser, args) }},
		"whoHasAccessTo":         {"whoHasAccessTo", func() error { return cmdaccount.WhoHasAccessTo(db, currentUser, args) }},

		// PIV attestation
		"pivAddTrustAnchor":    {"pivAddTrustAnchor", func() error { return cmdpiv.PivAddTrustAnchor(db, currentUser, args) }},
		"pivListTrustAnchors":  {"pivListTrustAnchors", func() error { return cmdpiv.PivListTrustAnchors(db, currentUser, args) }},
		"pivRemoveTrustAnchor": {"pivRemoveTrustAnchor", func() error { return cmdpiv.PivRemoveTrustAnchor(db, currentUser, args) }},

		// Group
		"groupInfo":             {"groupInfo", func() error { return cmdgroup.GroupInfo(db, currentUser, args) }},
		"groupList":             {"groupList", func() error { return cmdgroup.GroupList(db, currentUser, args) }},
		"groupCreate":           {"groupCreate", func() error { return cmdgroup.GroupCreate(db, currentUser, args) }},
		"groupDelete":           {"groupDelete", func() error { return cmdgroup.GroupDelete(db, currentUser, args) }},
		"groupAddAccess":        {"groupAddAccess", func() error { return cmdgroup.GroupAddAccess(db, currentUser, args) }},
		"groupDelAccess":        {"groupDelAccess", func() error { return cmdgroup.GroupDelAccess(db, currentUser, args) }},
		"groupAddMember":        {"groupAddMember", func() error { return cmdgroup.GroupAddMember(db, currentUser, args) }},
		"groupDelMember":        {"groupDelMember", func() error { return cmdgroup.GroupDelMember(db, currentUser, args) }},
		"groupGenerateEgressKey": {"groupGenerateEgressKey", func() error { return cmdgroup.GroupGenerateEgressKey(db, currentUser, args) }},
		"groupListEgressKeys":   {"groupListEgressKeys", func() error { return cmdgroup.GroupListEgressKeys(db, currentUser, args) }},
		"groupListAccesses":     {"groupListAccesses", func() error { return cmdgroup.GroupListAccesses(db, currentUser, args) }},
		"groupAddAlias":         {"groupAddAlias", func() error { return cmdgroup.GroupAddAlias(db, currentUser, args) }},
		"groupDelAlias":         {"groupDelAlias", func() error { return cmdgroup.GroupDelAlias(db, currentUser, args) }},
		"groupListAliases":      {"groupListAliases", func() error { return cmdgroup.GroupListAliases(db, currentUser, args) }},
		"groupSetMFA":           {"groupSetMFA", func() error { return cmdgroup.GroupSetMFA(db, currentUser, args) }},

		// TTY
		"ttyList": {"ttyList", func() error { return cmdtty.TtyList(db, currentUser, args) }},
		"ttyPlay": {"ttyPlay", func() error {
			err := cmdtty.TtyPlay(db, currentUser, args)
			resetStdIn()
			return err
		}},

		// Misc
		"help": {"help", func() error { cmdhelp.DisplayHelp(db, *currentUser); return nil }},
		"info": {"info", func() error { cmdhelp.DisplayInfo(); return nil }},
		"exit": {"exit", func() error {
			log.Info("session end", slog.String("reason", "exit"))
			os.Exit(0)
			return nil
		}},
	}
	if e, ok := commandsMap[cmd]; !ok {
		log.Warn("command", slog.String("cmd", cmd), slog.String("event", "command"),
			slog.Any("args", args), slog.String("result", "unknown_command"))
		fmt.Printf("Unknown command: %s\n", cmd)
	} else if !hasPerm(e.Perm) {
		log.Warn("command", slog.String("cmd", cmd), slog.String("event", "command"),
			slog.Any("args", args), slog.String("result", "permission_denied"))
		fmt.Printf("Permission denied: %s\n", cmd)
	} else {
		err := e.Handler()
		if err != nil {
			log.Error("command", slog.String("cmd", cmd), slog.String("event", "command"),
				slog.Any("args", args), slog.String("result", "error"), slog.String("error", err.Error()))
		} else {
			log.Info("command", slog.String("cmd", cmd), slog.String("event", "command"),
				slog.Any("args", args), slog.String("result", "ok"))
		}
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
