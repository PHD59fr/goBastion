package app

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"goBastion/commands"
	"goBastion/models"
	"goBastion/utils"
	"goBastion/utils/autocomplete"
	"goBastion/utils/totp"

	"log/slog"

	"github.com/c-bata/go-prompt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"gorm.io/gorm"
)

// Run is the main entry point after DB init: it looks up the current user,
// runs the pre-connection checks, then dispatches to interactive or non-interactive mode.
func Run(db *gorm.DB, log *slog.Logger) {
	sysUser, err := currentSystemUser()
	if err != nil {
		log.Error("Error fetching current system user", slog.Any("error", err))
		return
	}

	var currentUser models.User
	if err = db.Where("username = ?", sysUser).First(&currentUser).Error; err != nil {
		ip := strings.Split(os.Getenv("SSH_CLIENT"), " ")[0]
		log.Warn("unknown user connection attempt", slog.String("user", sysUser), slog.String("ip", ip))
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
		log.Info("session start", slog.String("user", currentUser.Username), slog.String("mode", "interactive"))
		runInteractiveMode(db, &currentUser, log)
	} else {
		cmd := os.Args[1]
		args := os.Args[2:]
		if strings.TrimSpace(cmd) == "" {
			if !checkTOTP(&currentUser, log) {
				return
			}
			log.Info("session start", slog.String("user", currentUser.Username), slog.String("mode", "interactive"))
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
			log.Info("session start", slog.String("user", currentUser.Username), slog.String("mode", "command"), slog.String("cmd", cmd))
			runNonInteractiveMode(db, &currentUser, log, cmd, args)
			log.Info("session end", slog.String("user", currentUser.Username))
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
		if err := commands.TCPProxy(db, *currentUser, *log, host, port); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	} else if strings.HasPrefix(command, "sftp-session") {
		target := strings.TrimPrefix(strings.TrimPrefix(command, "sftp-session "), "sftp-session")
		if err := commands.SftpSession(db, *currentUser, *log, target); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	} else if isMoshServerRequest(command, args) {
		runMoshServer(command, args, log)
	} else {
		if err := commands.SSHConnect(db, *currentUser, *log, command); err != nil {
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
	log.Info("session end", slog.String("user", currentUser.Username), slog.String("reason", "disconnect"))
}

// executeCommand looks up and runs a command, enforcing permission checks.
func executeCommand(db *gorm.DB, currentUser *models.User, log *slog.Logger, cmd string, args []string) {
	resetStdIn() // Mandatory: prevents the terminal from being left in a broken state.

	// Attach user to all log records emitted during this command.
	log = log.With(slog.String("user", currentUser.Username))

	hasPerm := func(perm string) bool {
		return currentUser.CanDo(db, perm, "")
	}

	type entry struct {
		Perm    string
		Handler func()
	}

	commandsMap := map[string]entry{
		// Self
		"selfListIngressKeys": {"selfListIngressKeys", func() {
			if err := commands.SelfListIngressKeys(db, currentUser); err != nil {
				log.Error("selfListIngressKeys error", slog.String("error", err.Error()))
			}
		}},
		"selfAddIngressKey": {"selfAddIngressKey", func() {
			if err := commands.SelfAddIngressKey(db, currentUser, args); err != nil {
				log.Error("selfAddIngressKey error", slog.String("error", err.Error()))
			}
		}},
		"selfDelIngressKey": {"selfDelIngressKey", func() {
			if err := commands.SelfDelIngressKey(db, currentUser, args); err != nil {
				log.Error("selfDelIngressKey error", slog.String("error", err.Error()))
			}
		}},
		"selfGenerateEgressKey": {"selfGenerateEgressKey", func() {
			if err := commands.SelfGenerateEgressKey(db, currentUser, args); err != nil {
				log.Error("selfGenerateEgressKey error", slog.String("error", err.Error()))
			}
		}},
		"selfListEgressKeys": {"selfListEgressKeys", func() {
			if err := commands.SelfListEgressKeys(db, currentUser); err != nil {
				log.Error("selfListEgressKeys error", slog.String("error", err.Error()))
			}
		}},
		"selfListAccesses": {"selfListAccesses", func() {
			if err := commands.SelfListAccesses(db, currentUser); err != nil {
				log.Error("selfListAccesses error", slog.String("error", err.Error()))
			}
		}},
		"selfAddAccess": {"selfAddAccess", func() {
			if err := commands.SelfAddAccess(db, currentUser, args); err != nil {
				log.Error("selfAddAccess error", slog.String("error", err.Error()))
			}
		}},
		"selfDelAccess": {"selfDelAccess", func() {
			if err := commands.SelfDelAccess(db, currentUser, args); err != nil {
				log.Error("selfDelAccess error", slog.String("error", err.Error()))
			}
		}},
		"selfAddAlias": {"selfAddAlias", func() {
			if err := commands.SelfAddAlias(db, currentUser, args); err != nil {
				log.Error("selfAddAlias error", slog.String("error", err.Error()))
			}
		}},
		"selfDelAlias": {"selfDelAlias", func() {
			if err := commands.SelfDelAlias(db, currentUser, args); err != nil {
				log.Error("selfDelAlias error", slog.String("error", err.Error()))
			}
		}},
		"selfListAliases": {"selfListAliases", func() {
			if err := commands.SelfListAliases(db, currentUser); err != nil {
				log.Error("selfListAliases error", slog.String("error", err.Error()))
			}
		}},
		"selfRemoveHostFromKnownHosts": {"selfRemoveHostFromKnownHosts", func() {
			if err := commands.SelfRemoveHostFromKnownHosts(db, currentUser, args); err != nil {
				log.Error("selfRemoveHostFromKnownHosts error", slog.String("error", err.Error()))
			}
		}},
		"selfReplaceKnownHost": {"selfReplaceKnownHost", func() {
			if err := commands.SelfReplaceKnownHost(db, currentUser, args); err != nil {
				log.Error("selfReplaceKnownHost error", slog.String("error", err.Error()))
			}
		}},
		"selfSetupTOTP": {"selfSetupTOTP", func() {
			if err := commands.SelfSetupTOTP(db, currentUser); err != nil {
				log.Error("selfSetupTOTP error", slog.String("error", err.Error()))
			}
		}},
		"selfDisableTOTP": {"selfDisableTOTP", func() {
			if err := commands.SelfDisableTOTP(db, currentUser); err != nil {
				log.Error("selfDisableTOTP error", slog.String("error", err.Error()))
			}
		}},

		// Account
		"accountList": {"accountList", func() {
			if err := commands.AccountList(db, currentUser); err != nil {
				log.Error("accountList error", slog.String("error", err.Error()))
			}
		}},
		"accountInfo": {"accountInfo", func() {
			if err := commands.AccountInfo(db, currentUser, args); err != nil {
				log.Error("accountInfo error", slog.String("error", err.Error()))
			}
		}},
		"accountCreate": {"accountCreate", func() {
			if err := commands.AccountCreate(db, currentUser, args); err != nil {
				log.Error("accountCreate error", slog.String("error", err.Error()))
			}
		}},
		"accountListIngressKeys": {"accountListIngressKeys", func() {
			if err := commands.AccountListIngressKeys(db, currentUser, args); err != nil {
				log.Error("accountListIngressKeys error", slog.String("error", err.Error()))
			}
		}},
		"accountListEgressKeys": {"accountListEgressKeys", func() {
			if err := commands.AccountListEgressKeys(db, currentUser, args); err != nil {
				log.Error("accountListEgressKeys error", slog.String("error", err.Error()))
			}
		}},
		"accountModify": {"accountModify", func() {
			if err := commands.AccountModify(db, currentUser, args); err != nil {
				log.Error("accountModify error", slog.String("error", err.Error()))
			}
		}},
		"accountDelete": {"accountDelete", func() {
			if err := commands.AccountDelete(db, currentUser, args); err != nil {
				log.Error("accountDelete error", slog.String("error", err.Error()))
			}
		}},
		"accountAddAccess": {"accountAddAccess", func() {
			if err := commands.AccountAddAccess(db, currentUser, args); err != nil {
				log.Error("accountAddAccess error", slog.String("error", err.Error()))
			}
		}},
		"accountDelAccess": {"accountDelAccess", func() {
			if err := commands.AccountDelAccess(db, currentUser, args); err != nil {
				log.Error("accountDelAccess error", slog.String("error", err.Error()))
			}
		}},
		"accountListAccess": {"accountListAccess", func() {
			if err := commands.AccountListAccess(db, currentUser, args); err != nil {
				log.Error("accountListAccess error", slog.String("error", err.Error()))
			}
		}},
		"accountDisableTOTP": {"accountDisableTOTP", func() {
			if err := commands.AccountDisableTOTP(db, currentUser, args); err != nil {
				log.Error("accountDisableTOTP error", slog.String("error", err.Error()))
			}
		}},

		// PIV attestation (admin)
		"pivAddTrustAnchor": {"pivAddTrustAnchor", func() {
			if err := commands.PivAddTrustAnchor(db, currentUser, args); err != nil {
				log.Error("pivAddTrustAnchor error", slog.String("error", err.Error()))
			}
		}},
		"pivListTrustAnchors": {"pivListTrustAnchors", func() {
			if err := commands.PivListTrustAnchors(db, currentUser, args); err != nil {
				log.Error("pivListTrustAnchors error", slog.String("error", err.Error()))
			}
		}},
		"pivRemoveTrustAnchor": {"pivRemoveTrustAnchor", func() {
			if err := commands.PivRemoveTrustAnchor(db, currentUser, args); err != nil {
				log.Error("pivRemoveTrustAnchor error", slog.String("error", err.Error()))
			}
		}},

		// PIV attestation (self)
		"selfAddIngressKeyPIV": {"selfAddIngressKeyPIV", func() {
			if err := commands.SelfAddIngressKeyPIV(db, currentUser, args); err != nil {
				log.Error("selfAddIngressKeyPIV error", slog.String("error", err.Error()))
			}
		}},

		// Group
		"groupInfo": {"groupInfo", func() {
			if err := commands.GroupInfo(db, currentUser, args); err != nil {
				log.Error("groupInfo error", slog.String("error", err.Error()))
			}
		}},
		"groupList": {"groupList", func() {
			if err := commands.GroupList(db, currentUser, args); err != nil {
				log.Error("groupList error", slog.String("error", err.Error()))
			}
		}},
		"groupCreate": {"groupCreate", func() {
			if err := commands.GroupCreate(db, currentUser, args); err != nil {
				log.Error("groupCreate error", slog.String("error", err.Error()))
			}
		}},
		"groupDelete": {"groupDelete", func() {
			if err := commands.GroupDelete(db, currentUser, args); err != nil {
				log.Error("groupDelete error", slog.String("error", err.Error()))
			}
		}},
		"groupAddAccess": {"groupAddAccess", func() {
			if err := commands.GroupAddAccess(db, currentUser, args); err != nil {
				log.Error("groupAddAccess error", slog.String("error", err.Error()))
			}
		}},
		"groupDelAccess": {"groupDelAccess", func() {
			if err := commands.GroupDelAccess(db, currentUser, args); err != nil {
				log.Error("groupDelAccess error", slog.String("error", err.Error()))
			}
		}},
		"groupAddMember": {"groupAddMember", func() {
			if err := commands.GroupAddMember(db, currentUser, args); err != nil {
				log.Error("groupAddMember error", slog.String("error", err.Error()))
			}
		}},
		"groupDelMember": {"groupDelMember", func() {
			if err := commands.GroupDelMember(db, currentUser, args); err != nil {
				log.Error("groupDelMember error", slog.String("error", err.Error()))
			}
		}},
		"groupGenerateEgressKey": {"groupGenerateEgressKey", func() {
			if err := commands.GroupGenerateEgressKey(db, currentUser, args); err != nil {
				log.Error("groupGenerateEgressKey error", slog.String("error", err.Error()))
			}
		}},
		"groupListEgressKeys": {"groupListEgressKeys", func() {
			if err := commands.GroupListEgressKeys(db, currentUser, args); err != nil {
				log.Error("groupListEgressKeys error", slog.String("error", err.Error()))
			}
		}},
		"groupListAccesses": {"groupListAccesses", func() {
			if err := commands.GroupListAccesses(db, currentUser, args); err != nil {
				log.Error("groupListAccesses error", slog.String("error", err.Error()))
			}
		}},
		"groupAddAlias": {"groupAddAlias", func() {
			if err := commands.GroupAddAlias(db, currentUser, args); err != nil {
				log.Error("groupAddAlias error", slog.String("error", err.Error()))
			}
		}},
		"groupDelAlias": {"groupDelAlias", func() {
			if err := commands.GroupDelAlias(db, currentUser, args); err != nil {
				log.Error("groupDelAlias error", slog.String("error", err.Error()))
			}
		}},
		"groupListAliases": {"groupListAliases", func() {
			if err := commands.GroupListAliases(db, currentUser, args); err != nil {
				log.Error("groupListAliases error", slog.String("error", err.Error()))
			}
		}},
		"groupSetMFA": {"groupSetMFA", func() {
			if err := commands.GroupSetMFA(db, currentUser, args); err != nil {
				log.Error("groupSetMFA error", slog.String("error", err.Error()))
			}
		}},

		// Password MFA
		"selfSetPassword": {"selfSetPassword", func() {
			if err := commands.SelfSetPassword(db, currentUser, args); err != nil {
				log.Error("selfSetPassword error", slog.String("error", err.Error()))
			}
		}},
		"selfChangePassword": {"selfChangePassword", func() {
			if err := commands.SelfChangePassword(db, currentUser, args); err != nil {
				log.Error("selfChangePassword error", slog.String("error", err.Error()))
			}
		}},
		"accountSetPassword": {"accountSetPassword", func() {
			if err := commands.AccountSetPassword(db, currentUser, args); err != nil {
				log.Error("accountSetPassword error", slog.String("error", err.Error()))
			}
		}},

		// TTY
		"ttyList": {"ttyList", func() {
			if err := commands.TtyList(db, currentUser, args); err != nil {
				log.Error("ttyList error", slog.String("error", err.Error()))
			}
		}},
		"ttyPlay": {"ttyPlay", func() {
			if err := commands.TtyPlay(db, currentUser, args); err != nil {
				resetStdIn()
				log.Error("ttyPlay error", slog.String("error", err.Error()))
			}
		}},
		"whoHasAccessTo": {"whoHasAccessTo", func() {
			if err := commands.WhoHasAccessTo(db, currentUser, args); err != nil {
				log.Error("whoHasAccessTo error", slog.String("error", err.Error()))
			}
		}},

		// Misc
		"help":  {"help", func() { commands.DisplayHelp(db, *currentUser) }},
		"info":  {"info", func() { commands.DisplayInfo() }},
		"exit":  {"exit", func() {
			log.Info("session end", slog.String("reason", "exit"))
			os.Exit(0)
		}},
	}

	if e, ok := commandsMap[cmd]; !ok {
		log.Warn("unknown command", slog.String("cmd", cmd))
		fmt.Printf("Unknown command: %s\n", cmd)
	} else if !hasPerm(e.Perm) {
		log.Warn("permission denied", slog.String("cmd", cmd))
		fmt.Printf("Permission denied: %s\n", cmd)
	} else {
		log.Info("command", slog.String("cmd", cmd), slog.Any("args", args))
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
		log.Info("password mfa challenge", slog.String("user", user.Username), slog.String("ip", ip))
		fmt.Print("🔑 Enter password: ")
		pass, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			log.Warn("password mfa read error", slog.String("user", user.Username), slog.String("error", err.Error()))
			fmt.Fprintln(os.Stderr, "⛔ Could not read password.")
			return false
		}
		if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), pass) != nil {
			log.Warn("password mfa failure", slog.String("user", user.Username), slog.String("ip", ip))
			fmt.Println("⛔ Invalid password. Access denied.")
			return false
		}
		log.Info("password mfa success", slog.String("user", user.Username), slog.String("ip", ip))
	}

	// TOTP check
	if !user.TOTPEnabled || user.TOTPSecret == "" {
		return true
	}
	log.Info("totp challenge", slog.String("user", user.Username), slog.String("ip", ip))
	fmt.Print("🔐 Enter TOTP code: ")
	reader := bufio.NewReader(os.Stdin)
	code, err := reader.ReadString('\n')
	if err != nil {
		log.Warn("totp read error", slog.String("user", user.Username), slog.String("ip", ip), slog.String("error", err.Error()))
		fmt.Fprintln(os.Stderr, "\n⛔ Could not read TOTP code.")
		return false
	}
	if !totp.Verify(user.TOTPSecret, strings.TrimSpace(code)) {
		log.Warn("totp failure", slog.String("user", user.Username), slog.String("ip", ip))
		fmt.Println("⛔ Invalid TOTP code. Access denied.")
		return false
	}
	log.Info("totp success", slog.String("user", user.Username), slog.String("ip", ip))
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

	log.Info("mosh-server passthrough", slog.Any("args", cmdArgs))

	cmd := exec.Command("mosh-server", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Error("mosh-server error", slog.String("error", err.Error()))
	}
}
