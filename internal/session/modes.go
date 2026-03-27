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
	"time"

	"github.com/c-bata/go-prompt"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	"gorm.io/gorm"

	"goBastion/internal/commands/help"
	"goBastion/internal/commands/registry"
	cmdssh "goBastion/internal/commands/ssh"
	cmdtty "goBastion/internal/commands/tty"
	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/utils"
	"goBastion/internal/utils/autocomplete"
	"goBastion/internal/utils/system"
	"goBastion/internal/utils/totp"
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
		ip := system.ClientIPFromEnv()
		log.Warn("login rejected", slog.String("user", sysUser), slog.String("from", ip), slog.String("reason", "user not in database"))
		fmt.Printf("User '%s' is not registered in the bastion. Contact your admin to create your account.\n", sysUser)
		return
	}

	if !preConnectionCheck(db, currentUser, log) {
		return
	}

	if len(os.Args) == 1 {
		if !checkTOTP(db, &currentUser, log) {
			return
		}
		log.Info("session_start", slog.String("user", currentUser.Username), slog.String("event", "session_start"), slog.String("cmd", "interactive"))
		runInteractiveMode(db, &currentUser, log)
	} else {
		cmd := os.Args[1]
		args := os.Args[2:]
		if strings.TrimSpace(cmd) == "" {
			if !checkTOTP(db, &currentUser, log) {
				return
			}
			log.Info("session_start", slog.String("user", currentUser.Username), slog.String("event", "session_start"), slog.String("cmd", "interactive"))
			runInteractiveMode(db, &currentUser, log)
		} else {
			// Skip TOTP for raw TCP proxy (-W) and sftp-session: no TTY, raw pipe only.
			_, _, isTCPProxy := parseTCPProxyRequest(cmd, args)
			isSftpSession := strings.HasPrefix(cmd, "sftp-session")
			if !isTCPProxy && !isSftpSession {
				if !checkTOTP(db, &currentUser, log) {
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
			log.Warn("tcp_proxy_failed", slog.String("error", err.Error()))
			fmt.Fprintln(os.Stderr, "TCP proxy connection failed. Check the target host and your access rights.")
		}
	} else if strings.HasPrefix(command, "sftp-session") {
		target := strings.TrimPrefix(strings.TrimPrefix(command, "sftp-session "), "sftp-session")
		if err := cmdssh.SftpSession(db, *currentUser, *log, target); err != nil {
			log.Warn("sftp_session_failed", slog.String("error", err.Error()))
			fmt.Fprintln(os.Stderr, "SFTP session failed. Check the target host and your access rights.")
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

// executeCommand looks up and runs a command from the central registry, enforcing permission checks.
func executeCommand(db *gorm.DB, currentUser *models.User, log *slog.Logger, cmd string, args []string) {
	resetStdIn() // Mandatory: prevents the terminal from being left in a broken state.

	log = log.With(slog.String("user", currentUser.Username))
	hasPerm := func(perm string) bool {
		return currentUser.CanDo(db, perm, "")
	}

	adapter := osadapter.NewLinuxAdapter()
	cmds := registry.BuildRegistry(db, currentUser, log, adapter, args, func() {
		log.Info("session end", slog.String("reason", "exit"))
		os.Exit(0)
	})

	var found *registry.CommandSpec
	for i := range cmds {
		if cmds[i].Name == cmd {
			found = &cmds[i]
			break
		}
	}

	if found == nil {
		log.Warn("command", slog.String("cmd", cmd), slog.String("event", "command"),
			slog.Any("args", args), slog.String("result", "unknown_command"))
		fmt.Printf("Unknown command: %s\n", cmd)
		return
	}

	if found.Permission != "" && !hasPerm(found.Permission) {
		log.Warn("command", slog.String("cmd", cmd), slog.String("event", "command"),
			slog.Any("args", args), slog.String("result", "permission_denied"))
		fmt.Printf("Permission denied for '%s'. Contact your admin or type 'help' to see available commands.\n", cmd)
		return
	}

	// Special commands with custom inline logic
	switch cmd {
	case "help":
		help.DisplayHelpFromRegistry(cmds, db, *currentUser, hasPerm)
		return
	case "info":
		help.DisplayInfo()
		return
	case "exit":
		log.Info("session end", slog.String("reason", "exit"))
		os.Exit(0)
		return
	case "ttyPlay":
		err := cmdtty.TtyPlay(db, currentUser, args)
		resetStdIn()
		if err != nil {
			log.Error("command", slog.String("cmd", cmd), slog.String("event", "command"),
				slog.Any("args", args), slog.String("result", "error"), slog.String("error", err.Error()))
		} else {
			log.Info("command", slog.String("cmd", cmd), slog.String("event", "command"),
				slog.Any("args", args), slog.String("result", "ok"))
		}
		return
	}

	if found.Handler == nil {
		return
	}

	err := found.Handler()
	if err != nil {
		log.Error("command", slog.String("cmd", cmd), slog.String("event", "command"),
			slog.Any("args", args), slog.String("result", "error"), slog.String("error", err.Error()))
	} else {
		log.Info("command", slog.String("cmd", cmd), slog.String("event", "command"),
			slog.Any("args", args), slog.String("result", "ok"))
	}
}

// resetStdIn restores the terminal to canonical (cooked) mode.
func resetStdIn() {
	cmd := exec.Command("/bin/stty", "-raw", "echo")
	cmd.Stdin = os.Stdin
	_ = cmd.Run() // Run() already calls Wait() internally
}

// maxMFAAttempts is the maximum number of TOTP/backup code attempts allowed per login.
const maxMFAAttempts = 3

// checkMFA prompts for TOTP and/or password second factors if configured.
// Returns false if any check fails, which should cause the session to be terminated immediately.
func checkMFA(db *gorm.DB, user *models.User, log *slog.Logger) bool {
	ip := system.ClientIPFromEnv()

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
			fmt.Println("Contact your admin to reset your password (accountSetPassword --user " + user.Username + " --clear).")
			return false
		}
		log.Info("mfa_success", slog.String("event", "mfa_password"), slog.String("user", user.Username), slog.String("from", ip))
	} else {
		// Dummy bcrypt comparison to normalize timing regardless of whether
		// password MFA is configured, preventing timing side-channel disclosure.
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$10$abcdefghijklmnopqrstuuXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"), []byte("x"))
	}

	// TOTP check
	if !user.TOTPEnabled || user.TOTPSecret == "" {
		return true
	}
	log.Info("mfa_challenge", slog.String("event", "mfa_totp"), slog.String("user", user.Username), slog.String("from", ip))

	for attempt := 1; attempt <= maxMFAAttempts; attempt++ {
		fmt.Printf("🔐 Enter TOTP code (or backup code) [attempt %d/%d]: ", attempt, maxMFAAttempts)
		reader := bufio.NewReader(os.Stdin)
		code, err := reader.ReadString('\n')
		if err != nil {
			log.Warn("mfa_error", slog.String("event", "mfa_totp"), slog.String("user", user.Username), slog.String("from", ip), slog.String("error", err.Error()))
			fmt.Fprintln(os.Stderr, "\n⛔ Could not read code.")
			return false
		}
		code = strings.TrimSpace(code)

		// Try TOTP first
		if totp.Verify(user.TOTPSecret, code) {
			log.Info("mfa_success", slog.String("event", "mfa_totp"), slog.String("user", user.Username), slog.String("from", ip))
			return true
		}

		// Try backup code
		if user.BackupCodes != "" {
			matched, updatedJSON, err := totp.VerifyAndConsumeBackupCode(code, user.BackupCodes)
			if err != nil {
				log.Warn("mfa_error", slog.String("event", "mfa_backup_code"), slog.String("user", user.Username), slog.String("error", err.Error()))
			} else if matched {
				if dbErr := db.Model(user).Update("backup_codes", updatedJSON).Error; dbErr != nil {
					log.Error("mfa_backup_code_db_error", slog.String("user", user.Username), slog.String("error", dbErr.Error()))
					fmt.Println("⛔ Internal error saving backup code. Contact your admin.")
					return false
				}
				user.BackupCodes = updatedJSON
				remaining := totp.CountBackupCodes(updatedJSON)
				log.Info("mfa_success", slog.String("event", "mfa_backup_code"), slog.String("user", user.Username), slog.String("from", ip))
				fmt.Printf("✅ Backup code accepted. %d code(s) remaining.\n", remaining)
				return true
			}
		}

		if attempt < maxMFAAttempts {
			fmt.Println("⛔ Invalid code. Try again.")
			time.Sleep(time.Duration(attempt) * time.Second) // exponential backoff
		}
	}

	log.Warn("mfa_failure", slog.String("event", "mfa_totp"), slog.String("user", user.Username), slog.String("from", ip), slog.Int("attempts", maxMFAAttempts))
	fmt.Printf("⛔ Invalid TOTP or backup code. Access denied after %d attempts.\n", maxMFAAttempts)
	fmt.Println("If you lost access to your authenticator, contact your admin to disable TOTP (accountDisableTOTP --user " + user.Username + ").")
	return false
}

// checkTOTP is kept for backward compatibility; delegates to checkMFA.
func checkTOTP(db *gorm.DB, user *models.User, log *slog.Logger) bool {
	return checkMFA(db, user, log)
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
