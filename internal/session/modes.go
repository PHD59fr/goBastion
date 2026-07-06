package session

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"time"

	"github.com/c-bata/go-prompt"
	"github.com/google/uuid"
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
	sessionID := uuid.NewString()
	log = log.With(slog.String("session_id", sessionID))
	_ = os.Setenv("GOB_SESSION_ID", sessionID)

	sysUser, err := currentSystemUser()
	if err != nil {
		log.Error("system_user_lookup_failed", slog.String("error", err.Error()))
		return
	}

	var currentUser models.User
	if err = db.Where("username = ?", sysUser).First(&currentUser).Error; err != nil {
		ip := system.ClientIPFromEnv()
		log.Warn("login_rejected", slog.String("user", sysUser), slog.String("from", ip), slog.String("reason", "user not in database"))
		fmt.Printf("User '%s' is not registered in the bastion. Contact your admin to create your account.\n", sysUser)
		return
	}

	if !preConnectionCheck(db, currentUser, log) {
		return
	}

	if len(os.Args) == 1 {
		if currentUser.OSHOnly {
			fmt.Println("⛔ This account is limited to -osh commands only. Interactive mode is disabled.")
			return
		}
		if !checkTOTP(db, &currentUser, log) {
			return
		}
		log.Info("session_start", slog.String("user", currentUser.Username), slog.String("cmd", "interactive"))
		runInteractiveMode(db, &currentUser, log)
	} else {
		cmd := os.Args[1]
		args := os.Args[2:]
		if currentUser.OSHOnly && !strings.HasPrefix(strings.TrimSpace(cmd), "-osh") {
			fmt.Println("⛔ This account is limited to -osh commands only.")
			return
		}
		if strings.TrimSpace(cmd) == "" {
			if !checkTOTP(db, &currentUser, log) {
				return
			}
			log.Info("session_start", slog.String("user", currentUser.Username), slog.String("cmd", "interactive"))
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
			log.Info("session_start", slog.String("user", currentUser.Username), slog.String("cmd", cmd))
			runNonInteractiveMode(db, &currentUser, log, cmd, args)
			log.Info("session_end", slog.String("user", currentUser.Username))
		}
	}
}

// runNonInteractiveMode executes a single bastion command passed via -osh flag.
func runNonInteractiveMode(db *gorm.DB, currentUser *models.User, log *slog.Logger, command string, args []string) {
	if currentUser.OSHOnly && !strings.HasPrefix(strings.TrimSpace(command), "-osh") {
		fmt.Println("⛔ This account is limited to -osh commands only.")
		return
	}

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
		executeCommandJSONAware(db, currentUser, log, command, args)
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

type oshJSONMode string

const (
	oshJSONDisabled  oshJSONMode = ""
	oshJSONCompact   oshJSONMode = "json"
	oshJSONPretty    oshJSONMode = "json-pretty"
	oshJSONGreppable oshJSONMode = "json-greppable"
)

func parseOshJSONMode(args []string) (oshJSONMode, []string) {
	filtered := make([]string, 0, len(args))
	mode := oshJSONDisabled
	for _, a := range args {
		switch a {
		case "--json":
			mode = oshJSONCompact
		case "--json-pretty":
			mode = oshJSONPretty
		case "--json-greppable":
			mode = oshJSONGreppable
		default:
			filtered = append(filtered, a)
		}
	}
	return mode, filtered
}

func executeCommandJSONAware(db *gorm.DB, currentUser *models.User, log *slog.Logger, cmd string, args []string) {
	mode, filteredArgs := parseOshJSONMode(args)
	if mode == oshJSONDisabled {
		_ = executeCommand(db, currentUser, log, cmd, filteredArgs)
		return
	}

	stdout, stderr, runErr, err := captureOutput(func() error {
		return executeCommand(db, currentUser, log, cmd, filteredArgs)
	})
	if err != nil {
		log.Error("json_api_capture_failed", slog.String("cmd", cmd), slog.String("error", err.Error()))
		_ = executeCommand(db, currentUser, log, cmd, filteredArgs)
		return
	}

	errorCode := "OK"
	errorMessage := "OK"
	if runErr != nil {
		switch {
		case errors.Is(runErr, ErrUnknownCommand):
			errorCode = "KO_UNKNOWN_COMMAND"
		case errors.Is(runErr, ErrPermissionDenied):
			errorCode = "KO_PERMISSION_DENIED"
		default:
			errorCode = "ERR_COMMAND"
		}
		errorMessage = runErr.Error()
	}

	payload := map[string]any{
		"command":       cmd,
		"error_code":    errorCode,
		"error_message": errorMessage,
		"value": map[string]any{
			"stdout": strings.TrimSpace(stdout),
			"stderr": strings.TrimSpace(stderr),
		},
	}
	emitJSONPayload(mode, payload)
}

func captureOutput(run func() error) (stdout string, stderr string, runErr error, captureErr error) {
	origStdout := os.Stdout
	origStderr := os.Stderr

	r, w, err := os.Pipe()
	if err != nil {
		return "", "", nil, err
	}
	rErr, wErr, err := os.Pipe()
	if err != nil {
		_ = r.Close()
		_ = w.Close()
		return "", "", nil, err
	}

	os.Stdout = w
	os.Stderr = wErr
	doneOut := make(chan string, 1)
	doneErr := make(chan string, 1)
	readErr := make(chan error, 2)
	go func() {
		var buf bytes.Buffer
		_, cErr := io.Copy(&buf, r)
		if cErr != nil {
			readErr <- cErr
			return
		}
		doneOut <- buf.String()
	}()
	go func() {
		var buf bytes.Buffer
		_, cErr := io.Copy(&buf, rErr)
		if cErr != nil {
			readErr <- cErr
			return
		}
		doneErr <- buf.String()
	}()

	runErr = run()

	_ = w.Close()
	_ = wErr.Close()
	os.Stdout = origStdout
	os.Stderr = origStderr
	_ = r.Close()
	_ = rErr.Close()

	var out, errOut string
	for i := 0; i < 2; i++ {
		select {
		case out = <-doneOut:
		case errOut = <-doneErr:
		case err = <-readErr:
			return "", "", runErr, err
		}
	}
	return out, errOut, runErr, nil
}

func emitJSONPayload(mode oshJSONMode, payload map[string]any) {
	var (
		data []byte
		err  error
	)
	if mode == oshJSONPretty {
		data, err = json.MarshalIndent(payload, "", "  ")
	} else {
		data, err = json.Marshal(payload)
	}
	if err != nil {
		fmt.Println("JSON_OUTPUT={\"error_code\":\"ERR_JSON\",\"error_message\":\"failed to encode json\",\"value\":null}")
		return
	}

	switch mode {
	case oshJSONGreppable:
		fmt.Printf("JSON_OUTPUT=%s\n", string(data))
	default:
		fmt.Println("JSON_START")
		fmt.Println(string(data))
		fmt.Println("JSON_END")
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
	log.Info("session_end", slog.String("user", currentUser.Username), slog.String("reason", "disconnect"))
}

var (
	ErrUnknownCommand   = errors.New("unknown command")
	ErrPermissionDenied = errors.New("permission denied")
)

// executeCommand looks up and runs a command from the central registry, enforcing permission checks.
func executeCommand(db *gorm.DB, currentUser *models.User, log *slog.Logger, cmd string, args []string) error {
	resetStdIn() // Mandatory: prevents the terminal from being left in a broken state.

	log = log.With(slog.String("user", currentUser.Username))
	hasPerm := func(perm string) bool {
		return currentUser.CanDo(db, perm, "")
	}

	adapter := osadapter.NewLinuxAdapter()
	cmds := registry.BuildRegistry(db, currentUser, log, adapter, args, func() {
		log.Info("session_end", slog.String("reason", "exit"))
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
		log.Warn("command", slog.String("cmd", cmd),
			slog.Any("args", args), slog.String("result", "unknown_command"))
		fmt.Printf("Unknown command: %s\n", cmd)
		return fmt.Errorf("%w: %s", ErrUnknownCommand, cmd)
	}

	if found.Permission != "" && !hasPerm(found.Permission) {
		log.Warn("command", slog.String("cmd", cmd),
			slog.Any("args", args), slog.String("result", "permission_denied"))
		fmt.Printf("Permission denied for '%s'. Contact your admin or type 'help' to see available commands.\n", cmd)
		return fmt.Errorf("%w: %s", ErrPermissionDenied, cmd)
	}

	// Special commands with custom inline logic
	switch cmd {
	case "help":
		help.DisplayHelpFromRegistry(cmds, db, *currentUser, hasPerm)
		return nil
	case "info":
		help.DisplayInfo()
		return nil
	case "exit":
		log.Info("session_end", slog.String("reason", "exit"))
		os.Exit(0)
		return nil
	case "ttyPlay":
		err := cmdtty.TtyPlay(db, currentUser, args)
		resetStdIn()
		if err != nil {
			log.Error("command_failed", slog.String("cmd", cmd),
				slog.Any("args", args), slog.String("result", "error"), slog.String("error", err.Error()))
		} else {
			log.Info("command", slog.String("cmd", cmd),
				slog.Any("args", args), slog.String("result", "ok"))
		}
		return err
	}

	if found.Handler == nil {
		return nil
	}

	err := found.Handler()
	if err != nil {
		log.Error("command_failed", slog.String("cmd", cmd),
			slog.Any("args", args), slog.String("result", "error"), slog.String("error", err.Error()))
		return err
	} else {
		log.Info("command", slog.String("cmd", cmd),
			slog.Any("args", args), slog.String("result", "ok"))
	}
	return nil
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

	log.Info("mosh_server")

	cmd := exec.Command("mosh-server", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Error("mosh_server", slog.String("error", err.Error()))
	}
}
