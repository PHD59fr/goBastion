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
	"sync"
	"sync/atomic"
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
	"goBastion/internal/config"
	"goBastion/internal/models"
	"goBastion/internal/osadapter"
	"goBastion/internal/utils"
	"goBastion/internal/utils/autocomplete"
	"goBastion/internal/utils/dbConnector"
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

	// Maintenance mode: only administrators may connect.
	if cfg := config.Get(); cfg.Maintenance.Enabled && !currentUser.IsAdmin() {
		msg := cfg.Maintenance.Message
		if msg == "" {
			msg = "🚧 Bastion under maintenance: only administrators may connect."
		}
		fmt.Println(msg)
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
		if !config.Get().Interactive.Allow {
			fmt.Println("⛔ Interactive shell is disabled by configuration.")
			return
		}
		if config.Get().ForceOSHOnly.Enabled {
			fmt.Println("⛔ Interactive shell is disabled; use -osh commands only.")
			return
		}
		if !checkMFA(db, &currentUser, log) {
			return
		}
		releaseSession, err := registerActiveSession(db, &currentUser, sessionID, "interactive_shell")
		if err != nil {
			log.Warn("session_limit_reached", slog.String("user", currentUser.Username), slog.String("error", err.Error()))
			fmt.Println("⛔ Session denied: maximum concurrent sessions reached on this instance.")
			return
		}
		defer releaseSession()
		log.Info("session_start", slog.String("user", currentUser.Username), slog.String("cmd", "interactive"))
		runInteractiveMode(db, &currentUser, log, releaseSession)
	} else {
		cmd := os.Args[1]
		args := os.Args[2:]

		isInteractive := strings.TrimSpace(cmd) == "" || cmd == "--"

		if config.Get().ForceOSHOnly.Enabled && !isInteractive && !strings.HasPrefix(strings.TrimSpace(cmd), "-osh") {
			fmt.Println("⛔ Interactive shell is disabled; use -osh commands only.")
			return
		}
		if currentUser.OSHOnly && !isInteractive && !strings.HasPrefix(strings.TrimSpace(cmd), "-osh") {
			fmt.Println("⛔ This account is limited to -osh commands only.")
			return
		}
		if isInteractive {
			if !config.Get().Interactive.Allow {
				fmt.Println("⛔ Interactive shell is disabled by configuration.")
				return
			}
			if !checkMFA(db, &currentUser, log) {
				return
			}
			releaseSession, err := registerActiveSession(db, &currentUser, sessionID, "interactive_shell")
			if err != nil {
				log.Warn("session_limit_reached", slog.String("user", currentUser.Username), slog.String("error", err.Error()))
				fmt.Println("⛔ Session denied: maximum concurrent sessions reached on this instance.")
				return
			}
			defer releaseSession()
			log.Info("session_start", slog.String("user", currentUser.Username), slog.String("cmd", "interactive"))
			runInteractiveMode(db, &currentUser, log, releaseSession)
		} else {
			// sftp-session is handled separately. Raw TCP proxy (-W) cannot safely
			// carry an MFA prompt on its byte stream, so fail closed when account
			// MFA would otherwise be required.
			_, _, isTCPProxy := parseTCPProxyRequest(cmd, args)
			isSftpSession := strings.HasPrefix(cmd, "sftp-session")
			if isTCPProxy {
				if msg := tcpProxyMFABlockMessage(currentUser); msg != "" {
					fmt.Println(msg)
					return
				}
			} else if !isSftpSession {
				if !checkMFA(db, &currentUser, log) {
					return
				}
			}
			sessionKind := classifySessionKind(cmd, args)
			releaseSession, err := registerActiveSession(db, &currentUser, sessionID, sessionKind)
			if err != nil {
				log.Warn("session_limit_reached", slog.String("user", currentUser.Username), slog.String("kind", sessionKind), slog.String("error", err.Error()))
				fmt.Println("⛔ Session denied: maximum concurrent sessions reached on this instance.")
				return
			}
			defer releaseSession()
			log.Info("session_start", slog.String("user", currentUser.Username), slog.String("cmd", cmd))
			runNonInteractiveMode(db, &currentUser, log, cmd, args)
			log.Info("session_end", slog.String("user", currentUser.Username))
		}
	}
}

func tcpProxyMFABlockMessage(user models.User) string {
	switch {
	case user.PasswordHash != "":
		return "⛔ TCP proxy (-W) is unavailable when password MFA is enabled on your account."
	case user.TOTPEnabled && user.TOTPSecret != "":
		return "⛔ TCP proxy (-W) is unavailable when TOTP MFA is enabled on your account."
	case config.Get().RequireMFA.Enabled:
		return "⛔ TCP proxy (-W) is unavailable while global MFA enforcement is enabled."
	default:
		return ""
	}
}

func classifySessionKind(cmd string, args []string) string {
	if strings.HasPrefix(strings.TrimSpace(cmd), "-osh") || cmd == "-osh" {
		return "osh"
	}
	if _, ok := parseDBRequest(cmd, args); ok {
		return "db"
	}
	if strings.HasPrefix(cmd, "sftp-session") {
		return "sftp"
	}
	if _, _, ok := parseTCPProxyRequest(cmd, args); ok {
		return "tcp_proxy"
	}
	if isMoshServerRequest(cmd, args) {
		return "mosh"
	}
	return "ssh"
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
			runInteractiveMode(db, currentUser, log, nil)
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
		if !config.Get().SFTP.Enabled {
			fmt.Fprintln(os.Stderr, "⛔ SFTP transfers are disabled.")
			return
		}
		target := strings.TrimPrefix(strings.TrimPrefix(command, "sftp-session "), "sftp-session")
		if err := cmdssh.SFTPSession(db, *currentUser, *log, target); err != nil {
			log.Warn("sftp_session_failed", slog.String("error", err.Error()))
			fmt.Fprintln(os.Stderr, "SFTP session failed. Check the target host and your access rights.")
		}
	} else if isMoshServerRequest(command, args) {
		if !config.Get().Mosh.Enabled {
			fmt.Fprintln(os.Stderr, "⛔ Mosh is disabled.")
			return
		}
		if !config.MoshAvailable() {
			fmt.Fprintln(os.Stderr, "⛔ Mosh is not installed in this image. Use the full image variant.")
			return
		}
		runMoshServer(command, args, log)
	} else if dbArgs, ok := parseDBRequest(command, args); ok {
		if len(dbArgs) < 1 {
			fmt.Fprintln(os.Stderr, "⛔ Usage: bastion --db|-db [user@]host[:port[:protocol]] [--mysql|--pg|--redis] [--dbname name]")
			return
		}
		access, err := dbConnector.ResolveTarget(db, *currentUser, dbArgs[0], dbArgs[1:]...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "⛔ %v\n", err)
			return
		}
		if err := dbConnector.Connect(db, *currentUser, access); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	} else {
		if err := cmdssh.Connect(db, *currentUser, *log, command); err != nil {
			fmt.Println(err)
		}
	}
}

func parseDBRequest(cmd string, args []string) ([]string, bool) {
	if cmd == "--db" || cmd == "-db" {
		return args, true
	}
	for _, prefix := range []string{"--db ", "-db "} {
		if strings.HasPrefix(cmd, prefix) {
			return strings.Fields(strings.TrimSpace(strings.TrimPrefix(cmd, prefix))), true
		}
	}
	return nil, false
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
	readErr := make(chan error, 1)
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

	// Drain both channels. Pipes are closed so goroutines will finish and
	// send exactly one value each (either a string or an error). We always
	// iterate twice to avoid goroutine leaks and data loss.
	for i := 0; i < 2; i++ {
		select {
		case stdout = <-doneOut:
		case stderr = <-doneErr:
		case captureErr = <-readErr:
			// Save the error but continue draining the other channel.
		}
	}
	return stdout, stderr, runErr, captureErr
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
func runInteractiveMode(db *gorm.DB, currentUser *models.User, log *slog.Logger, forceRelease func()) {
	defer resetStdIn()
	fmt.Println(utils.FgBlueB("Type 'help' to display available commands, 'tab' to autocomplete, 'exit' to quit."))

	showCompletions := false

	// shouldExit is checked by go-prompt's ExitChecker on every keystroke.
	// When set, p.Run() returns cleanly (with terminal restored via tearDown).
	var shouldExit atomic.Bool

	// resetIdle is defined below; declared here so the completer closure can
	// reset the idle watchdog on every keystroke (not just on command run).
	var resetIdle func()

	wrappedCompleter := func(d prompt.Document) []prompt.Suggest {
		if resetIdle != nil {
			resetIdle()
		}
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

	// Navigation key bindings that also reset the idle timer.
	// CursorDown/CursorUp can panic when the suggestion list is displayed
	// because the extra suggestion rows make TranslateRowColToIndex go out
	// of range. We recover silently — during suggestion display the user
	// should use Tab/Shift-Tab to navigate, not arrow keys.
	safeMove := func(fn func(*prompt.Buffer)) func(*prompt.Buffer) {
		return func(buf *prompt.Buffer) {
			defer func() { _ = recover() }()
			resetIdle()
			fn(buf)
		}
	}
	navBindings := []prompt.KeyBind{
		{Key: prompt.Up, Fn: safeMove(func(buf *prompt.Buffer) { buf.CursorUp(1) })},
		{Key: prompt.Down, Fn: safeMove(func(buf *prompt.Buffer) { buf.CursorDown(1) })},
		{Key: prompt.Left, Fn: safeMove(func(buf *prompt.Buffer) { buf.CursorLeft(1) })},
		{Key: prompt.Right, Fn: safeMove(func(buf *prompt.Buffer) { buf.CursorRight(1) })},
		{Key: prompt.Home, Fn: safeMove(func(buf *prompt.Buffer) { buf.CursorLeft(1000) })},
		{Key: prompt.End, Fn: safeMove(func(buf *prompt.Buffer) { buf.CursorRight(1000) })},
		{Key: prompt.PageUp, Fn: safeMove(func(buf *prompt.Buffer) { buf.CursorUp(10) })},
		{Key: prompt.PageDown, Fn: safeMove(func(buf *prompt.Buffer) { buf.CursorDown(10) })},
	}

	promptSymbol := "$ "
	if currentUser.IsAdmin() {
		promptSymbol = "# "
	}

	bastionName, _ := os.Hostname()

	// Idle timeout watchdog: reset on each executed command; fires (and exits
	// the session) if no command runs within IdleTimeout. 0 = disabled.
	idleTimeout := time.Duration(config.Get().Session.IdleTimeout)
	var idleTimer *time.Timer
	var idleMu sync.Mutex
	stopIdle := func() {
		idleMu.Lock()
		defer idleMu.Unlock()
		if idleTimer != nil {
			idleTimer.Stop()
			idleTimer = nil
		}
	}
	resetIdle = func() {
		if idleTimeout <= 0 {
			return
		}
		idleMu.Lock()
		defer idleMu.Unlock()
		if idleTimer != nil {
			idleTimer.Stop()
		}
		idleTimer = time.AfterFunc(idleTimeout, func() {
			log.Info("session_end", slog.String("user", currentUser.Username), slog.String("reason", "idle_timeout"))
			// go-prompt reads /dev/tty directly — os.Stdin.Close() cannot stop it.
			// Restore terminal and force-exit.
			resetStdIn()
			fmt.Println("\n⛔ Session timed out due to inactivity.")
			if forceRelease != nil {
				forceRelease()
			}
			os.Exit(0)
		})
	}
	config.SetIdleResetFn(resetIdle)
	resetIdle()
	defer func() {
		idleMu.Lock()
		if idleTimer != nil {
			idleTimer.Stop()
		}
		idleMu.Unlock()
	}()

	opts := []prompt.Option{
		prompt.OptionPrefix(currentUser.Username + "@" + bastionName + ":" + promptSymbol),
		prompt.OptionPrefixTextColor(prompt.DarkGreen),
		prompt.OptionAddKeyBind(tabKeyBinding),
		prompt.OptionAddKeyBind(escKeyBinding),
	}
	for _, b := range navBindings {
		opts = append(opts, prompt.OptionAddKeyBind(b))
	}

	// ExitChecker is called on every keystroke via go-prompt's handleKeyBinding.
	// When it returns true, p.Run() exits cleanly with terminal restored.
	opts = append(opts, prompt.OptionSetExitCheckerOnInput(func(in string, breakline bool) bool {
		return shouldExit.Load()
	}))

	p := prompt.New(
		func(in string) {
			showCompletions = false
			tokens := strings.Fields(in)
			if len(tokens) == 0 {
				return
			}
			if tokens[0] == "ttyPlay" {
				stopIdle()
			}
			err := executeCommand(db, currentUser, log, tokens[0], tokens[1:])
			if errors.Is(err, errSessionExit) {
				shouldExit.Store(true)
				return
			}
			resetIdle()
		},
		wrappedCompleter,
		opts...,
	)
	p.Run()
	log.Info("session_end", slog.String("user", currentUser.Username), slog.String("reason", "disconnect"))
}

var (
	ErrUnknownCommand   = errors.New("unknown command")
	ErrPermissionDenied = errors.New("permission denied")
	// errSessionExit signals a normal session termination (exit command or idle timeout).
	// The caller should close stdin to make p.Run() return gracefully.
	errSessionExit = errors.New("session exit")
)

// featureEnabled reports whether the named feature toggle is on.
func featureEnabled(feat string, cfg *config.Config) bool {
	switch feat {
	case "self_ingress":
		return cfg.SelfIngress.Enabled
	case "egress_key":
		return cfg.EgressKey.Enabled
	case "known_hosts":
		return cfg.KnownHosts.Enabled
	case "alias_self":
		return cfg.AliasSelf.Enabled
	case "self_mfa":
		return cfg.SelfMFA.Enabled
	case "self_password":
		return cfg.SelfPassword.Enabled
	case "pivs":
		return cfg.PIV.Enabled
	case "backup_codes":
		return cfg.BackupCodes.Enabled
	case "realms":
		return cfg.Realms.Enabled
	case "guest_access":
		return cfg.GuestAccess.Enabled
	case "database":
		return cfg.Database.Enabled
	case "groups":
		return cfg.Groups.Enabled
	case "restricted_cmds":
		return cfg.RestrictedCmds.Enabled
	case "restricted_grants":
		return cfg.RestrictedGrants.Enabled
	case "tty_play":
		return cfg.TTYPlay.Enabled
	case "alias_group":
		return cfg.AliasGroup.Enabled
	case "mosh":
		return cfg.Mosh.Enabled && config.MoshAvailable()
	}
	return true
}

// featureLabel returns a human-readable (English) label for a feature toggle.
func featureLabel(feat string) string {
	switch feat {
	case "self_ingress":
		return "Self ingress keys"
	case "egress_key":
		return "Egress key generation"
	case "known_hosts":
		return "Known-hosts self-management"
	case "alias_self":
		return "Personal aliases"
	case "self_mfa":
		return "TOTP self-setup"
	case "self_password":
		return "Password MFA self-management"
	case "pivs":
		return "PIV"
	case "backup_codes":
		return "Backup codes"
	case "realms":
		return "Realms"
	case "guest_access":
		return "Guest access"
	case "database":
		return "Database access"
	case "groups":
		return "Groups"
	case "restricted_cmds":
		return "Restricted commands"
	case "restricted_grants":
		return "Restricted command grants"
	case "tty_play":
		return "TTY replay"
	case "alias_group":
		return "Group aliases"
	}
	return feat
}

// featureDenied returns a non-empty English denial message if the command is
// blocked by a disabled feature flag or by global read-only mode.
func featureDenied(found *registry.CommandSpec, user *models.User) string {
	cfg := config.Get()
	for _, feat := range found.Features {
		if !featureEnabled(feat, cfg) {
			return fmt.Sprintf("⛔ %s is disabled.", featureLabel(feat))
		}
	}
	if cfg.Readonly.Enabled && !user.IsAdmin() && found.Mutating {
		if cfg.Readonly.Message != "" {
			return cfg.Readonly.Message
		}
		return "🔒 Read-only mode: modifications are disabled."
	}
	return ""
}

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

	// Feature-flag gate: disabled features (and global read-only mode) deny
	// their commands before any handler runs.
	if msg := featureDenied(found, currentUser); msg != "" {
		log.Warn("command", slog.String("cmd", cmd),
			slog.Any("args", args), slog.String("result", "feature_disabled"))
		fmt.Println(msg)
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
		return errSessionExit
	case "ttyPlay":
		err := cmdtty.Play(db, currentUser, args)
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
	if err := cmd.Run(); err != nil {
		slog.Warn("stty_restore_failed", slog.Any("error", err))
	}
}

// maxMFAAttempts is the maximum number of TOTP/backup code attempts allowed per login.
// Value is read from configuration.

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
		// Global MFA enforcement: if required, a missing TOTP secret is fatal.
		if config.Get().RequireMFA.Enabled {
			fmt.Println("⛔ MFA (TOTP) is required. Run selfSetupTOTP to enable it before connecting.")
			return false
		}
		return true
	}
	log.Info("mfa_challenge", slog.String("event", "mfa_totp"), slog.String("user", user.Username), slog.String("from", ip))

	for attempt := 1; attempt <= config.Get().MFA.MaxAttempts; attempt++ {
		fmt.Printf("🔐 Enter TOTP code (or backup code) [attempt %d/%d]: ", attempt, config.Get().MFA.MaxAttempts)
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

		if attempt < config.Get().MFA.MaxAttempts {
			fmt.Println("⛔ Invalid code. Try again.")
			time.Sleep(time.Duration(attempt) * time.Duration(config.Get().MFA.BackoffBase)) // linear backoff
		}
	}

	log.Warn("mfa_failure", slog.String("event", "mfa_totp"), slog.String("user", user.Username), slog.String("from", ip), slog.Int("attempts", config.Get().MFA.MaxAttempts))
	fmt.Printf("⛔ Invalid TOTP or backup code. Access denied after %d attempts.\n", config.Get().MFA.MaxAttempts)
	fmt.Println("If you lost access to your authenticator, contact your admin to disable TOTP (accountDisableTOTP --user " + user.Username + ").")
	return false
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

// allowedMoshFlags is the set of flags that mosh-server is permitted to receive.
// Any other flag is rejected to prevent argument injection.
var allowedMoshFlags = map[string]bool{
	"-s": true,
	"-c": true,
	"-":  true,
}

// runMoshServer exec's mosh-server directly, passing through validated arguments.
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

	// Validate arguments to prevent injection of unexpected flags.
	// Only known-safe flags (-s, -c, -) and positional arguments (host, port) are allowed.
	for i, arg := range cmdArgs {
		if arg == "--" {
			// End-of-options marker; everything after this is positional and safe.
			break
		}
		if strings.HasPrefix(arg, "-") && !allowedMoshFlags[arg] {
			log.Error("mosh_server_rejected",
				slog.String("reason", "unexpected flag"),
				slog.String("flag", arg),
			)
			fmt.Fprintf(os.Stderr, "mosh-server: rejected unsafe argument %q\n", arg)
			return
		}
		// Skip the value that follows a flag that expects an argument.
		if allowedMoshFlags[arg] && arg != "-" && i+1 < len(cmdArgs) {
			// Skip the next token (value for this flag).
			continue
		}
	}

	log.Info("mosh_server")

	cmd := exec.Command("mosh-server", cmdArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Error("mosh_server", slog.String("error", err.Error()))
	}
}
