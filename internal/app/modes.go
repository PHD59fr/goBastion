package app

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"

	"goBastion/commands"
	"goBastion/models"
	"goBastion/utils"
	"goBastion/utils/autocomplete"

	"log/slog"

	"github.com/c-bata/go-prompt"
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
		log.Info("session start", slog.String("user", currentUser.Username), slog.String("mode", "interactive"))
		runInteractiveMode(db, &currentUser, log)
	} else {
		cmd := os.Args[1]
		args := os.Args[2:]
		if strings.TrimSpace(cmd) == "" {
			log.Info("session start", slog.String("user", currentUser.Username), slog.String("mode", "interactive"))
			runInteractiveMode(db, &currentUser, log)
		} else {
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
	} else {
		log.Info("ssh tunnel", slog.String("user", currentUser.Username), slog.String("target", command))
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
			if err := commands.SelfRemoveHostFromKnownHosts(args); err != nil {
				log.Error("selfRemoveHostFromKnownHosts error", slog.String("error", err.Error()))
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

// currentSystemUser returns the username of the current OS process owner.
func currentSystemUser() (string, error) {
	u, err := user.Current()
	if err != nil {
		return "", err
	}
	return u.Username, nil
}
