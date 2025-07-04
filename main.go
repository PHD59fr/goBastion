package main

import (
	"bufio"
	"flag"
	"fmt"
	"goBastion/utils/sshHostKey"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"goBastion/commands"
	"goBastion/models"
	"goBastion/utils"
	"goBastion/utils/autocomplete"
	"goBastion/utils/logger"
	"goBastion/utils/sync"

	"log/slog"

	"github.com/c-bata/go-prompt"
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	gormLogger "gorm.io/gorm/logger"
)

func isSSHConnection() bool {
	envVars := []string{"SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY"}
	for _, env := range envVars {
		if _, exists := os.LookupEnv(env); exists {
			return true
		}
	}
	return false
}

func createFirstAdminUser(db *gorm.DB) error {
	var userCount int64
	if err := db.Model(&models.User{}).Where("system_user = ?", false).Count(&userCount).Error; err != nil {
		return fmt.Errorf("error counting users: %w", err)
	}

	if userCount == 0 {
		if err := sync.CreateSystemUsersFromSystemToDb(db); err != nil {
			return fmt.Errorf("error syncing users from system: %w", err)
		}

		fmt.Println("No users found in the database.")
		fmt.Println("Let's create an initial administrator account.")

		reader := bufio.NewReader(os.Stdin)

		fmt.Print("Enter username: ")
		username, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("error reading username: %w", err)
		}
		username = strings.TrimSpace(username)

		fmt.Print("Enter the complete public SSH key: ")
		pubKey, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("error reading public key: %w", err)
		}
		pubKey = strings.TrimSpace(pubKey)

		if username == "" || pubKey == "" {
			return fmt.Errorf("username and public key cannot be empty")
		}

		if err := commands.CreateUser(db, username, pubKey); err != nil {
			return fmt.Errorf("error creating user: %w", err)
		}

		if err := commands.SwitchSysRoleUser(db, username); err != nil {
			return fmt.Errorf("error switching system role: %w", err)
		}

		fmt.Printf("User %s created successfully.\n", username)
	} else {
		fmt.Println("You cannot use this command because there are already users in the database.")
	}

	return nil
}

func main() {
	log, err := logger.NewLogger()
	if err != nil {
		fmt.Println("Error initializing logger:", err)
		return
	}

	dbDir := "/var/lib/goBastion"
	if err := os.MkdirAll(dbDir, 0777); err != nil {
		log.Error("Failed to create DB directory",
			slog.String("directory", dbDir),
			slog.Any("error", err),
		)
	}

	dbPath := filepath.Join(dbDir, "bastion.db")
	dsn := "file:" + dbPath + "?cache=shared&mode=rwc"

	gormLoggerConfig := gormLogger.Config{
		SlowThreshold: time.Second,
		LogLevel:      gormLogger.Silent,
		Colorful:      true,
	}
	dbLogger := gormLogger.New(logger.NewGormLogger(log), gormLoggerConfig)

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: dbLogger,
	})
	if err != nil {
		log.Error("Failed to connect to database",
			slog.Any("error", err),
		)
		return
	}

	err = db.AutoMigrate(
		&models.User{},
		&models.Group{},
		&models.UserGroup{},
		&models.IngressKey{},
		&models.SelfEgressKey{},
		&models.GroupEgressKey{},
		&models.SelfAccess{},
		&models.GroupAccess{},
		&models.Aliases{},
		&models.SshHostKey{},
		&models.KnownHostsEntry{},
	)
	if err != nil {
		log.Error("Failed to auto-migrate models",
			slog.Any("error", err),
		)
		return
	}

	db.Exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS unique_user_entry 
    ON known_hosts_entries(user_id, entry) 
    WHERE deleted_at IS NULL;
`)

	sqlDB, err := db.DB()
	if err != nil {
		log.Error("Failed to get generic database object",
			slog.Any("error", err),
		)
		return
	}
	sqlDB.SetMaxOpenConns(2)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(5 * time.Minute)

	db.Exec("PRAGMA journal_mode=WAL;")
	db.Exec("PRAGMA synchronous=NORMAL;")
	db.Exec("PRAGMA cache_size=-2000;")
	db.Exec("PRAGMA busy_timeout=20000;")

	sysUser, err := user.Current()
	if err != nil {
		log.Error("Error fetching current system user",
			slog.Any("error", err),
		)
	}
	currentUsername := sysUser.Username

	if !isSSHConnection() && currentUsername == "root" {
		restoreFlag := flag.Bool("restore", false, "Import users, ssh host keys, from db")
		regenerateSSHHostKeysFlag := flag.Bool("regenerateSSHHostKeys", false, "Force regenerate SSH host keys")
		firstInstallFlag := flag.Bool("firstInstall", false, "First install")

		flag.Parse()
		if *restoreFlag {
			if err = sync.RestoreBastionSSHHostKeys(db); err != nil {
				log.Error("Error restoring ssh host keys",
					slog.Any("error", err),
				)
				return
			}

			if err = sync.CreateSystemUsersFromSystemToDb(db); err != nil {
				log.Error("Error syncing users from system",
					slog.Any("error", err),
				)
				return
			}

			if err = sync.CreateUsersFromDB(db, *log); err != nil {
				log.Error("Error restoring from db",
					slog.Any("error", err),
				)
				return
			}
			return
		}

		if *regenerateSSHHostKeysFlag {
			if err = sshHostKey.GenerateSSHHostKeys(db, true); err != nil {
				log.Error("Error regenerating ssh host keys",
					slog.Any("error", err),
				)
				return
			}
			return
		}

		if *firstInstallFlag {
			if err = createFirstAdminUser(db); err != nil {
				log.Error("Error creating first user",
					slog.Any("error", err),
				)
			}
			return
		}
	}

	var currentUser models.User
	result := db.Where("username = ?", currentUsername).First(&currentUser)
	if result.Error != nil {
		fmt.Printf("User %s not found in database. Exiting application.\n", currentUsername)
		return
	}

	if !preConnectionCheck(db, currentUser, log) {
		return
	}

	if len(os.Args) == 1 {
		runInteractiveMode(db, &currentUser, log)
	} else {
		cmd := os.Args[1]
		args := os.Args[2:]
		if strings.TrimSpace(cmd) == "" {
			runInteractiveMode(db, &currentUser, log)
		} else {
			runNonInteractiveMode(db, &currentUser, log, cmd, args)
		}
	}
}

func preConnectionCheck(db *gorm.DB, currentUser models.User, log *slog.Logger) bool {
	if os.Getuid() == 0 {
		fmt.Println("You cannot run this program as root.")
		os.Exit(1)
	}
	splash := "*------------------------------------------------------------------------------*\n|THIS IS A PRIVATE COMPUTER SYSTEM, UNAUTHORIZED ACCESS IS STRICTLY PROHIBITED.|\n|ALL CONNECTIONS ARE LOGGED. IF YOU ARE NOT AUTHORIZED, DISCONNECT NOW.        |\n*------------------------------------------------------------------------------*\n"
	fmt.Print(splash)

	title := "            \t .,,.      .,,.\n            \t | '|,,,,,,| '|\n            \t |' | '__  |' |\n┌────────────────|__._/##\\_.__|─────────────────┐\n│             ____            _   _             │\n│  __ _  ___ | __ )  __ _ ___| |_(_) ___  _ __  │\n│ / _` |/ _ \\|  _ \\ / _` / __| __| |/ _ \\| '_ \\ │\n│| (_| | (_) | |_) | (_| \\__ \\ |_| | (_) | | | |│\n│ \\__, |\\___/|____/ \\__,_|___/\\__|_|\\___/|_| |_|│\n│ |___/                                         │\n└───────────────────────────────────────────────┘"
	fmt.Println(utils.FgYellow(title))

	if currentUser.SystemUser {
		fmt.Printf("User %s is a system user. System users are not allowed to use goBastion.\n", currentUser.Username)
		return false
	}

	if !currentUser.IsEnabled() {
		fmt.Println(utils.FgRedB("Your account is disabled, please contact your administrator."))
		return false
	}

	introMsg := ""

	if !currentUser.LastLoginAt.IsZero() {
		introMsg += "Your last login: " + currentUser.LastLoginAt.Format("Mon Jan 2 15:04:05 2006")
	}

	if currentUser.LastLoginFrom != "" {
		if introMsg == "" {
			introMsg = "Your last login: from " + currentUser.LastLoginFrom
		} else {
			introMsg += " from " + currentUser.LastLoginFrom
		}
	}

	fmt.Print(utils.FgGreenB("▶") + " Welcome to goBastion !\n")
	fmt.Println(introMsg)

	currentUser.LastLoginAt = time.Now()
	currentUser.LastLoginFrom = strings.Split(os.Getenv("SSH_CLIENT"), " ")[0]
	db.Save(&currentUser)

	return true
}

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
		if err := commands.SSHConnect(db, *currentUser, *log, command); err != nil {
			fmt.Println(err)
		}
	}
}

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

	p := prompt.New(func(in string) {
		showCompletions = false
		tokens := strings.Fields(in)
		if len(tokens) == 0 {
			return
		}
		cmd := tokens[0]
		args := tokens[1:]
		executeCommand(db, currentUser, log, cmd, args)
	}, wrappedCompleter,
		prompt.OptionPrefix(currentUser.Username+"@"+bastionName+":"+promptSymbol),
		prompt.OptionPrefixTextColor(prompt.DarkGreen),
		prompt.OptionAddKeyBind(tabKeyBinding),
		prompt.OptionAddKeyBind(escKeyBinding),
	)
	p.Run()
}

func executeCommand(db *gorm.DB, currentUser *models.User, log *slog.Logger, cmd string, args []string) {
	resetStdIn() // Mandatory! Otherwise, the terminal may be left in an unusable state.

	hasPerm := func(perm string) bool {
		return currentUser.CanDo(db, perm, "")
	}

	commandsMap := map[string]struct {
		Perm    string
		Handler func()
	}{
		// Self-commands
		"selfListIngressKeys": {"selfListIngressKeys", func() { commands.SelfListIngressKeys(db, currentUser) }},
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

		// Account commands
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

		// Group commands
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
				resetStdIn() // Due to the nature of ttyPlay, we need to reset stdin to avoid terminal issues.
				log.Error("ttyPlay error", slog.String("error", err.Error()))
			}
		}},
		"whoHasAccessTo": {"whoHasAccessTo", func() {
			if err := commands.WhoHasAccessTo(db, currentUser, args); err != nil {
				log.Error("whoHasAccessTo error", slog.String("error", err.Error()))
			}
		}},

		// Misc
		"help": {"help", func() { commands.DisplayHelp(db, *currentUser) }},
		"info": {"info", func() { commands.DisplayInfo() }},
		"exit": {"exit", func() { os.Exit(0) }},
	}
	if entry, ok := commandsMap[cmd]; !ok || !hasPerm(entry.Perm) {
		fmt.Printf("Unknown or unauthorized command: %s\n", cmd)
	} else {
		entry.Handler()
	}
}

func resetStdIn() {
	cmd := exec.Command("/bin/stty", "-raw", "echo")
	cmd.Stdin = os.Stdin
	_ = cmd.Run()
	_ = cmd.Wait()
}
