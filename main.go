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

		if err := commands.SwitchRoleUser(db, username); err != nil {
			return fmt.Errorf("error switching role: %w", err)
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
			return autocomplete.Completion(d, currentUser)
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
	switch cmd {
	// Self commands
	case "selfListIngressKeys":
		commands.SelfListIngressKeys(db, currentUser)
	case "selfAddIngressKey":
		if err := commands.SelfAddIngressKey(db, currentUser, args); err != nil {
			log.Error("selfAddIngressKey error", slog.String("error", err.Error()))
		}
	case "selfDelIngressKey":
		if err := commands.SelfDelIngressKey(db, currentUser, args); err != nil {
			log.Error("selfDelIngressKey error", slog.String("error", err.Error()))
		}
	case "selfGenerateEgressKey":
		if err := commands.SelfGenerateEgressKey(db, currentUser, args); err != nil {
			log.Error("selfGenerateEgressKey error", slog.String("error", err.Error()))
		}
	case "selfListEgressKeys":
		if err := commands.SelfListEgressKeys(db, currentUser); err != nil {
			log.Error("selfListEgressKeys error", slog.String("error", err.Error()))
		}
	case "selfListAccesses":
		if err := commands.SelfListAccesses(db, currentUser); err != nil {
			log.Error("selfListAccesses error", slog.String("error", err.Error()))
		}
	case "selfAddAccess":
		if err := commands.SelfAddAccess(db, currentUser, args); err != nil {
			log.Error("selfAddAccess error", slog.String("error", err.Error()))
		}
	case "selfDelAccess":
		if err := commands.SelfDelAccess(db, currentUser, args); err != nil {
			log.Error("selfDelAccess error", slog.String("error", err.Error()))
		}
	case "selfAddAlias":
		if err := commands.SelfAddAlias(db, currentUser, args); err != nil {
			log.Error("selfAddAlias error", slog.String("error", err.Error()))
		}
	case "selfDelAlias":
		if err := commands.SelfDelAlias(db, currentUser, args); err != nil {
			log.Error("selfDelAlias error", slog.String("error", err.Error()))
		}
	case "selfListAliases":
		if err := commands.SelfListAliases(db, currentUser); err != nil {
			log.Error("selfListAliases error", slog.String("error", err.Error()))
		}
	// Account commands
	case "accountList":
		commands.AccountList(db, currentUser)
	case "accountInfo":
		commands.AccountInfo(db, currentUser, args)
	case "accountCreate":
		if err := commands.AccountCreate(db, currentUser, args); err != nil {
			log.Error("accountCreate error", slog.String("error", err.Error()))
		}
	case "accountListIngressKeys":
		if err := commands.AccountListIngressKeys(db, currentUser, args); err != nil {
			log.Error("accountListIngressKeys error", slog.String("error", err.Error()))
		}
	case "accountListEgressKeys":
		if err := commands.AccountListEgressKeys(db, currentUser, args); err != nil {
			log.Error("accountListEgressKeys error", slog.String("error", err.Error()))
		}
	case "accountModify":
		if err := commands.AccountModify(db, currentUser, args); err != nil {
			log.Error("accountModify error", slog.String("error", err.Error()))
		}
	case "accountDelete":
		if err := commands.AccountDelete(db, currentUser, args); err != nil {
			log.Error("accountDelete error", slog.String("error", err.Error()))
		}
	case "accountAddAccess":
		if err := commands.AccountAddAccess(db, currentUser, args); err != nil {
			log.Error("accountAddAccess error", slog.String("error", err.Error()))
		}
	case "accountDelAccess":
		if err := commands.AccountDelAccess(db, currentUser, args); err != nil {
			log.Error("accountDelAccess error", slog.String("error", err.Error()))
		}
	case "accountListAccess":
		if err := commands.AccountListAccess(db, currentUser, args); err != nil {
			log.Error("accountListAccess error", slog.String("error", err.Error()))
		}
	// Group commands
	case "groupInfo":
		if err := commands.GroupInfo(db, args); err != nil {
			log.Error("groupInfo error", slog.String("error", err.Error()))
		}
	case "groupList":
		commands.GroupList(db, currentUser, args)
	case "groupCreate":
		if err := commands.GroupCreate(db, currentUser, args); err != nil {
			log.Error("groupCreate error", slog.String("error", err.Error()))
		}
	case "groupDelete":
		if err := commands.GroupDelete(db, currentUser, args); err != nil {
			log.Error("groupDelete error", slog.String("error", err.Error()))
		}
	case "groupAddAccess":
		if err := commands.GroupAddAccess(db, currentUser, args); err != nil {
			log.Error("groupAddAccess error", slog.String("error", err.Error()))
		}
	case "groupDelAccess":
		if err := commands.GroupDelAccess(db, currentUser, args); err != nil {
			log.Error("groupDelAccess error", slog.String("error", err.Error()))
		}
	case "groupAddMember":
		if err := commands.GroupAddMember(db, currentUser, args); err != nil {
			log.Error("groupAddMember error", slog.String("error", err.Error()))
		}
	case "groupDelMember":
		if err := commands.GroupDelMember(db, currentUser, args); err != nil {
			log.Error("groupDelMember error", slog.String("error", err.Error()))
		}
	case "groupGenerateEgressKey":
		if err := commands.GroupGenerateEgressKey(db, currentUser, args); err != nil {
			log.Error("groupGenerateEgressKey error", slog.String("error", err.Error()))
		}
	case "groupListEgressKeys":
		if err := commands.GroupListEgressKeys(db, currentUser, args); err != nil {
			log.Error("groupListEgressKeys error", slog.String("error", err.Error()))
		}
	case "groupListAccess":
		if err := commands.GroupListAccess(db, currentUser, args); err != nil {
			log.Error("groupListAccess error", slog.String("error", err.Error()))
		}
	case "groupAddAlias":
		if err := commands.GroupAddAlias(db, currentUser, args); err != nil {
			log.Error("groupAddAlias error", slog.String("error", err.Error()))
		}
	case "groupDelAlias":
		if err := commands.GroupDelAlias(db, currentUser, args); err != nil {
			log.Error("groupDelAlias error", slog.String("error", err.Error()))
		}
	case "groupListAliases":
		if err := commands.GroupListAliases(db, currentUser, args); err != nil {
			log.Error("groupListAliases error", slog.String("error", err.Error()))
		}
	// Command "TTY"
	case "ttyList":
		if err := commands.TtyList(currentUser, args); err != nil {
			log.Error("ttyList error", slog.String("error", err.Error()))
		}
	case "ttyPlay":
		if err := commands.TtyPlay(currentUser, args); err != nil {
			log.Error("ttyPlay error", slog.String("error", err.Error()))
		}
	case "whoHasAccessTo":
		if err := commands.WhoHasAccessTo(db, currentUser, args); err != nil {
			log.Error("whoHasAccessTo error", slog.String("error", err.Error()))
		}
	// Miscellaneous Commands
	case "help":
		commands.DisplayHelp(db, *currentUser)
	case "info":
		commands.DisplayInfo()
	case "exit":
		os.Exit(0)
	default:
		fmt.Printf("Unknown command: %s\n", cmd)
	}
}

func resetStdIn() {
	cmd := exec.Command("/bin/stty", "-raw", "echo")
	cmd.Stdin = os.Stdin
	_ = cmd.Run()
	_ = cmd.Wait()
}
