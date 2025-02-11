package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"log/slog"
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
	"goBastion/utils/sync"

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
		if err := sync.AddSystemUsersFromSystemToDb(db); err != nil {
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
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	dbDir := "/var/lib/goBastion"
	if err := os.MkdirAll(dbDir, 0777); err != nil {
		logger.Error("Failed to create DB directory", slog.String("directory", dbDir), slog.Any("error", err))
	}

	dbPath := filepath.Join(dbDir, "bastion.db")
	dsn := "file:" + dbPath + "?cache=shared&mode=rwc"

	gormLoggerConfig := gormLogger.Config{
		SlowThreshold: time.Second,
		LogLevel:      gormLogger.Silent,
		Colorful:      true,
	}
	dbLogger := gormLogger.New(log.New(os.Stdout, "\r\n", log.LstdFlags), gormLoggerConfig)

	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: dbLogger,
	})
	if err != nil {
		logger.Error("Failed to connect to database", slog.Any("error", err))
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
	)
	if err != nil {
		logger.Error("Failed to auto-migrate models", slog.Any("error", err))
		return
	}

	sqlDB, err := db.DB()
	if err != nil {
		logger.Error("Failed to get generic database object", slog.Any("error", err))
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
		logger.Error("Error fetching current system user", slog.Any("error", err))
	}
	currentUsername := sysUser.Username

	if !isSSHConnection() && currentUsername == "root" {
		restoreFlag := flag.Bool("restore", false, "Import from db")
		firstInstallFlag := flag.Bool("firstInstall", false, "First install")

		flag.Parse()
		if *restoreFlag {
			if err = sync.AddSystemUsersFromSystemToDb(db); err != nil {
				logger.Error("Error syncing users from system")
				return
			}

			if err = sync.CreateUsersFromDB(db, *logger); err != nil {
				logger.Error("Error restoring from db: " + err.Error())
				return
			}
			logger.Info("Users restored from db successfully!")
			return
		}

		if *firstInstallFlag {
			if err = createFirstAdminUser(db); err != nil {
				logger.Error("Error creating first user: " + err.Error())
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

	if !preConnectionCheck(db, currentUser) {
		return
	}

	if len(os.Args) == 1 {
		runInteractiveMode(db, &currentUser, *logger)
	} else {
		cmd := os.Args[1]
		args := os.Args[2:]
		if strings.TrimSpace(cmd) == "" {
			runInteractiveMode(db, &currentUser, *logger)
		} else {
			runNonInteractiveMode(db, &currentUser, *logger, cmd, args)
		}
	}
}

func preConnectionCheck(db *gorm.DB, currentUser models.User) bool {
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

func runNonInteractiveMode(db *gorm.DB, currentUser *models.User, logger slog.Logger, command string, args []string) {
	if command == "-osh" {
		if len(args) < 1 {
			fmt.Println("Usage: -osh <command> <args>")
			fmt.Println("Entering interactive mode.")
			runInteractiveMode(db, currentUser, logger)
		}
	}

	if strings.HasPrefix(command, "-osh") {
		parts := strings.Split(command, "-osh")
		command = parts[1]
		commandParts := strings.Split(command, " ")
		command = commandParts[1]
		args = commandParts[2:]
		executeCommand(db, currentUser, logger, command, args)
	} else {
		if err := commands.SSHConnect(db, *currentUser, logger, command); err != nil {
			fmt.Println(err)
		}
	}
}

func runInteractiveMode(db *gorm.DB, currentUser *models.User, logger slog.Logger) {
	defer resetStdIn()
	fmt.Println(utils.FgBlueB("Type 'help' to display available commands, 'tab' to autocomplete, 'exit' to quit."))

	showCompletions := false

	wrappedCompleter := func(d prompt.Document) []prompt.Suggest {
		if showCompletions {
			return autocomplete.Completion(d, currentUser)
		}
		return []prompt.Suggest{}
	}

	var p *prompt.Prompt

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

	p = prompt.New(func(in string) {
		showCompletions = false
		tokens := strings.Fields(in)
		if len(tokens) == 0 {
			return
		}
		cmd := tokens[0]
		args := tokens[1:]
		executeCommand(db, currentUser, logger, cmd, args)
	}, wrappedCompleter,
		prompt.OptionPrefix(currentUser.Username+"@"+bastionName+":"+promptSymbol),
		prompt.OptionAddKeyBind(tabKeyBinding),
		prompt.OptionAddKeyBind(escKeyBinding),
	)
	p.Run()
}

func executeCommand(db *gorm.DB, currentUser *models.User, logger slog.Logger, cmd string, args []string) {
	resetStdIn() // Mandatory! Otherwise, the terminal may be left in an unusable state.
	switch cmd {
	// Self commands
	case "selfListIngressKeys":
		commands.SelfListIngressKeys(db, currentUser)
	case "selfAddIngressKey":
		if err := commands.SelfAddIngressKey(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "selfDelIngressKey":
		if err := commands.SelfDelIngressKey(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "selfGenerateEgressKey":
		if err := commands.SelfGenerateEgressKey(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "selfListEgressKeys":
		if err := commands.SelfListEgressKeys(db, currentUser); err != nil {
			logger.Error(err.Error())
		}
	case "selfListAccesses":
		if err := commands.SelfListAccesses(db, currentUser); err != nil {
			logger.Error(err.Error())
		}
	case "selfAddPersonalAccess":
		if err := commands.SelfAddPersonalAccess(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "selfDelPersonalAccess":
		if err := commands.SelfDelPersonalAccess(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	// Account commands
	case "accountList":
		commands.AccountList(db, currentUser)
	case "accountInfo":
		commands.AccountInfo(db, currentUser, args)
	case "accountCreate":
		if err := commands.AccountCreate(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "accountListIngressKeys":
		if err := commands.AccountListIngressKeys(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "accountListEgressKeys":
		if err := commands.AccountListEgressKeys(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "accountModify":
		if err := commands.AccountModify(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "accountDelete":
		if err := commands.AccountDelete(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "accountAddPersonalAccess":
		if err := commands.AccountAddPersonalAccess(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "accountDelPersonalAccess":
		if err := commands.AccountDelPersonalAccess(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "accountListAccess":
		if err := commands.AccountListAccess(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	// Group commands
	case "groupInfo":
		if err := commands.GroupInfo(db, args); err != nil {
			logger.Error(err.Error())
		}
	case "groupList":
		commands.GroupList(db, currentUser, args)
	case "groupCreate":
		if err := commands.GroupCreate(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "groupDelete":
		if err := commands.GroupDelete(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "groupAddAccess":
		if err := commands.GroupAddAccess(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "groupDelAccess":
		if err := commands.GroupDelAccess(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "groupAddMember":
		if err := commands.GroupAddMember(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "groupDelMember":
		if err := commands.GroupDelMember(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "groupGenerateEgressKey":
		if err := commands.GroupGenerateEgressKey(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "groupListEgressKeys":
		if err := commands.GroupListEgressKeys(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "groupListAccess":
		if err := commands.GroupListAccess(db, currentUser, args); err != nil {
			logger.Error(err.Error())
		}
	case "whoHasAccessTo":
		if err := commands.WhoHasAccessTo(db, currentUser, args); err != nil {
			logger.Error(err.Error())
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
