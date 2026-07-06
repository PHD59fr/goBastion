package cmdhelper

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"goBastion/internal/models"
	"goBastion/internal/utils/console"
	"goBastion/internal/utils/validation"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type StringFlag struct {
	Ptr   *string
	Name  string
	Def   string
	Usage string
}

type BoolFlag struct {
	Ptr   *bool
	Name  string
	Def   bool
	Usage string
}

type IntFlag struct {
	Ptr   *int
	Name  string
	Def   int
	Usage string
}

type Int64Flag struct {
	Ptr   *int64
	Name  string
	Def   int64
	Usage string
}

func ParseFlags(cmdName, usage string, args []string, flags ...interface{}) (*flag.FlagSet, error) {
	fs := flag.NewFlagSet(cmdName, flag.ContinueOnError)
	for _, f := range flags {
		switch v := f.(type) {
		case StringFlag:
			fs.StringVar(v.Ptr, v.Name, v.Def, v.Usage)
		case BoolFlag:
			fs.BoolVar(v.Ptr, v.Name, v.Def, v.Usage)
		case IntFlag:
			fs.IntVar(v.Ptr, v.Name, v.Def, v.Usage)
		case Int64Flag:
			fs.Int64Var(v.Ptr, v.Name, v.Def, v.Usage)
		}
	}
	return fs, fs.Parse(args)
}

func CleanArgs(ptrs ...*string) {
	for _, p := range ptrs {
		*p = strings.TrimSpace(*p)
	}
}

func RequirePermission(db *gorm.DB, user *models.User, permission, resource, title string) error {
	if !user.CanDo(db, permission, resource) {
		console.ErrorBlock(title, "Access Denied", fmt.Sprintf("You do not have permission to perform this action on '%s'.", resource))
		return fmt.Errorf("access denied for %s", user.Username)
	}
	return nil
}

func FindGroup(db *gorm.DB, name, title string) (*models.Group, error) {
	var g models.Group
	if err := db.Where("name = ?", name).First(&g).Error; err != nil {
		console.ErrorBlock(title, "Not Found", fmt.Sprintf("Group '%s' not found.", name))
		return nil, err
	}
	return &g, nil
}

func FindUser(db *gorm.DB, username, title string) (*models.User, error) {
	var u models.User
	if err := db.Where("username = ?", username).First(&u).Error; err != nil {
		console.ErrorBlock(title, "Not Found", fmt.Sprintf("User '%s' not found.", username))
		return nil, err
	}
	return &u, nil
}

func FindRealm(db *gorm.DB, name, title string) (*models.Realm, error) {
	var r models.Realm
	if err := db.Where("name = ?", name).First(&r).Error; err != nil {
		console.ErrorBlock(title, "Not Found", fmt.Sprintf("Realm '%s' not found.", name))
		return nil, err
	}
	return &r, nil
}

func EnsureNotLastAdmin(db *gorm.DB, title string) error {
	var count int64
	if err := db.Model(&models.User{}).Where("role = ? AND deleted_at IS NULL", models.RoleAdmin).Count(&count).Error; err != nil {
		return fmt.Errorf("error counting admins: %w", err)
	}
	if count <= 1 {
		console.ErrorBlock(title, "Operation Denied", "Cannot demote or remove the last remaining admin.")
		return fmt.Errorf("cannot demote the last remaining admin")
	}
	return nil
}

func ValidateHost(host, title string) bool {
	if !validation.IsValidHost(host) {
		console.ErrorBlock(title, "Invalid Server", "Server hostname/IP contains invalid characters (e.g., '@').")
		return false
	}
	return true
}

func ValidateUsername(username, title string) bool {
	if !validation.IsValidUsername(username) {
		console.ErrorBlock(title, "Invalid Username", "SSH username contains invalid characters.")
		return false
	}
	return true
}

func ValidatePort(port int64, title string) bool {
	if !validation.IsValidPort(port) {
		console.ErrorBlock(title, "Invalid Port", "Port must be between 1 and 65535.")
		return false
	}
	return true
}

func ValidateProtocol(protocol, title string) bool {
	if !validation.IsValidProtocol(protocol) {
		console.ErrorBlock(title, "Invalid Protocol", "Protocol must be one of: ssh, scpupload, scpdownload, sftp, rsync.")
		return false
	}
	return true
}

func ValidateCIDRs(cidrs, title string) bool {
	if !validation.IsValidCIDRs(cidrs) {
		console.ErrorBlock(title, "Invalid CIDRs", "--from must be a comma-separated list of valid CIDR notation (e.g. 10.0.0.0/8,192.168.1.0/24).")
		return false
	}
	return true
}

func ReadInput(prompt string) (string, error) {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

func ParseUUID(id, title string) (uuid.UUID, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		console.ErrorBlock(title, "Invalid UUID", fmt.Sprintf("'%s' is not a valid UUID.", id))
		return uuid.Nil, err
	}
	return parsed, nil
}
