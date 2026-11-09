package permissions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"time"

	"goBastion/internal/utils/validation"
)

const passwdLimit = 4 << 20
const passwdEntriesLimit = 100000

type identityLookup struct {
	user   func(string) (*user.User, error)
	userID func(string) (*user.User, error)
	group  func(string) (uint32, error)
	passwd func() ([]byte, error)
}

type passwdInventory struct {
	names   map[string]uint32
	managed map[uint32]string
	primary map[uint32]bool
}

type boundedPasswdOutput struct{ data []byte }

func (b *boundedPasswdOutput) Write(p []byte) (int, error) {
	remaining := passwdLimit - len(b.data)
	if len(p) > remaining {
		b.data = append(b.data, p[:remaining]...)
		return remaining, errors.New("passwd inventory size limit reached")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}

func getentPasswd() ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/getent", "passwd")
	cmd.Stderr = io.Discard
	output := &boundedPasswdOutput{}
	cmd.Stdout = output
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("cannot obtain bounded local passwd inventory: %w", err)
	}
	if len(output.data) == 0 {
		return nil, errors.New("empty passwd inventory")
	}
	return output.data, nil
}

func parsePasswdInventory(data []byte) (passwdInventory, error) {
	if len(data) == 0 || len(data) > passwdLimit {
		return passwdInventory{}, errors.New("invalid passwd inventory size")
	}
	result := passwdInventory{names: make(map[string]uint32), managed: make(map[uint32]string), primary: make(map[uint32]bool)}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(lines) > passwdEntriesLimit {
		return passwdInventory{}, errors.New("passwd inventory entry limit reached")
	}
	for _, line := range lines {
		if len(line) == 0 || len(line) > 4096 {
			return passwdInventory{}, errors.New("malformed passwd inventory line")
		}
		parts := strings.Split(line, ":")
		if len(parts) != 7 || parts[0] == "" || strings.ContainsAny(parts[0], "\r\n") {
			return passwdInventory{}, errors.New("malformed passwd inventory record")
		}
		uid, err := strconv.ParseUint(parts[2], 10, 32)
		if err != nil {
			return passwdInventory{}, errors.New("invalid passwd UID")
		}
		gid, err := strconv.ParseUint(parts[3], 10, 32)
		if err != nil {
			return passwdInventory{}, errors.New("invalid passwd primary GID")
		}
		if _, exists := result.names[parts[0]]; exists {
			return passwdInventory{}, errors.New("duplicate passwd login name")
		}
		result.names[parts[0]] = uint32(uid)
		result.primary[uint32(gid)] = true
		if uid >= 1000 && uid < 65000 {
			if _, exists := result.managed[uint32(uid)]; exists {
				return passwdInventory{}, errors.New("duplicate managed passwd UID")
			}
			result.managed[uint32(uid)] = parts[0]
		}
	}
	return result, nil
}

func productionIdentityLookup() identityLookup {
	return identityLookup{user: user.Lookup, userID: user.LookupId, group: groupID, passwd: getentPasswd}
}

func identities(name string, retired bool) (identity, error) {
	return identitiesWithLookup(name, retired, productionIdentityLookup())
}

func identitiesWithLookup(name string, retired bool, source identityLookup) (identity, error) {
	if name != strings.ToLower(name) || !validation.IsValidManagedUsername(name) {
		return identity{}, errors.New("invalid recording account")
	}
	data, err := source.passwd()
	if err != nil {
		return identity{}, err
	}
	inventory, err := parsePasswdInventory(data)
	if err != nil {
		return identity{}, err
	}
	var uid uint32
	if retired {
		if _, present := inventory.names[name]; present {
			return identity{}, errors.New("retired account still exists in passwd inventory")
		}
		if _, err = source.user(name); err == nil {
			return identity{}, errors.New("retired recording account still exists locally")
		}
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			return identity{}, fmt.Errorf("cannot prove retired account absence: %w", err)
		}
	} else {
		u, e := source.user(name)
		if e != nil {
			return identity{}, errors.New("recording account is unavailable")
		}
		parsed, e := strconv.ParseUint(u.Uid, 10, 32)
		if e != nil || parsed < 1000 || parsed >= 65000 || u.Username != name || inventory.names[name] != uint32(parsed) {
			return identity{}, errors.New("invalid recording account identity")
		}
		uid = uint32(parsed)
		a, e := source.userID(u.Uid)
		if e != nil || a.Username != name || a.Uid != u.Uid {
			return identity{}, errors.New("noncanonical recording account identity")
		}
	}
	shared, err := source.group("gobastion")
	if err != nil {
		return identity{}, err
	}
	auditors, err := source.group("gobastion-auditors")
	if err != nil {
		return identity{}, err
	}
	if shared == auditors {
		return identity{}, errors.New("recording groups must be distinct")
	}
	if inventory.primary[auditors] {
		return identity{}, errors.New("recording auditor group cannot be a primary group")
	}
	return identity{uid: uid, shared: shared, auditors: auditors, retired: retired, managed: inventory.managed}, nil
}

func groupID(name string) (uint32, error) {
	g, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("recording group %s unavailable", name)
	}
	id, err := strconv.Atoi(g.Gid)
	if err != nil || id < 1 || id > 1<<31-1 {
		return 0, errors.New("invalid recording group ID")
	}
	return uint32(id), nil
}
