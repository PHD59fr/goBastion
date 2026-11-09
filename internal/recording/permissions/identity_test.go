package permissions

import (
	"errors"
	"fmt"
	"os/user"
	"testing"
)

func TestPasswdInventoryRejectsAliases(t *testing.T) {
	for _, tc := range []struct{ name, data string }{
		{"duplicate login", "alice:x:1000:1001::/home/alice:/bin/sh\nalice:x:1001:1001::/home/alice:/bin/sh\n"},
		{"duplicate managed UID", "alice:x:1000:1001::/home/alice:/bin/sh\nbob:x:1000:1001::/home/bob:/bin/sh\n"},
		{"malformed", "alice:x:not-a-uid:1001::/home/alice:/bin/sh\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parsePasswdInventory([]byte(tc.data)); err == nil {
				t.Fatal("unsafe passwd inventory accepted")
			}
		})
	}
}

func TestRetiredIdentityRequiresConfirmedUnknownUser(t *testing.T) {
	passwd := []byte("root:x:0:0::/root:/bin/sh\nalice:x:1000:1001::/home/alice:/bin/sh\n")
	source := identityLookup{
		user:   func(string) (*user.User, error) { return nil, user.UnknownUserError("retiredone") },
		userID: func(string) (*user.User, error) { return nil, errors.New("unused") },
		group: func(name string) (uint32, error) {
			if name == "gobastion" {
				return 1001, nil
			}
			return 1005, nil
		},
		passwd: func() ([]byte, error) { return passwd, nil },
	}
	if _, err := identitiesWithLookup("retiredone", true, source); err != nil {
		t.Fatal(err)
	}
	source.user = func(string) (*user.User, error) { return nil, fmt.Errorf("NSS unavailable") }
	if _, err := identitiesWithLookup("retiredone", true, source); err == nil {
		t.Fatal("transient lookup error treated as unknown user")
	}
	source.user = func(string) (*user.User, error) { return nil, user.UnknownUserError("retiredone") }
	source.passwd = func() ([]byte, error) { return []byte("retiredone:x:1002:1001::/home/r:/bin/sh\n"), nil }
	if _, err := identitiesWithLookup("retiredone", true, source); err == nil {
		t.Fatal("passwd alias accepted")
	}
}
