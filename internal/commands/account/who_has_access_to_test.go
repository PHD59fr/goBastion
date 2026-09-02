package account

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"goBastion/internal/models"

	"gorm.io/gorm"
)

func TestWhoHasAccessToSelfAccessMatching(t *testing.T) {
	tests := []struct {
		name        string
		query       string
		matching    string
		nonMatching string
	}{
		{name: "exact host", query: "exact.example.com", matching: "exact.example.com", nonMatching: "other.example.com"},
		{name: "stored server contains query literally", query: "prod", matching: "api-prod.internal", nonMatching: "api-stage.internal"},
		{name: "query contains stored server literally", query: "api-prod.internal", matching: "prod", nonMatching: "stage"},
		{name: "queried IP inside stored CIDR", query: "10.20.3.4", matching: "10.20.0.0/16", nonMatching: "10.21.0.0/16"},
		{name: "percent is literal", query: "%", matching: "db%prod", nonMatching: "dbXprod"},
		{name: "underscore is literal", query: "_", matching: "db_prod", nonMatching: "dbXprod"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := newTestDB(t)
			admin := newAdminUser(t, db, "admin")
			expectedUser := newRegularUser(t, db, "expected-user")
			decoyUser := newRegularUser(t, db, "decoy-user")

			createWhoHasAccessSelfAccess(t, db, expectedUser, tt.matching)
			createWhoHasAccessSelfAccess(t, db, decoyUser, tt.nonMatching)

			output, err := runWhoHasAccessTo(t, db, admin, tt.query)
			if err != nil {
				t.Fatalf("WhoHasAccessTo returned error: %v", err)
			}
			if !strings.Contains(output, expectedUser.Username) {
				t.Errorf("output does not contain matching user %q:\n%s", expectedUser.Username, output)
			}
			if strings.Contains(output, decoyUser.Username) {
				t.Errorf("output contains non-matching user %q:\n%s", decoyUser.Username, output)
			}
		})
	}
}

func TestWhoHasAccessToQueriedCIDRContainsStoredGroupIP(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	member := newRegularUser(t, db, "group-member")
	group := models.Group{Name: "network-team"}
	if err := db.Create(&group).Error; err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := db.Create(&models.UserGroup{
		UserID:  member.ID,
		GroupID: group.ID,
		Role:    models.GroupRoleMember,
	}).Error; err != nil {
		t.Fatalf("create group membership: %v", err)
	}
	if err := db.Create(&models.GroupAccess{
		GroupID:  group.ID,
		Server:   "192.168.1.25",
		Username: "root",
		Port:     22,
		Protocol: "ssh",
	}).Error; err != nil {
		t.Fatalf("create group access: %v", err)
	}

	output, err := runWhoHasAccessTo(t, db, admin, "192.168.1.0/24")
	if err != nil {
		t.Fatalf("WhoHasAccessTo returned error: %v", err)
	}
	if !strings.Contains(output, member.Username) {
		t.Errorf("output does not contain group member %q:\n%s", member.Username, output)
	}
}

func TestWhoHasAccessToDoesNotReportCIDRFalseMatch(t *testing.T) {
	db := newTestDB(t)
	admin := newAdminUser(t, db, "admin")
	user := newRegularUser(t, db, "non-matching-user")
	createWhoHasAccessSelfAccess(t, db, user, "172.16.3.0/24")

	output, err := runWhoHasAccessTo(t, db, admin, "172.16.2.1")
	if err != nil {
		t.Fatalf("WhoHasAccessTo returned error: %v", err)
	}
	if strings.Contains(output, user.Username) {
		t.Errorf("output contains non-matching user %q:\n%s", user.Username, output)
	}
}

func createWhoHasAccessSelfAccess(t *testing.T, db *gorm.DB, user *models.User, server string) {
	t.Helper()
	if err := db.Create(&models.SelfAccess{
		UserID:   user.ID,
		Server:   server,
		Username: "root",
		Port:     22,
		Protocol: "ssh",
	}).Error; err != nil {
		t.Fatalf("create self access: %v", err)
	}
}

func runWhoHasAccessTo(t *testing.T, db *gorm.DB, admin *models.User, server string) (string, error) {
	t.Helper()
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe stdout: %v", err)
	}
	os.Stdout = w
	defer func() { os.Stdout = oldStdout }()

	commandErr := WhoHasAccessTo(db, admin, []string{"--server", server})
	_ = w.Close()
	var output bytes.Buffer
	if _, err := io.Copy(&output, r); err != nil {
		t.Fatalf("read stdout: %v", err)
	}
	_ = r.Close()
	return output.String(), commandErr
}
