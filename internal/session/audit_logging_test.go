package session

import (
	"reflect"
	"testing"
)

func TestRedactAuditArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "separate password value",
			args: []string{"--user", "alice", "--password", "secret", "--host", "db.example"},
			want: []string{"--user", "alice", "--password", auditRedactedValue, "--host", "db.example"},
		},
		{
			name: "equals password value",
			args: []string{"--password=secret", "--port", "5432"},
			want: []string{"--password=" + auditRedactedValue, "--port", "5432"},
		},
		{
			name: "single dash password value",
			args: []string{"-password", "secret", "--host", "db.example"},
			want: []string{"-password", auditRedactedValue, "--host", "db.example"},
		},
		{
			name: "single dash equals password value",
			args: []string{"-password=secret", "--host", "db.example"},
			want: []string{"-password=" + auditRedactedValue, "--host", "db.example"},
		},
		{
			name: "multiple password values",
			args: []string{"--password", "one", "safe", "--password=two"},
			want: []string{"--password", auditRedactedValue, "safe", "--password=" + auditRedactedValue},
		},
		{
			name: "similarly named safe flag",
			args: []string{"--password-file", "/safe/path", "--user", "alice"},
			want: []string{"--password-file", "/safe/path", "--user", "alice"},
		},
		{
			name: "credential-bearing positional URLs and MySQL DSN",
			args: []string{"postgres://alice:secret@db/test", "redis://:secret@db/0", "alice:secret@tcp(db:3306)/test"},
			want: []string{auditRedactedValue, auditRedactedValue, auditRedactedValue},
		},
		{
			name: "quoted PostgreSQL keyword DSN",
			args: []string{"host=db user=alice password='secret with spaces' dbname=test"},
			want: []string{auditRedactedValue},
		},
		{
			name: "DSN flag and case-insensitive secret flag",
			args: []string{"--dsn", "opaque-secret", "--API_KEY=secret", "PGPASSWORD=secret"},
			want: []string{"--dsn", auditRedactedValue, "--API_KEY=" + auditRedactedValue, "PGPASSWORD=" + auditRedactedValue},
		},
		{
			name: "URL query credentials and encoded key inside a flag",
			args: []string{"postgres://db/test?password=secret", "--connection=https://db/?%74oken=secret"},
			want: []string{auditRedactedValue, auditRedactedValue},
		},
		{
			name: "separated assignment operator",
			args: []string{"--password", "=", "secret", "--host", "db"},
			want: []string{"--password", auditRedactedValue, auditRedactedValue, "--host", "db"},
		},
		{
			name: "PostgreSQL assignment tokens",
			args: []string{"host=db", "password", "=", "secret", "pwd=", "secret2", "token", "=secret3"},
			want: []string{"host=db", "password", auditRedactedValue, auditRedactedValue, "pwd=" + auditRedactedValue, auditRedactedValue, "token", auditRedactedValue},
		},
		{
			name: "public connection targets",
			args: []string{"postgres://db/test", "--host=db", "alice@db", "host=db user=alice"},
			want: []string{"postgres://db/test", "--host=db", "alice@db", "host=db user=alice"},
		},
		{
			name: "nil arguments",
			args: nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := append([]string(nil), tt.args...)
			got := redactAuditArgs(tt.args)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("redactAuditArgs(%q) = %q, want %q", tt.args, got, tt.want)
			}
			if !reflect.DeepEqual(tt.args, original) {
				t.Errorf("redactAuditArgs altered handler arguments: got %q, want %q", tt.args, original)
			}
		})
	}
}

func TestRedactAuditCommand(t *testing.T) {
	tests := []struct {
		name    string
		command string
		want    string
	}{
		{
			name:    "PostgreSQL assignment with whitespace",
			command: "-osh connect host=db password = credential user=alice",
			want:    "-osh connect host=db password [REDACTED] [REDACTED] user=alice",
		},
		{
			name:    "PostgreSQL assignment with separated value",
			command: "-osh connect host=db password= credential user=alice",
			want:    "-osh connect host=db password=[REDACTED] [REDACTED] user=alice",
		},
		{
			name:    "positional credential URL",
			command: "-osh connect 'postgres://alice:credential@db/test'",
			want:    "-osh connect [REDACTED]",
		},
		{
			name:    "quoted keyword DSN",
			command: `-osh connect "host=db password=credential user=alice"`,
			want:    "-osh connect [REDACTED]",
		},
		{
			name:    "original SSH command with separate value",
			command: "-osh selfAddDBAccess --host db.example --password secret --user alice",
			want:    "-osh selfAddDBAccess --host db.example --password [REDACTED] --user alice",
		},
		{
			name:    "original SSH command with equals value",
			command: "-osh selfAddDBAccess --password=secret --host db.example",
			want:    "-osh selfAddDBAccess --password=[REDACTED] --host db.example",
		},
		{
			name:    "SSH command with single dash password",
			command: `-osh selfAddDBAccess -password "secret with spaces" --host db.example`,
			want:    "-osh selfAddDBAccess -password [REDACTED] --host db.example",
		},
		{
			name:    "SSH command with single dash equals password",
			command: "-osh selfAddDBAccess -password=secret --host db.example",
			want:    "-osh selfAddDBAccess -password=[REDACTED] --host db.example",
		},
		{
			name:    "safe command remains byte-for-byte unchanged",
			command: "-osh  accountList   --json",
			want:    "-osh  accountList   --json",
		},
		{
			name:    "quoted password with spaces",
			command: `-osh selfAddDBAccess --password "secret with spaces" --host db.example`,
			want:    "-osh selfAddDBAccess --password [REDACTED] --host db.example",
		},
		{
			name:    "quoted equals password",
			command: `-osh selfAddDBAccess --password='secret with spaces'`,
			want:    "-osh selfAddDBAccess --password=[REDACTED]",
		},
		{
			name:    "unfinished quoted password",
			command: `-osh selfAddDBAccess --password "secret with spaces`,
			want:    auditRedactedValue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redactAuditCommand(tt.command); got != tt.want {
				t.Errorf("redactAuditCommand(%q) = %q, want %q", tt.command, got, tt.want)
			}
		})
	}
}
