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
			name:    "safe command remains byte-for-byte unchanged",
			command: "-osh  accountList   --json",
			want:    "-osh  accountList   --json",
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
