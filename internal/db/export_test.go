package db

import (
	"strings"
	"testing"
)

// realRSAKey is representative of an RSA-4096 private key PEM (shortened for testing).
const realRSAKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78L
hWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc/BJECPebWKRXjBZCiFV4n3okIh
Cs/p1wCEjzVIXgpSTlFiwHcrCMy4DWsFRh8cNyxS0LHoIiEjpZaEzNYDiSk6kDZ
oL3b3ALBY9cMgIGRTxHIBD/y3OCGS0Ry7lhpFoaQEF4QJSQB6oBhgqDvMIEQxhj
-----END RSA PRIVATE KEY-----`

const realOpenSSHKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDn5v7QmCRtFMLW7bQbmXyQgmJQHPe3LPKIEjZDzfm5HQAAAJBC96YA
QvemAAAAC3NzaC10ZWQyNTUxOQAAACDn5v7QmCRtFMLW7bQbmXyQgmJQHPe3LPKIEjZD
zfm5HQAAAEBCkMmFoXt5bZlPxzRn2TuRbPEyXimJ0iBNhHPi5Ckv7ufm/tCYJG0Uwtbt
tBuZfJCCYlAc97cs8ogSNkPN+bkAAAAPdGVzdEBleGFtcGxlCgE=
-----END OPENSSH PRIVATE KEY-----`

func TestFormatValue_PEMKeyForPostgres(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		targetDialect  string
		wantPrefix     string
		wantNoRawNewline bool
	}{
		{
			name:             "RSA key to postgres uses E-string",
			input:            realRSAKey,
			targetDialect:    "postgres",
			wantPrefix:       "E'",
			wantNoRawNewline: true,
		},
		{
			name:             "OpenSSH key to postgres uses E-string",
			input:            realOpenSSHKey,
			targetDialect:    "postgres",
			wantPrefix:       "E'",
			wantNoRawNewline: true,
		},
		{
			name:             "RSA key to sqlite keeps raw newlines",
			input:            realRSAKey,
			targetDialect:    "sqlite",
			wantPrefix:       "'",
			wantNoRawNewline: false,
		},
		{
			name:          "simple string to postgres uses regular quoting",
			input:         "hello world",
			targetDialect: "postgres",
			wantPrefix:    "'",
		},
		{
			name:          "string with single quote is escaped",
			input:         "it's a test",
			targetDialect: "postgres",
			wantPrefix:    "'",
		},
		{
			name:          "string with single quote is escaped for postgres with newline",
			input:         "line1\nit's line2",
			targetDialect: "postgres",
			wantPrefix:    "E'",
			wantNoRawNewline: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatValue(tt.input, "col", nil, tt.targetDialect)

			if !strings.HasPrefix(got, tt.wantPrefix) {
				t.Errorf("formatValue() = %q, want prefix %q", got[:min(len(got), 20)], tt.wantPrefix)
			}

			if tt.wantNoRawNewline && strings.ContainsRune(got, '\n') {
				t.Errorf("formatValue() contains raw newline for postgres target; got:\n%s", got)
			}

			if tt.wantNoRawNewline && strings.ContainsRune(got, '\r') {
				t.Errorf("formatValue() contains raw carriage return for postgres target")
			}
		})
	}
}

func TestFormatValue_PEMTrailingNewline(t *testing.T) {
	// A PEM key without trailing newline (as stored by strings.TrimSpace) must
	// get a trailing \n added during export so that OpenSSH can parse the temp file.
	keyNoNewline := realRSAKey // const defined without trailing newline

	for _, dialect := range []string{"postgres", "sqlite", "mysql"} {
		got := formatValue(keyNoNewline, "priv_key", nil, dialect)
		// Strip the outer SQL quoting to recover the stored value
		var inner string
		if strings.HasPrefix(got, "E'") {
			inner = got[2 : len(got)-1]
			inner = strings.ReplaceAll(inner, `\\`, "\x00")
			inner = strings.ReplaceAll(inner, `\n`, "\n")
			inner = strings.ReplaceAll(inner, `\r`, "\r")
			inner = strings.ReplaceAll(inner, "\x00", `\`)
		} else {
			inner = got[1 : len(got)-1]
			inner = strings.ReplaceAll(inner, `''`, `'`)
		}
		if !strings.HasSuffix(inner, "\n") {
			t.Errorf("dialect=%s: PEM key missing trailing newline in exported value", dialect)
		}
	}
}

func TestFormatValue_PEMRoundTrip(t *testing.T) {
	// Verify that escapeSQLStringPostgres correctly represents the key content
	// so that PostgreSQL (interpreting E'...' escape sequences) would recover
	// the original string.
	key := realRSAKey

	escaped := escapeSQLStringPostgres(key)

	// The escaped form must NOT contain raw newlines (they must be \n sequences).
	if strings.ContainsRune(escaped, '\n') {
		t.Error("escapeSQLStringPostgres: raw newline found in output")
	}
	if strings.ContainsRune(escaped, '\r') {
		t.Error("escapeSQLStringPostgres: raw carriage return found in output")
	}

	// The escaped form must contain the \n escape sequence.
	if !strings.Contains(escaped, `\n`) {
		t.Error("escapeSQLStringPostgres: expected \\n escape sequence not found")
	}

	// Simulate PostgreSQL's E-string interpretation: replace \n → newline, \\ → \.
	roundTripped := escaped
	roundTripped = strings.ReplaceAll(roundTripped, `\\`, "\x00") // temp placeholder
	roundTripped = strings.ReplaceAll(roundTripped, `\n`, "\n")
	roundTripped = strings.ReplaceAll(roundTripped, `\r`, "\r")
	roundTripped = strings.ReplaceAll(roundTripped, "\x00", `\`)

	if roundTripped != key {
		t.Errorf("round-trip mismatch:\noriginal:     %q\nround-tripped:%q", key, roundTripped)
	}
}

func TestEscapeSQLStringPostgres_Backslash(t *testing.T) {
	input := `path\to\file`
	got := escapeSQLStringPostgres(input)
	want := `path\\to\\file`
	if got != want {
		t.Errorf("escapeSQLStringPostgres(%q) = %q, want %q", input, got, want)
	}
}

func TestEscapeSQLStringPostgres_SingleQuote(t *testing.T) {
	input := "it's fine"
	got := escapeSQLStringPostgres(input)
	want := "it''s fine"
	if got != want {
		t.Errorf("escapeSQLStringPostgres(%q) = %q, want %q", input, got, want)
	}
}

func TestEscapeSQLStringPostgres_CRLF(t *testing.T) {
	// Keys transferred via Windows/FTP-text-mode may arrive with \r\n.
	// Ensure both are escaped so the SQL file has no raw control characters.
	input := "line1\r\nline2"
	got := escapeSQLStringPostgres(input)
	if strings.ContainsRune(got, '\r') || strings.ContainsRune(got, '\n') {
		t.Errorf("escapeSQLStringPostgres: output still contains raw CR/LF: %q", got)
	}
	want := `line1\r\nline2`
	if got != want {
		t.Errorf("escapeSQLStringPostgres(%q) = %q, want %q", input, got, want)
	}
}


