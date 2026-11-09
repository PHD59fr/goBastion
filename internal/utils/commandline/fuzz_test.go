package commandline

import (
	"slices"
	"testing"
	"unicode/utf8"
)

func FuzzScan(f *testing.F) {
	for _, seed := range []string{"", "alpha beta", `a 'quoted value'`, `a\\b`, "x\n;y", "[2001:db8::1]:22", string([]byte{0xff, 'x'})} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, input string) {
		// Bound work for arbitrary fuzzer input while retaining invalid UTF-8 cases.
		if len(input) > 1<<16 {
			return
		}
		tokens, err := Scan(input)
		if err != nil {
			if tokens != nil {
				t.Fatalf("Scan returned tokens with an error: %#v", tokens)
			}
			return
		}
		split, err := Split(input)
		if err != nil {
			t.Fatalf("Split rejected input accepted by Scan: %v", err)
		}
		values := make([]string, len(tokens))
		previousEnd := 0
		for i, token := range tokens {
			if token.Start < previousEnd || token.Start < 0 || token.End < token.Start || token.End > len(input) {
				t.Fatalf("token %d has invalid source range [%d,%d) after %d for %d-byte input", i, token.Start, token.End, previousEnd, len(input))
			}
			values[i] = token.Value
			previousEnd = token.End
		}
		if !slices.Equal(split, values) {
			t.Fatalf("Split values %#v differ from Scan values %#v", split, values)
		}
		if utf8.ValidString(input) {
			quoted := Quote(input)
			got, err := Split(quoted)
			if err != nil || len(got) != 1 || got[0] != input {
				t.Fatalf("Quote/Split failed round trip: got %#v, err %v", got, err)
			}
			quotedTokens, err := Scan(quoted)
			if err != nil || len(quotedTokens) != 1 || quotedTokens[0].ShellSyntax {
				t.Fatalf("quoted literal was not one non-shell token: %#v, err %v", quotedTokens, err)
			}
		}
	})
}
