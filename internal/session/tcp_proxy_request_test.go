package session

import "testing"

func TestTCPProxyRequestBracketedHosts(t *testing.T) {
	for _, host := range []string{"server.example.com", "192.0.2.10", "2001:db8::10"} {
		request := "[" + host + "]:2222"
		for _, separate := range []bool{false, true} {
			cmd, args := "-W "+request, []string(nil)
			if separate {
				cmd, args = "-W", []string{request}
			}
			gotHost, port, ok := parseTCPProxyRequest(cmd, args)
			if !ok || gotHost != host || port != "2222" {
				t.Errorf("%q %v: got host=%q port=%q ok=%v", cmd, args, gotHost, port, ok)
			}
		}
	}
}
