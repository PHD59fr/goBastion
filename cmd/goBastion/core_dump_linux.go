package main

import "golang.org/x/sys/unix"

var setCoreDumpLimit = unix.Setrlimit

func disableCoreDumps() error {
	return setCoreDumpLimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
}
