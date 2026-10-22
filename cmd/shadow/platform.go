package main

import (
	"fmt"
	"os"
	"runtime"
)

// elevationPrefix is how a user re-runs shadow with the privileges it needs:
// "sudo " on Unix, nothing on Windows, where the binding grants the interface to
// every user and only Zadig needs admin rights.
func elevationPrefix() string {
	if runtime.GOOS == "windows" {
		return ""
	}
	return "sudo "
}

// checkPrivileges reports the privilege problem that would stop the exploit, or
// nil. Unix needs root to take the interface; Windows needs none.
func checkPrivileges() error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if os.Geteuid() != 0 {
		return fmt.Errorf("shadow needs root to talk to the Kindle over USB")
	}
	return nil
}

// rerunHint tells the user how to re-run shadow with those privileges; it is
// empty on hosts that need none.
func rerunHint() string {
	if prefix := elevationPrefix(); prefix != "" {
		return fmt.Sprintf("Run it with %s%s", prefix, os.Args[0])
	}
	return ""
}
