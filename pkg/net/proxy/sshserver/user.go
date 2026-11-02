package sshserver

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Login shells are not included in os/user.User. Consult the local account
// database for this optional default, while retaining /bin/sh for service
// accounts and numeric UIDs without a usable interactive shell.
func loginShell(uid uint32) string {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "/bin/sh"
	}
	return passwdLoginShell(string(data), strconv.FormatUint(uint64(uid), 10))
}

func passwdLoginShell(passwd, uid string) string {
	for line := range strings.SplitSeq(passwd, "\n") {
		fields := strings.Split(line, ":")
		if len(fields) != 7 || fields[2] != uid {
			continue
		}
		shell := fields[6]
		if filepath.IsAbs(shell) && filepath.Base(shell) != "nologin" && filepath.Base(shell) != "false" {
			return shell
		}
	}
	return "/bin/sh"
}
