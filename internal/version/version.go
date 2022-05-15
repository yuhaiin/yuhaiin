package version

import (
	"runtime"
	"strings"
)

var (
	// Version can be set at link time by executing
	// the command: `git describe --abbrev=0 --tags HEAD`
	Version string

	// GitCommit can be set at link time by executing
	// the command: `git rev-parse --short HEAD`
	GitCommit string

	BuildArch string
	BuildTime string
)

func String() string {
	if Version == "" {
		Version = "Not Released Version"
	}

	str := strings.Builder{}

	str.WriteString("version: ")
	str.WriteString(Version)
	str.WriteString("\n")

	str.WriteString("commit: ")
	str.WriteString(GitCommit)
	str.WriteString("\n")

	str.WriteString("build arch: ")
	str.WriteString(BuildArch)
	str.WriteString("\n")

	str.WriteString("build time: ")
	str.WriteString(BuildTime)
	str.WriteString("\n")

	str.WriteString("go version: ")
	str.WriteString(runtime.Version())
	str.WriteString("\n")

	return str.String()
}
