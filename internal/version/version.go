package version

import (
	"runtime"
	"strings"
)

var (
	Art = `
_____.___.     .__           .__.__        
\__  |   |__ __|  |__ _____  |__|__| ____  
 /   |   |  |  \  |  \\__  \ |  |  |/    \ 
 \____   |  |  /   Y  \/ __ \|  |  |   |  \
 / ______|____/|___|  (____  /__|__|___|  /
 \/                 \/     \/           \/ 
 `
	AppName = "ユハイイン" // 郵便配達員　ゆうびんはいたついん
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

	str.WriteString(AppName)
	str.WriteByte('\n')
	str.WriteString("version: ")
	str.WriteString(Version)
	str.WriteByte('\n')

	str.WriteString("commit: ")
	str.WriteString(GitCommit)
	str.WriteByte('\n')

	str.WriteString("build arch: ")
	str.WriteString(BuildArch)
	str.WriteByte('\n')

	str.WriteString("build time: ")
	str.WriteString(BuildTime)
	str.WriteByte('\n')

	str.WriteString("go version: ")
	str.WriteString(runtime.Version())
	str.WriteByte('\n')

	return str.String()
}
