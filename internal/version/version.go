package version

import (
	"fmt"
	"io"
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
	AppName = "Yuhaiin" // ユハイイン 郵便配達員　ゆうびんはいたついん
	// Version can be set at link time by executing
	// the command: `git describe --abbrev=0 --tags HEAD`
	Version string

	// GitCommit can be set at link time by executing
	// the command: `git rev-parse --short HEAD`
	GitCommit string

	BuildArch string
	BuildTime string
)

func init() {
	if Version == "" {
		Version = "Not Released Version"
	}
}

func Output[T io.Writer](w T) T {
	fmt.Fprintln(w, AppName)
	fmt.Fprintf(w, "version: %v\n", Version)
	fmt.Fprintf(w, "commit: %v\n", GitCommit)
	fmt.Fprintf(w, "platform: %v/%v\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(w, "build arch: %v\n", BuildArch)
	fmt.Fprintf(w, "build time: %v\n", BuildTime)
	fmt.Fprintf(w, "go version: %v\n", runtime.Version())
	return w
}

func String() string {
	return Output(&strings.Builder{}).String()
}
