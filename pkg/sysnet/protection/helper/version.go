package helper

import (
	"runtime/debug"

	"github.com/Asutorufa/yuhaiin/internal/version"
)

// BuildID identifies the build of this executable: the release version and
// commit, or for development builds the VCS revision Go recorded. The
// protection service reports it, so Yuhaiin can tell when the running
// service is older than the binary on disk.
func BuildID() string {
	id := version.Version
	if version.GitCommit != "" {
		return id + "+" + version.GitCommit
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		var rev, dirty string
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				if s.Value == "true" {
					dirty = "-dirty"
				}
			}
		}
		if rev != "" {
			return id + "+" + rev + dirty
		}
	}
	return id
}

// outdated reports whether a running service of build service should be
// restarted to run build ours. An unknown build (an older service that does
// not report one) counts as outdated.
func outdated(service, ours string) bool {
	return ours != "" && service != ours
}
