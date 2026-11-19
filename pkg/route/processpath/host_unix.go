//go:build !windows

package processpath

import "runtime"

// Host returns the flavor of this platform.
func Host() Flavor { return HostSyntax() }

// HostSyntax returns the flavor of this platform.
func HostSyntax() Flavor {
	switch runtime.GOOS {
	case "linux", "android":
		return Linux
	case "darwin", "ios":
		return Darwin
	}
	return Unix
}
