//go:build linux

package harden

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// Apply performs the requested protections, returning the ones that took effect
// so the caller can say so rather than claiming more than happened.
//
// It stops at the first failure rather than applying what it can and reporting
// a partial result. A caller that asked for both wanted both; continuing past a
// refused mlockall and reporting "core dumps disabled" invites exactly the
// misplaced confidence this package exists to avoid.
func Apply(o Options) (applied []string, err error) {
	if o.LockMemory {
		// MCL_CURRENT covers what is mapped now; MCL_FUTURE covers every later
		// allocation, which is the half that matters -- session keys are
		// derived long after start-up.
		if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
			return applied, fmt.Errorf("harden: mlockall: %w "+
				"(needs CAP_IPC_LOCK or RLIMIT_MEMLOCK headroom; "+
				"raise it with `ulimit -l unlimited` or LimitMEMLOCK=infinity in the unit)", err)
		}
		applied = append(applied, "memory locked (no key material reaches swap)")
	}
	if o.NoCoreDumps {
		if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
			return applied, fmt.Errorf("harden: prctl(PR_SET_DUMPABLE, 0): %w", err)
		}
		applied = append(applied, "core dumps and same-uid ptrace disabled")
	}
	return applied, nil
}
