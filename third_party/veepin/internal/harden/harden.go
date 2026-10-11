// Package harden holds the two process-level protections veepin can take for
// its own key material, as opposed to the one it deliberately does not.
//
// doc/security.md opens by refusing to zero key material after use, and the
// reasoning is right: Go's collector moves and copies objects, so overwriting
// the copy the code can still name clears one of several and produces something
// that *looks* like it wipes keys. It then says where the boundary should be
// defended instead -- "process isolation, disabled core dumps, encrypted swap" --
// and hands all three to the operator.
//
// Two of those three the process can take itself, on Linux, through x/sys/unix,
// with no new dependency and no cgo:
//
//   - mlockall(MCL_CURRENT|MCL_FUTURE) keeps every page resident, so a session
//     key never reaches swap. That closes the read-the-disk-afterwards case
//     outright rather than narrowing it.
//   - prctl(PR_SET_DUMPABLE, 0) stops a crash writing keys into a core file,
//     and stops a same-uid process attaching with ptrace.
//
// # What this does not cover
//
// A debugger with CAP_SYS_PTRACE, a hypervisor, a kernel exploit, or anything
// with code execution in the process. The boundary moves; it does not close, and
// doc/security.md still says veepin does not claim protection against an
// attacker who can read process memory.
//
// # Why every call reports its failure
//
// Both are opt-in and both fail loudly. mlockall needs RLIMIT_MEMLOCK headroom
// or CAP_IPC_LOCK, and a hardening switch that silently does nothing is worse
// than no switch -- for exactly the reason doc/security.md gives about fake key
// wiping. The appearance invites confidence the process has not earned.
package harden

// Options selects which protections to apply. The zero value applies none,
// which is the behaviour from before this package existed.
type Options struct {
	// LockMemory calls mlockall(MCL_CURRENT|MCL_FUTURE): no page of this
	// process reaches swap, so key material cannot be recovered from a swap
	// partition or file afterwards.
	//
	// The cost is real and worth stating: the whole resident set becomes
	// unswappable, and the kernel refuses the call outright if it would exceed
	// RLIMIT_MEMLOCK. On a memory-constrained host this trades an availability
	// risk for a confidentiality gain, which is why it is a flag rather than a
	// default.
	LockMemory bool

	// NoCoreDumps calls prctl(PR_SET_DUMPABLE, 0): a crash writes no core file
	// carrying live session keys, and a same-uid process cannot ptrace in.
	//
	// It also makes /proc/self owned by root, which is why it is separable from
	// LockMemory rather than bundled with it -- a deployment that reads its own
	// /proc entries for monitoring needs to know that changed.
	NoCoreDumps bool
}

// Any reports whether any protection was requested, so a caller can skip the
// platform check and its log line entirely when nothing was asked for.
func (o Options) Any() bool { return o.LockMemory || o.NoCoreDumps }
