package protection

import (
	"context"
	"errors"

	"github.com/Asutorufa/yuhaiin/pkg/contract/sysnet"
)

// Backend makes the operating system enforce a Policy. Implementations keep
// the enforcement independent of the calling process: Close and the end of
// the process never remove protection, only Disable does.
type Backend interface {
	// Status reads the real operating system state, not a cached setting.
	Status(ctx context.Context) (sysnet.ProtectionStatus, error)
	// Enable saves the request to protect and applies policy. A failed
	// apply leaves the previous rules in force.
	Enable(ctx context.Context, policy Policy) error
	// Update applies a new policy while protection is enabled. It does
	// nothing while protection is disabled; it never enables it.
	Update(ctx context.Context, policy Policy) error
	// Disable saves the request not to protect and removes the rules.
	Disable(ctx context.Context) error
	// Close releases the connection to the backend. Protection stays.
	Close() error
}

// Sessioned is implemented by backends whose runtime part of the policy
// (tunnels, own traffic) is bound to a connection. Session changes whenever
// that part was lost, so the controller sends it again.
type Sessioned interface{ Session() uint64 }

// ProcessPreparer is implemented by backends that identify Yuhaiin's own
// connections by a property of the process (the macOS socket group). It
// prepares the current process and reports whether its new sockets are
// identifiable.
type ProcessPreparer interface {
	PrepareProcess(status sysnet.ProtectionStatus) (ok bool, reason string)
}

// RuleReader is implemented by backends that can show the rules they load,
// read-only, for diagnostics.
type RuleReader interface {
	Rules(ctx context.Context) sysnet.ProtectionRules
}

// ErrUnsupported is returned by the backend of platforms without Network
// Protection.
var ErrUnsupported = errors.New("network protection is not supported on this platform")

// Unsupported is the backend of platforms without Network Protection. Its
// status is "unsupported" and never an error, so the API works everywhere.
type Unsupported struct{}

func (Unsupported) Status(context.Context) (sysnet.ProtectionStatus, error) {
	return UnsupportedStatus(), nil
}
func (Unsupported) Enable(context.Context, Policy) error { return ErrUnsupported }
func (Unsupported) Update(context.Context, Policy) error { return nil }
func (Unsupported) Disable(context.Context) error        { return nil }
func (Unsupported) Close() error                         { return nil }

// UnsupportedStatus is the status of a platform without a backend.
func UnsupportedStatus() sysnet.ProtectionStatus {
	return sysnet.ProtectionStatus{State: sysnet.ProtectionUnsupported, PhysicalInterfaces: []string{}, TunnelInterfaces: []string{},
		PrivateNetworks: []string{}, BypassNetworks: []string{}}
}
