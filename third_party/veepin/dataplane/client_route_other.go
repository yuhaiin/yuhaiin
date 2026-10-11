//go:build !linux && !darwin

package dataplane

import (
	"fmt"
	"runtime"
)

// Client-side host networking is unimplemented on this platform.
//
// This file is item 12 of the operability plan. `client_route.go` used to carry
// no build tag at all: it compiled everywhere and failed at run time with
//
//	exec: "ip": executable file not found
//
// which reads as a broken installation rather than as "this platform is not
// supported", and sat badly next to `tun_other.go`'s clean "not supported on
// darwin (Linux only)" one file over. The error below is the one that file
// already gave.
//
// BSD is the obvious next platform and is nearly free: the macOS file's
// commands are `ifconfig` and `route`, which FreeBSD and OpenBSD share, and
// their tun devices carry the same 4-octet AF header `tun_darwin.go` strips.
// What differs is the device open (`/dev/tunN` rather than a control socket)
// and the resolver mechanism, which is `/etc/resolv.conf` and therefore the
// backend the Linux file already has.

// ClientRouter is the unsupported stub.
type ClientRouter struct{ cfg ClientNetConfig }

// NewClientRouter creates a router that will refuse to apply anything.
func NewClientRouter(cfg ClientNetConfig) *ClientRouter { return &ClientRouter{cfg: cfg} }

// DNSBackend is empty: nothing was installed.
func (r *ClientRouter) DNSBackend() string { return "" }

// Apply reports that this platform has no implementation, naming it.
func (r *ClientRouter) Apply() error {
	return fmt.Errorf("dataplane: client routing is not supported on %s "+
		"(Linux and macOS only)", runtime.GOOS)
}

// Revert is a no-op: Apply installed nothing.
func (r *ClientRouter) Revert() error { return nil }
