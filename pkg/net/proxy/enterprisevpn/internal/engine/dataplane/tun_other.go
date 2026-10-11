//go:build !linux && !darwin

package dataplane

import (
	"fmt"
	"runtime"
)

// TUN is not supported on this platform; the Linux implementation uses the
// kernel TUN driver directly. On other platforms OpenTUN returns an error.
type TUN struct {
	name    string
	virtual VirtualPacketIO
}

// OpenTUN is unsupported off Linux.
func OpenTUN(name string) (*TUN, error) {
	if v, ok := consumeVirtualTUN(name); ok {
		return &TUN{name: name, virtual: v}, nil
	}
	return nil, fmt.Errorf("dataplane: TUN device not supported on %s (Linux only)", runtime.GOOS)
}

// OpenTUNGSO is unsupported off Linux, like OpenTUN.
func OpenTUNGSO(name string) (*TUN, error) { return OpenTUN(name) }

// OpenTAP is unsupported off Linux, like OpenTUN.
func OpenTAP(name string) (*TUN, error) { return OpenTUN(name) }

// GSO is always false off Linux.
func (t *TUN) GSO() bool { return false }

// Name is unsupported off Linux.
func (t *TUN) Name() string { return t.name }

// Read is unsupported off Linux.
func (t *TUN) Read(buf []byte) (int, error) {
	if t.virtual != nil {
		return t.virtual.Read(buf)
	}
	return 0, fmt.Errorf("dataplane: TUN not supported on this platform")
}

// Write is unsupported off Linux.
func (t *TUN) Write(pkt []byte) (int, error) {
	if t.virtual != nil {
		return t.virtual.Write(pkt)
	}
	return 0, fmt.Errorf("dataplane: TUN not supported on this platform")
}

// Close is unsupported off Linux.
func (t *TUN) Close() error {
	if t.virtual != nil {
		return t.virtual.Close()
	}
	return nil
}
