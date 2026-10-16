package amneziawg

import (
	"errors"
	"io"
	"os"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	awgtun "github.com/amnezia-vpn/amneziawg-go/v3/tun"
)

// tunAdapter bridges the official v3 TUN API and yuhaiin's lightweight stack.
// No host TUN, routing changes, or elevated privileges are needed.
type tunAdapter struct {
	net    *wireguard.LightweightNetTun
	events chan awgtun.Event
	once   sync.Once
}

var _ awgtun.Device = (*tunAdapter)(nil)

func newTunAdapter(net *wireguard.LightweightNetTun) *tunAdapter {
	a := &tunAdapter{net: net, events: make(chan awgtun.Event, 1)}
	a.events <- awgtun.EventUp
	return a
}
func (a *tunAdapter) File() *os.File              { return nil }
func (a *tunAdapter) Name() (string, error)       { return "amneziawg-lightweight", nil }
func (a *tunAdapter) MTU() (int, error)           { return a.net.MTU() }
func (a *tunAdapter) BatchSize() int              { return 1 }
func (a *tunAdapter) Events() <-chan awgtun.Event { return a.events }
func (a *tunAdapter) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) == 0 || offset < 0 || offset > len(bufs[0]) {
		return 0, io.ErrShortBuffer
	}
	n, err := a.net.ReadPacket(bufs[0][offset:])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	return 1, nil
}
func (a *tunAdapter) Write(bufs [][]byte, offset int) (int, error) {
	if offset < 0 {
		return 0, errors.New("amneziawg: negative packet offset")
	}
	for _, b := range bufs {
		if offset > len(b) {
			return 0, io.ErrShortBuffer
		}
	}
	return a.net.Write(bufs, offset)
}
func (a *tunAdapter) Close() error {
	a.once.Do(func() { _ = a.net.Close(); close(a.events) })
	return nil
}
