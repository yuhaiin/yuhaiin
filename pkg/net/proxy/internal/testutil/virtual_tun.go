package testutil

import (
	"context"
	"errors"
	"sync"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/dataplane"
)

// VirtualTUN adapts packet channels to the dataplane's test-only virtual TUN.
type VirtualTUN struct {
	name   string
	in     chan []byte
	out    chan []byte
	done   chan struct{}
	close  sync.Once
	remove sync.Once
}

// NewVirtualTUN registers a packet-oriented TUN under name and returns a
// function that removes the registration after the protocol closes it.
func NewVirtualTUN(name string) (*VirtualTUN, func(), error) {
	if name == "" {
		return nil, nil, errors.New("virtual TUN name is required")
	}
	tun := &VirtualTUN{
		name: name,
		in:   make(chan []byte, 4),
		out:  make(chan []byte, 4),
		done: make(chan struct{}),
	}
	remove, err := dataplane.RegisterVirtualTUN(name, tun)
	if err != nil {
		return nil, nil, err
	}
	return tun, func() { tun.remove.Do(remove) }, nil
}

func (t *VirtualTUN) Name() string { return t.name }

// Send sends one packet from the local stack into the VPN.
func (t *VirtualTUN) Send(packet []byte) error {
	copyPacket := append([]byte(nil), packet...)
	select {
	case t.in <- copyPacket:
		return nil
	case <-t.done:
		return dataplane.ErrClosed
	}
}

// Receive returns one packet from the VPN, or ctx's error if it does not arrive.
func (t *VirtualTUN) Receive(ctx context.Context) ([]byte, error) {
	select {
	case packet := <-t.out:
		return packet, nil
	case <-t.done:
		return nil, dataplane.ErrClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *VirtualTUN) Read(p []byte) (int, error) {
	select {
	case packet := <-t.in:
		return copy(p, packet), nil
	case <-t.done:
		return 0, dataplane.ErrClosed
	}
}

func (t *VirtualTUN) Write(p []byte) (int, error) {
	packet := append([]byte(nil), p...)
	select {
	case t.out <- packet:
		return len(p), nil
	case <-t.done:
		return 0, dataplane.ErrClosed
	}
}

func (t *VirtualTUN) Close() error {
	t.close.Do(func() { close(t.done) })
	return nil
}
