package dialer

import (
	"context"
	"net/netip"
	"syscall"

	"github.com/Asutorufa/yuhaiin/pkg/net/netstate"
)

// SocketNetworkBinder optionally binds an outbound fd to a native Network and
// returns its stable identity. An empty identity means unknown. Android installs
// this separately from protect(), which is also used for inbound listeners.
var SocketNetworkBinder func(fd int32, interfaceName string) (string, error)

const unknownNativeNetwork = "native:unknown"

type nativeBinding struct {
	manager      *netstate.Manager
	ctx          context.Context
	cancel       context.CancelCauseFunc
	path         netstate.Path
	registration *netstate.Registration
	family       uint8
	bind         func(int32, string) (string, error)
}

func newNativeBinding(ctx context.Context, family uint8) *nativeBinding {
	bind := SocketNetworkBinder
	if bind == nil {
		return nil
	}
	ctx, cancel := context.WithCancelCause(ctx)
	return &nativeBinding{manager: netstate.Default, ctx: ctx, cancel: cancel, family: family, bind: bind}
}

func (b *nativeBinding) control(c syscall.RawConn, opts *Options) error {
	if b == nil {
		return nil
	}
	var inner error
	err := c.Control(func(fd uintptr) { opts.networkID, inner = b.bind(int32(fd), opts.InterfaceName) })
	if err != nil {
		return err
	}
	if inner != nil {
		return inner
	}
	if opts.networkID != "" {
		b.path = b.manager.CaptureNetwork(opts.networkID, netip.Addr{}, b.family)
		b.registration = b.manager.Register(b.path, func(netstate.Event) { b.cancel(netstate.ErrInvalidated) })
	} else {
		// The binder explicitly could not establish identity. Do not later
		// assign an Android Network from a potentially stale matching IP.
		opts.networkID = unknownNativeNetwork
	}
	return nil
}

func (b *nativeBinding) close() {
	if b != nil {
		_ = b.registration.Close()
		b.cancel(context.Canceled)
	}
}
