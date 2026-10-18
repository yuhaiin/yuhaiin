package ssh

import (
	"io"
	"net"
	"sync/atomic"

	"github.com/Asutorufa/yuhaiin/pkg/net/pipe"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

// SSH channels do not implement deadlines. Bridge each channel to the existing
// deadline-aware pipe, keeping timeouts and half-closes local to that channel.
func wrapChannel(channel net.Conn) net.Conn {
	local, bridge := pipe.Pipe()
	local.SetLocalAddr(channel.LocalAddr())
	local.SetRemoteAddr(channel.RemoteAddr())
	local.SetOnClose(func() {
		_ = bridge.Close()
		_ = channel.Close()
	})
	var running atomic.Int32
	running.Store(2)
	finish := func() {
		if running.Add(-1) == 0 {
			_ = bridge.Close()
			_ = channel.Close()
		}
	}
	go func() {
		defer finish()
		_, err := copyChannel(bridge, channel)
		_ = bridge.CloseWrite()
		if err != nil {
			_ = local.Close()
		}
	}()
	go func() {
		defer finish()
		_, err := copyChannel(channel, bridge)
		if half, ok := channel.(interface{ CloseWrite() error }); ok && err == nil {
			_ = half.CloseWrite()
		} else {
			_ = local.Close()
		}
	}()
	return local
}

func copyChannel(dst io.Writer, src io.Reader) (int64, error) {
	// Match x/crypto/ssh's 32 KiB channel packets rather than splitting each
	// packet into multiple pipe transfers and SSH writes.
	buffer := pool.GetBytes(32 * 1024)
	defer pool.PutBytes(buffer)
	return io.CopyBuffer(dst, src, buffer)
}
