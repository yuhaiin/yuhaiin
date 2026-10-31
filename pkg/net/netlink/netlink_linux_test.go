//go:build !android

package netlink

import (
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestProcSearchLiveLinuxSockets(t *testing.T) {
	for _, network := range []string{"tcp4", "tcp6", "udp4", "udp6"} {
		t.Run(network, func(t *testing.T) {
			addr := "127.0.0.1:0"
			if network[len(network)-1] == '6' {
				addr = "[::1]:0"
			}
			var socket syscall.Conn
			if network[:3] == "tcp" {
				l, err := net.Listen(network, addr)
				if err != nil {
					t.Skip(err)
				}
				defer l.Close()
				socket = l.(syscall.Conn)
			} else {
				c, err := net.ListenPacket(network, addr)
				if err != nil {
					t.Skip(err)
				}
				defer c.Close()
				socket = c.(syscall.Conn)
			}
			raw, err := socket.SyscallConn()
			if err != nil {
				t.Fatal(err)
			}
			var stat unix.Stat_t
			var statErr error
			if err := raw.Control(func(fd uintptr) { statErr = unix.Fstat(int(fd), &stat) }); err != nil {
				t.Fatal(err)
			}
			if statErr != nil {
				t.Fatal(statErr)
			}
			if stat.Ino > uint64(^uint32(0)) {
				t.Skip("socket inode exceeds the socket-diag uint32 representation")
			}
			path, pid, err := resolveProcessNameByProcSearch(uint32(stat.Ino), stat.Uid)
			if err != nil || path == "" || pid != uint(os.Getpid()) {
				t.Fatalf("path=%q pid=%d err=%v", path, pid, err)
			}
		})
	}
}
