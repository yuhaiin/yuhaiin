package app

import (
	"fmt"
	"log"
	"net"
	"runtime"
	"time"

	httpserver "github.com/Asutorufa/yuhaiin/pkg/net/proxy/http/server"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/redir/redirserver"
	server "github.com/Asutorufa/yuhaiin/pkg/net/proxy/server"
	socks5server "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/server"
)

type sType int

const (
	hTTP sType = 1 << iota
	socks5
	redir
	udp
)

var (
	support = []sType{hTTP, socks5, socks5 | udp, redir}
	ref     = map[sType]func(string) (server.Server, error){
		hTTP: func(host string) (server.Server, error) {
			return server.NewTCPServer(host, httpserver.HTTPHandle())
		},
		socks5: func(host string) (server.Server, error) {
			return server.NewTCPServer(host, socks5server.Socks5Handle())
		},
		redir: func(host string) (server.Server, error) {
			if runtime.GOOS == "windows" {
				log.Println("redir not support windows")
				return nil, nil
			}
			return server.NewTCPServer(host, redirserver.RedirHandle())
		},
		socks5 | udp: func(s string) (server.Server, error) {
			return server.NewUDPServer(s, socks5server.Socks5UDPHandle())
		},
	}
)

type LocalListen struct {
	Server map[sType]server.Server
	hosts  *llOpt
}

// llOpt Local listener opts
type llOpt struct {
	hosts      map[sType]string
	tcpConn    func(string) (net.Conn, error)
	packetConn func(string) (net.PacketConn, error)
}

// LlOption Local Listener Option
type LlOption func(hosts *llOpt)

func WithSocks5(host string) LlOption {
	return func(hosts *llOpt) {
		hosts.hosts[socks5] = host
		hosts.hosts[socks5|udp] = host
	}
}

func WithRedir(host string) LlOption {
	return func(hosts *llOpt) {
		hosts.hosts[redir] = host
	}
}

func WithHTTP(host string) LlOption {
	return func(hosts *llOpt) {
		hosts.hosts[hTTP] = host
	}
}

func WithTCPConn(f func(string) (net.Conn, error)) LlOption {
	return func(opt *llOpt) {
		opt.tcpConn = f
	}
}

func WithPacketConn(f func(string) (net.PacketConn, error)) LlOption {
	return func(opt *llOpt) {
		opt.packetConn = f
	}
}

func NewLocalListenCon(opt ...LlOption) (l *LocalListen, err error) {
	hosts := &llOpt{
		tcpConn: func(s string) (net.Conn, error) {
			return net.DialTimeout("tcp", s, 5*time.Second)
		},
		packetConn: func(s string) (net.PacketConn, error) {
			return net.ListenPacket("udp", "")
		},
		hosts: map[sType]string{},
	}
	for i := range opt {
		if opt[i] == nil {
			continue
		}
		opt[i](hosts)
	}

	l = &LocalListen{
		Server: map[sType]server.Server{},
		hosts:  hosts,
	}

	for _, style := range support {
		if ref[style] == nil {
			log.Printf("can't find %d function\n", style)
			continue
		}

		l.Server[style], err = ref[style](hosts.hosts[style])
		if err != nil {
			log.Println(err)
		}
	}

	l.setConn(hosts.tcpConn, hosts.packetConn)
	return l, nil
}

func (l *LocalListen) SetAHost(opt ...LlOption) (erra error) {
	if len(opt) == 0 {
		return nil
	}

	for i := range opt {
		if opt[i] == nil {
			continue
		}
		opt[i](l.hosts)
	}

	var err error
	for _, style := range support {
		if l.Server[style] == nil && ref[style] == nil {
			continue
		}

		if l.Server[style] == nil {
			l.Server[style], err = ref[style](l.hosts.hosts[style])
		} else {
			err = l.Server[style].UpdateListen(l.hosts.hosts[style])
		}

		if err != nil {
			erra = fmt.Errorf("%v\n UpdateListen %d -> %v", erra, style, err)
		}
	}
	l.setConn(l.hosts.tcpConn, l.hosts.packetConn)
	return
}

func (l *LocalListen) setConn(
	conn func(string) (net.Conn, error),
	packetConn func(string) (net.PacketConn, error),
) {
	if conn == nil || packetConn == nil {
		return
	}

	fmt.Println("Local Listener Set TCP Proxy", &conn)
	for _, style := range support {
		if x, ok := l.Server[style].(server.TCPServer); ok {
			x.SetTCPConn(conn)
		}

		if x, ok := l.Server[style].(server.UDPServer); ok {
			x.SetUDPConn(packetConn)
		}
	}
}
