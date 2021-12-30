package socks5server

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/Asutorufa/yuhaiin/pkg/log/logasfmt"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/proxy"
	socks5client "github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/client"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

type Option struct {
	Username string
	Password string
}

const (
	connect = 0x01
	udp     = 0x03
	bind    = 0x02

	ipv4       = 0x01
	domainName = 0x03
	ipv6       = 0x04

	noAuthenticationRequired = 0x00
	gssapi                   = 0x01
	userAndPassword          = 0x02
	noAcceptableMethods      = 0xff

	succeeded                     = 0x00
	socksServerFailure            = 0x01
	connectionNotAllowedByRuleset = 0x02
	networkUnreachable            = 0x03
	hostUnreachable               = 0x04
	connectionRefused             = 0x05
	ttlExpired                    = 0x06
	commandNotSupport             = 0x07
	addressTypeNotSupport         = 0x08
)

var (
	errUDP = errors.New("UDP")
)

func handshake(modeOption ...func(*Option)) func(net.Conn, proxy.Proxy) {
	o := &Option{}
	for index := range modeOption {
		if modeOption[index] == nil {
			continue
		}
		modeOption[index](o)
	}
	return func(conn net.Conn, f proxy.Proxy) {
		handle(o.Username, o.Password, conn, f)
	}
}

func handle(user, key string, client net.Conn, f proxy.Proxy) {
	var err error
	b := *utils.BuffPool.Get().(*[]byte)
	defer utils.BuffPool.Put(&(b))

	//socks5 first handshake
	_, err = client.Read(b)
	if err != nil {
		return
	}

	err = firstHand(client, b[0], b[1], b[2], user, key)
	if err != nil {
		//fmt.Println(err)
		return
	}

	// socks5 second handshake
	_, err = client.Read(b[:])
	if err != nil {
		return
	}

	host, port, _, err := ResolveAddr(b[3:])
	if err != nil {
		return
	}
	server, err := getTarget(host, strconv.Itoa(port), b[1], client, f)
	if err != nil {
		if err != errUDP {
			logasfmt.Println(err)
		}
		return
	}

	if z, ok := server.(*net.TCPConn); ok {
		_ = z.SetKeepAlive(true)
	}
	defer server.Close()

	writeSecondResp(client, succeeded, client.LocalAddr().String()) // response to connect successful

	// hand shake successful
	utils.Forward(client, server)
}

func firstHand(client net.Conn, ver, nMethod, method byte, user, key string) error {
	if ver != 0x05 {
		writeFirstResp(client, noAcceptableMethods)
	}

	if method == noAuthenticationRequired {
		writeFirstResp(client, noAuthenticationRequired)
		return nil
	}

	if nMethod == 1 && method == userAndPassword {
		return verifyUserPass(client, user, key)
	}
	writeFirstResp(client, noAcceptableMethods)
	return fmt.Errorf("no Acceptable Methods: length:%d, method:%d, from:%s", nMethod, method, client.RemoteAddr())
}

func verifyUserPass(client net.Conn, user, key string) error {
	b := *utils.BuffPool.Get().(*[]byte)
	defer utils.BuffPool.Put(&(b))
	// get username and password
	_, err := client.Read(b[:])
	if err != nil {
		return err
	}
	username := b[2 : 2+b[1]]
	password := b[3+b[1] : 3+b[1]+b[2+b[1]]]
	if user != string(username) || key != string(password) {
		writeFirstResp(client, 0x01)
		return fmt.Errorf("verify username and password failed")
	}
	writeFirstResp(client, 0x00)
	return nil
}

func getTarget(host, port string, mode byte, client net.Conn, f proxy.Proxy) (net.Conn, error) {
	var server net.Conn
	var err error
	switch mode {
	case connect:
		server, err = f.Conn(net.JoinHostPort(host, port))
		if err != nil {
			writeSecondResp(client, hostUnreachable, client.LocalAddr().String())
			return nil, err
		}

	case udp: // udp
		l, err := newUDPServer(f, net.JoinHostPort(host, port))
		if err != nil {
			writeSecondResp(client, hostUnreachable, client.LocalAddr().String())
			return nil, err
		}
		// logasfmt.Println("----------request udp----------",
		// 	"target", net.JoinHostPort(host, port),
		// 	"local", l.l.LocalAddr().String(),
		// 	"remote", client.RemoteAddr().String(),
		// )
		writeSecondResp(client, succeeded, l.l.LocalAddr().String())
		b := make([]byte, 2)
		for {
			_, err := client.Read(b)
			if err != nil {
				l.Close()
				return nil, errUDP
			}
		}

	case bind: // bind request
		fallthrough

	default:
		writeSecondResp(client, commandNotSupport, client.LocalAddr().String())
		return nil, fmt.Errorf("not Support Method %d", mode)
	}
	return server, nil
}

func ResolveAddr(raw []byte) (dst string, port, size int, err error) {
	if len(raw) <= 0 {
		return "", 0, 0, fmt.Errorf("ResolveAddr() -> raw byte array is empty")
	}
	targetAddrRawSize := 1
	switch raw[0] {
	case ipv4:
		dst = net.IP(raw[targetAddrRawSize : targetAddrRawSize+4]).String()
		targetAddrRawSize += 4
	case ipv6:
		if len(raw) < 1+16+2 {
			return "", 0, 0, errors.New("errShortAddrRaw")
		}
		dst = net.IP(raw[1 : 1+16]).String()
		targetAddrRawSize += 16
	case domainName:
		addrLen := int(raw[1])
		if len(raw) < 1+1+addrLen+2 {
			// errShortAddrRaw
			return "", 0, 0, errors.New("error short address raw")
		}
		dst = string(raw[1+1 : 1+1+addrLen])
		targetAddrRawSize += 1 + addrLen
	default:
		// errUnrecognizedAddrType
		return "", 0, 0, errors.New("udp socks: Failed to get UDP package header")
	}
	port = (int(raw[targetAddrRawSize]) << 8) | int(raw[targetAddrRawSize+1])
	targetAddrRawSize += 2
	return dst, port, targetAddrRawSize, nil
}

func writeFirstResp(conn net.Conn, errREP byte) {
	_, _ = conn.Write([]byte{0x05, errREP})
}

func writeSecondResp(conn net.Conn, errREP byte, addr string) {
	Addr, err := socks5client.ParseAddr(addr)
	if err != nil {
		return
	}
	_, _ = conn.Write(append([]byte{0x05, errREP, 0x00}, Addr...))
}

type server struct {
	tcp proxy.Server
	// udp proxy.Server
}

func NewServer(host, username, password string) (proxy.Server, error) {
	tcp, err := proxy.NewTCPServer(
		host,
		proxy.TCPWithHandle(
			handshake(func(o *Option) {
				o.Password = password
				o.Username = username
			}),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create tcp server failed: %v", err)
	}
	// udp, err := proxy.NewUDPServer(host, proxy.UDPWithHandle((&udpHandler{}).handle))
	// if err != nil {
	// 	return nil, fmt.Errorf("create udp server failed: %v", err)
	// }
	return &server{tcp: tcp}, nil
}

func (s *server) SetProxy(p proxy.Proxy) {
	s.tcp.SetProxy(p)
	// s.udp.SetProxy(p)
}

func (s *server) SetServer(host string) error {
	err := s.tcp.SetServer(host)
	if err != nil {
		return fmt.Errorf("socks5 tcp server set host failed: %v", err)
	}
	// err = s.udp.SetServer(host)
	// if err != nil {
	// 	return fmt.Errorf("socks5 udp server set host failed: %v", err)
	// }
	return nil
}

func (s *server) Close() error {
	err := s.tcp.Close()
	if err != nil {
		return fmt.Errorf("socks5 tcp close server failed: %v", err)
	}
	// err = s.udp.Close()
	// if err != nil {
	// 	return fmt.Errorf("socks5 udp close server failed: %v", err)
	// }
	return nil
}
