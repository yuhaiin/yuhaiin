package socks5server

import (
	"fmt"
	"io"
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
	b := utils.GetBytes(utils.DefaultSize)
	defer utils.PutBytes(utils.DefaultSize, &b)

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

	host, port, _, err := socks5client.ResolveAddr(b[3:])
	if err != nil {
		return
	}
	err = secondHand(host, strconv.Itoa(port), b[1], client, f)
	if err != nil {
		logasfmt.Println("second hand failed:", err)
		return
	}

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
	b := utils.GetBytes(utils.DefaultSize)
	defer utils.PutBytes(utils.DefaultSize, &b)
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

func secondHand(host, port string, mode byte, client net.Conn, f proxy.Proxy) error {
	var err error
	switch mode {
	case connect:
		err = handleConnect(net.JoinHostPort(host, port), client, f)

	case udp: // udp
		err = handleUDP(net.JoinHostPort(host, port), client, f)

	case bind: // bind request
		fallthrough

	default:
		writeSecondResp(client, commandNotSupport, client.LocalAddr().String())
		return fmt.Errorf("not Support Method %d", mode)
	}

	if err != nil {
		writeSecondResp(client, hostUnreachable, client.LocalAddr().String())
	}
	return err
}

func handleConnect(target string, client net.Conn, f proxy.Proxy) error {
	server, err := f.Conn(target)
	if err != nil {
		return fmt.Errorf("connect to %s failed: %w", target, err)
	}
	if z, ok := server.(*net.TCPConn); ok {
		_ = z.SetKeepAlive(true)
	}
	writeSecondResp(client, succeeded, client.LocalAddr().String()) // response to connect successful
	// hand shake successful
	utils.Forward(client, server)
	server.Close()
	return nil
}

func handleUDP(target string, client net.Conn, f proxy.Proxy) error {
	l, err := newUDPServer(f, target)
	if err != nil {
		return fmt.Errorf("new udp server failed: %w", err)
	}
	writeSecondResp(client, succeeded, l.listener.LocalAddr().String())
	utils.SingleForward(client, io.Discard)
	l.Close()
	return nil
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

func NewServer(host, username, password string) (proxy.Server, error) {
	return proxy.NewTCPServer(
		host,
		proxy.TCPWithHandle(
			handshake(func(o *Option) {
				o.Password = password
				o.Username = username
			}),
		),
	)
}
