package dns

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/direct"
	nr "github.com/Asutorufa/yuhaiin/pkg/net/utils/resolver"
	"github.com/lucas-clemente/quic-go"
	"golang.org/x/net/http2"
)

type doq struct {
	conn       net.PacketConn
	connection quic.Connection
	host       string
	p          proxy.PacketProxy

	lock sync.RWMutex

	*client
}

func NewDoQ(host string, subnet *net.IPNet, dialer proxy.PacketProxy) dns.DNS {
	if dialer == nil {
		dialer = direct.Default
	}

	if i := strings.Index(host, "://"); i != -1 {
		host = host[i+3:]
	}

	_, _, err := net.SplitHostPort(host)
	if e, ok := err.(*net.AddrError); ok {
		if strings.Contains(e.Err, "missing port in address") {
			host = net.JoinHostPort(host, "784")
		}
	}

	d := &doq{p: dialer, host: host}

	d.client = NewClient(subnet, func(b []byte) ([]byte, error) {
		err := d.initSession()
		if err != nil {
			return nil, fmt.Errorf("init session failed: %w", err)
		}

		d.lock.RLock()
		con, err := d.connection.OpenStream()
		if err != nil {
			return nil, fmt.Errorf("open stream failed: %w", err)
		}
		defer d.lock.RUnlock()

		_, err = con.Write(b)
		if err != nil {
			return nil, fmt.Errorf("write dns req failed: %w", err)
		}

		// close to make server io.EOF
		if err = con.Close(); err != nil {
			return nil, fmt.Errorf("close stream failed: %w", err)
		}

		return ioutil.ReadAll(con)
	})
	return d
}

func (d *doq) Close() error {
	if d.connection != nil {
		d.connection.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
	}

	if d.conn != nil {
		d.conn.Close()
	}

	return nil
}

func (d *doq) initSession() error {
	d.lock.Lock()
	defer d.lock.Unlock()

	if d.connection != nil {
		select {
		case <-d.connection.Context().Done():
			d.connection.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
		default:
			return nil
		}
	}

	if d.conn == nil {
		conn, err := d.p.PacketConn(d.host)
		if err != nil {
			return err
		}
		d.conn = conn
	}

	addr, err := nr.ResolveUDPAddr(d.host)
	if err != nil {
		return fmt.Errorf("resolve udp addr failed: %w", err)
	}

	hostname, _, _ := net.SplitHostPort(d.host)
	session, err := quic.DialEarly(
		d.conn,
		addr,
		hostname,
		&tls.Config{
			NextProtos: []string{"http/1.1", "doq-i00", http2.NextProtoTLS},
		},
		&quic.Config{
			HandshakeIdleTimeout: time.Second * 10,
		})
	if err != nil {
		return fmt.Errorf("quic dial failed: %w", err)
	}

	d.connection = session
	return nil
}

func (d *doq) Resolver() *net.Resolver {
	return net.DefaultResolver
}

var TlsProtos = []string{"doq-i02"}

// TlsProtosCompat stores alternative TLS protocols for experimental interoperability
var TlsProtosCompat = []string{"doq-i02", "doq-i01", "doq-i00", "doq", "dq"}
