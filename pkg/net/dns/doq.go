package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/dns"
	"github.com/Asutorufa/yuhaiin/pkg/net/interfaces/proxy"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/quic-go/quic-go"
	"golang.org/x/net/http2"
)

func init() {
	Register(pdns.Type_doq, NewDoQ)
}

type doq struct {
	conn       net.PacketConn
	connection quic.Connection
	host       proxy.Address
	servername string
	dialer     proxy.PacketProxy

	mu sync.RWMutex

	*client
}

func NewDoQ(config Config) (dns.DNS, error) {
	addr, err := ParseAddr(statistic.Type_udp, config.Host, "784")
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}

	d := &doq{dialer: config.Dialer, host: addr, servername: config.Servername}

	d.client = NewClient(config, func(ctx context.Context, b []byte) ([]byte, error) {
		err := d.initSession(ctx)
		if err != nil {
			return nil, fmt.Errorf("init session failed: %w", err)
		}

		d.mu.RLock()
		con, err := d.connection.OpenStreamSync(ctx)
		if err != nil {
			return nil, fmt.Errorf("open stream failed: %w", err)
		}
		defer d.mu.RUnlock()

		err = con.SetWriteDeadline(time.Now().Add(time.Second * 4))
		if err != nil {
			con.Close()
			return nil, fmt.Errorf("set write deadline failed: %w", err)
		}

		buf := pool.GetBytesV2(2 + len(b))
		defer pool.PutBytesV2(buf)

		binary.BigEndian.PutUint16(buf.Bytes()[:2], uint16(len(b)))

		if _, err = con.Write(append(buf.Bytes()[:2], b...)); err != nil {
			con.Close()
			return nil, fmt.Errorf("write dns req failed: %w", err)
		}

		// close to make server io.EOF
		if err = con.Close(); err != nil {
			return nil, fmt.Errorf("close stream failed: %w", err)
		}

		err = con.SetReadDeadline(time.Now().Add(time.Second * 4))
		if err != nil {
			return nil, fmt.Errorf("set read deadline failed: %w", err)
		}

		var length uint16
		err = binary.Read(con, binary.BigEndian, &length)
		if err != nil {
			return nil, fmt.Errorf("read dns response length failed: %w", err)
		}

		data := make([]byte, length)
		_, err = io.ReadFull(con, data)
		if err != nil {
			return nil, fmt.Errorf("read dns server response failed: %w", err)
		}

		return data, nil
	})
	return d, nil
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

func (d *doq) initSession(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.connection != nil {
		select {
		case <-d.connection.Context().Done():
			d.connection.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
			if d.conn != nil {
				d.conn.Close()
				d.conn = nil
			}
		default:
			return nil
		}
	}

	if d.conn == nil {
		conn, err := d.dialer.PacketConn(ctx, d.host)
		if err != nil {
			return err
		}
		d.conn = conn
	}

	session, err := quic.DialEarlyContext(
		ctx,
		d.conn,
		d.host,
		d.host.String(),
		&tls.Config{
			NextProtos: []string{"http/1.1", "doq-i02", "doq-i01", "doq-i00", "doq", "dq", http2.NextProtoTLS},
			ServerName: d.servername,
		},
		&quic.Config{
			HandshakeIdleTimeout: time.Second * 5,
			MaxIdleTimeout:       time.Second * 5,
		})
	if err != nil {
		return fmt.Errorf("quic dial failed: %w", err)
	}

	d.connection = session
	return nil
}

var TlsProtos = []string{"doq-i02"}

// TlsProtosCompat stores alternative TLS protocols for experimental interoperability
var TlsProtosCompat = []string{"doq-i02", "doq-i01", "doq-i00", "doq", "dq"}
