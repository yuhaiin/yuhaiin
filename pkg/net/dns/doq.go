package dns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	pdns "github.com/Asutorufa/yuhaiin/pkg/protos/config/dns"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
	"github.com/Asutorufa/yuhaiin/pkg/utils/id"
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
	host       netapi.Address
	servername string
	dialer     netapi.PacketProxy

	mu sync.RWMutex

	*client
}

func NewDoQ(config Config) (netapi.Resolver, error) {
	addr, err := ParseAddr(statistic.Type_udp, config.Host, "784")
	if err != nil {
		return nil, fmt.Errorf("parse addr failed: %w", err)
	}

	if config.Servername == "" {
		config.Servername = addr.Hostname()
	}

	d := &doq{
		dialer:     config.Dialer,
		host:       addr,
		servername: config.Servername,
	}

	d.client = NewClient(config, func(ctx context.Context, b *request) ([]byte, error) {
		session, err := d.initSession(ctx)
		if err != nil {
			return nil, fmt.Errorf("init session failed: %w", err)
		}

		d.mu.RLock()
		conn, err := session.OpenStream()
		if err != nil {
			return nil, fmt.Errorf("open stream failed: %w", err)
		}
		defer conn.Close()
		defer d.mu.RUnlock()

		deadline, ok := ctx.Deadline()
		if !ok {
			deadline = time.Now().Add(time.Second * 5)
		}

		err = conn.SetDeadline(deadline)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("set deadline failed: %w", err)
		}

		buf := pool.GetBytes(2 + len(b.Question))
		defer pool.PutBytes(buf)

		binary.BigEndian.PutUint16(buf, uint16(len(b.Question)))
		copy(buf[2:], b.Question)

		if _, err = conn.Write(buf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("write dns req failed: %w", err)
		}

		// close to make server io.EOF
		if err = conn.Close(); err != nil {
			return nil, fmt.Errorf("close stream failed: %w", err)
		}

		var length uint16
		err = binary.Read(conn, binary.BigEndian, &length)
		if err != nil {
			return nil, fmt.Errorf("read dns response length failed: %w", err)
		}

		data := pool.GetBytes(int(length))

		_, err = io.ReadFull(conn, data)
		if err != nil {
			return nil, fmt.Errorf("read dns server response failed: %w", err)
		}

		return data, nil
	})
	return d, nil
}

func (d *doq) Close() error {
	var err error
	if d.connection != nil {
		er := d.connection.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
		if er != nil {
			err = errors.Join(err, er)
		}
	}

	if d.conn != nil {
		er := d.conn.Close()
		if er != nil {
			err = errors.Join(err, er)
		}
	}

	return err
}

type DOQWrapConn struct {
	net.PacketConn
	localAddrSalt string
}

func (d *DOQWrapConn) LocalAddr() net.Addr {
	return &doqWrapLocalAddr{d.PacketConn.LocalAddr(), d.localAddrSalt}
}

// doqWrapLocalAddr make doq packetConn local addr is different, otherwise the quic-go will panic
// see: https://github.com/quic-go/quic-go/issues/3727
type doqWrapLocalAddr struct {
	net.Addr
	salt string
}

func (a *doqWrapLocalAddr) String() string {
	return fmt.Sprintf("doq://%s-%s", a.Addr.String(), a.salt)
}

var doqIgGenerate = id.IDGenerator{}

func (d *doq) initSession(ctx context.Context) (quic.Connection, error) {
	connection := d.connection

	if connection != nil {
		select {
		case <-connection.Context().Done():
			_ = connection.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")
		default:
			return connection, nil
		}
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.connection != nil {
		select {
		case <-d.connection.Context().Done():
			_ = d.connection.CloseWithError(quic.ApplicationErrorCode(quic.NoError), "")

		default:
			return d.connection, nil
		}
	}

	if d.conn != nil {
		d.conn.Close()
		d.conn = nil
	}

	if d.conn == nil {
		conn, err := d.dialer.PacketConn(ctx, d.host)
		if err != nil {
			return nil, err
		}
		d.conn = conn
	}

	session, err := quic.Dial(
		ctx,
		&DOQWrapConn{d.conn, fmt.Sprint(doqIgGenerate.Generate())},
		d.host,
		&tls.Config{
			NextProtos: []string{"http/1.1", "doq-i02", "doq-i01", "doq-i00", "doq", "dq", http2.NextProtoTLS},
			ServerName: d.servername,
		}, &quic.Config{})
	if err != nil {
		_ = d.conn.Close()
		return nil, fmt.Errorf("quic dial failed: %w", err)
	}

	d.connection = session
	return session, nil
}
