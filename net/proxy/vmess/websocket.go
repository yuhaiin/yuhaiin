package vmess

import (
	"crypto/tls"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type websocketConn struct {
	net.Conn
	conn   *websocket.Conn
	reader io.Reader
}

func WebsocketDial(conn net.Conn, host, path, certPath string, tlsEnable bool) (net.Conn, error) {
	x := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return conn, nil
		},
		ReadBufferSize:   4 * 1024,
		WriteBufferSize:  4 * 1024,
		HandshakeTimeout: time.Second * 8,
	}

	protocol := "ws"

	if tlsEnable {
		//tls
		protocol = "wss"
		x.TLSClientConfig = &tls.Config{
			ServerName:         host,
			ClientSessionCache: getTLSSessionCache(),
		}

		if certPath != "" {
			cert, err := ioutil.ReadFile(certPath)
			if err != nil {
				return nil, err
			}
			// key, err := ioutil.ReadFile(keyPath)
			// if err != nil {
			// return nil, err
			// }
			// certPair, err := tls.X509KeyPair(cert, key)
			// if err != nil {
			// return nil, err
			// }

			x.TLSClientConfig.Certificates = append(
				x.TLSClientConfig.Certificates,
				tls.Certificate{
					Certificate: [][]byte{cert},
				})
		}
	}

	uri := protocol + "://" + host + getNormalizedPath(path)

	header := http.Header{}
	header.Add("Host", host)

	webSocketConn, resp, err := x.Dial(uri, header)
	if err != nil {
		var reason string
		if resp != nil {
			reason = resp.Status
		}
		return nil, errors.New("failed to dial to (" + uri + "): " + reason)
	}

	return &websocketConn{
		conn: webSocketConn,
	}, nil

}

var tlsSessionOnce sync.Once
var tlsSessionCache tls.ClientSessionCache

func getTLSSessionCache() tls.ClientSessionCache {
	tlsSessionOnce.Do(func() {
		tlsSessionCache = tls.NewLRUClientSessionCache(128)
	})
	return tlsSessionCache
}

func getNormalizedPath(path string) string {
	if path == "" {
		return "/"
	}
	if path[0] != '/' {
		return "/" + path
	}
	return path
}

func (w *websocketConn) Read(b []byte) (int, error) {
	for {
		reader, err := w.getReader()
		if err != nil {
			return 0, err
		}

		nBytes, err := reader.Read(b)
		if errors.Is(err, io.EOF) {
			w.reader = nil
			continue
		}
		return nBytes, err
	}
}

func (w *websocketConn) Write(b []byte) (int, error) {
	if err := w.conn.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *websocketConn) getReader() (io.Reader, error) {
	if w.reader != nil {
		return w.reader, nil
	}

	_, reader, err := w.conn.NextReader()
	if err != nil {
		return nil, err
	}
	w.reader = reader
	return reader, nil
}

func (w *websocketConn) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

func (w *websocketConn) RemoteAddr() net.Addr {
	return w.conn.RemoteAddr()
}

func (w *websocketConn) SetDeadline(t time.Time) error {
	err := w.conn.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return w.conn.SetWriteDeadline(t)
}

func (w *websocketConn) SetReadDeadLine(t time.Time) error {
	return w.conn.SetReadDeadline(t)
}

func (w *websocketConn) SetWriteDeadline(t time.Time) error {
	return w.conn.SetWriteDeadline(t)
}

func (w *websocketConn) Close() error {
	return w.conn.Close()
}
