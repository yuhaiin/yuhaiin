package vmess

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
)

type websocketConn struct {
	net.Conn
	conn   *websocket.Conn
	reader io.Reader
}

func WebsocketDial(conn net.Conn, host, path string, certPath string, tlsEnable bool) (net.Conn, error) {
	x := &websocket.Dialer{
		NetDial: func(network, addr string) (net.Conn, error) {
			return conn, nil
		},
		ReadBufferSize:   4 * 1024,
		WriteBufferSize:  4 * 1024,
		HandshakeTimeout: time.Second * 6,
	}

	protocol := "ws"

	if tlsEnable {
		//tls
		protocol = "wss"
		x.TLSClientConfig = &tls.Config{
			ServerName: host,
			// InsecureSkipVerify: true,
			ClientSessionCache: tlsSessionCache,
		}

		if certPath != "" {
			cert, err := ioutil.ReadFile(certPath)
			if err != nil {
				return nil, err
			}

			pool, err := x509.SystemCertPool()
			if err != nil {
				return nil, fmt.Errorf("get x509 system cert pool failed: %v", err)
			}

			block, _ := pem.Decode(cert)
			if block != nil {
				certA, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					log.Printf("parse certificate failed: %v", err)
				} else {
					x.TLSClientConfig.Certificates = append(
						x.TLSClientConfig.Certificates,
						tls.Certificate{
							Certificate: [][]byte{certA.Raw},
						},
					)
					pool.AddCert(certA)
				}
			}
			x.TLSClientConfig.ClientCAs = pool
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

var tlsSessionCache = tls.NewLRUClientSessionCache(128)

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
		if err != nil && errors.Is(err, io.EOF) {
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
