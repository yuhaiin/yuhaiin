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

func WebsocketDial(conn net.Conn, host, path string, certPath []string, tlsEnable bool) (net.Conn, error) {
	x := &websocket.Dialer{
		NetDial: func(string, string) (net.Conn, error) {
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

		root, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("get x509 system cert pool failed: %v", err)
		}
		x.TLSClientConfig = &tls.Config{
			ServerName:             host,
			RootCAs:                root,
			NextProtos:             []string{"http/1.1"},
			InsecureSkipVerify:     false,
			SessionTicketsDisabled: true,
			ClientSessionCache:     tlsSessionCache,
		}

		for i := range certPath {
			if certPath[i] == "" {
				continue
			}

			cert, err := ioutil.ReadFile(certPath[i])
			if err != nil {
				return nil, err
			}

			block, _ := pem.Decode(cert)
			if block == nil {
				continue
			}

			certA, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				log.Printf("parse certificate failed: %v", err)
				continue
			}

			x.TLSClientConfig.Certificates = append(
				x.TLSClientConfig.Certificates,
				tls.Certificate{
					Certificate: [][]byte{certA.Raw},
				},
			)
			x.TLSClientConfig.RootCAs.AddCert(certA)
		}
	}

	header := http.Header{}
	header.Add("Host", host)
	uri := fmt.Sprintf("%s://%s%s", protocol, host, getNormalizedPath(path))
	webSocketConn, resp, err := x.Dial(uri, header)
	if err != nil {
		var reason string
		if resp != nil {
			reason = resp.Status
		}
		return nil, errors.New("failed to dial to (" + uri + "): " + reason)
	}

	return &wsConn{Conn: webSocketConn}, nil

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

type wsConn struct {
	*websocket.Conn
	reader io.Reader
}

func (w *wsConn) Read(b []byte) (int, error) {
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

func (w *wsConn) Write(b []byte) (int, error) {
	err := w.Conn.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (w *wsConn) getReader() (io.Reader, error) {
	if w.reader != nil {
		return w.reader, nil
	}

	_, reader, err := w.Conn.NextReader()
	if err != nil {
		return nil, err
	}
	w.reader = reader
	return reader, nil
}

func (w *wsConn) SetDeadline(t time.Time) error {
	err := w.Conn.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return w.Conn.SetWriteDeadline(t)
}
