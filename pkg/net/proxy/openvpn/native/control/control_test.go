// Adapted from xen0bit/veepin (MIT). See ../THIRD_PARTY_LICENSE.
package control

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"testing"
	"time"
)

// link joins two control channels over an in-memory datagram path, optionally
// dropping the first delivery of chosen packets to force retransmission. It owns
// both endpoints under its lock so the pump goroutines and the test goroutine
// never race on the *Channel values.
type link struct {
	mu             sync.Mutex
	count          int
	dropNums       map[int]bool // 1-based global packet numbers to drop once
	client, server *Channel
}

func (l *link) setEnds(client, server *Channel) {
	l.mu.Lock()
	l.client, l.server = client, server
	l.mu.Unlock()
}

// deliver routes one datagram to an endpoint, dropping it if it is a scheduled
// drop or the destination is not wired up yet (an early hard reset before both
// ends exist — retransmission recovers it).
func (l *link) deliver(toServer bool, b []byte) {
	l.mu.Lock()
	l.count++
	drop := l.dropNums[l.count]
	if drop {
		delete(l.dropNums, l.count)
	}
	dst := l.client
	if toServer {
		dst = l.server
	}
	l.mu.Unlock()
	if drop || dst == nil {
		return
	}
	dst.Deliver(append([]byte(nil), b...))
}

func (l *link) toServer() func([]byte) error {
	return func(b []byte) error { l.deliver(true, b); return nil }
}

func (l *link) toClient() func([]byte) error {
	return func(b []byte) error { l.deliver(false, b); return nil }
}

// testCert makes a throwaway self-signed certificate for the TLS server side.
func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// runHandshake stands up a client and server Channel over l, runs a TLS
// handshake across them, and exchanges one application message each way.
func runHandshake(t *testing.T, l *link, timeout time.Duration) {
	t.Helper()

	client, err := New(l.toServer(), 0, timeout, nil)
	if err != nil {
		t.Fatal(err)
	}
	server, err := New(l.toClient(), 0, timeout, nil)
	if err != nil {
		t.Fatal(err)
	}
	l.setEnds(client, server)
	defer client.Close()
	defer server.Close()

	cert := testCert(t)
	serverDone := make(chan error, 1)
	go func() {
		tlsSrv := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}})
		if err := tlsSrv.Handshake(); err != nil {
			serverDone <- err
			return
		}
		buf := make([]byte, 64)
		n, err := tlsSrv.Read(buf)
		if err != nil {
			serverDone <- err
			return
		}
		if _, err := tlsSrv.Write(buf[:n]); err != nil { // echo
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	tlsCli := tls.Client(client, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test transport, cert verification is exercised elsewhere
	deadline := time.Now().Add(15 * time.Second)
	_ = client.SetDeadline(deadline)
	if err := tlsCli.Handshake(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	_ = client.SetDeadline(time.Time{})

	msg := []byte("hello over the control channel")
	if _, err := tlsCli.Write(msg); err != nil {
		t.Fatalf("client write: %v", err)
	}
	buf := make([]byte, 64)
	n, err := tlsCli.Read(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	if string(buf[:n]) != string(msg) {
		t.Fatalf("echo = %q, want %q", buf[:n], msg)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("server side: %v", err)
	}
}

// TestControlChannelCarriesTLS proves the whole control stack — hard reset,
// reliable ordering, session IDs, and the net.Conn — carries a real TLS
// handshake and application data over the lossless in-memory path.
func TestControlChannelCarriesTLS(t *testing.T) {
	l := &link{dropNums: map[int]bool{}}
	runHandshake(t, l, 100*time.Millisecond)
}

// TestControlChannelRecoversFromLoss drops several early datagrams so the
// handshake only completes if retransmission and reordering work end to end.
func TestControlChannelRecoversFromLoss(t *testing.T) {
	l := &link{dropNums: map[int]bool{1: true, 3: true, 4: true, 8: true}}
	runHandshake(t, l, 80*time.Millisecond)
}

func TestSessionIDsExchanged(t *testing.T) {
	l := &link{dropNums: map[int]bool{}}
	client, _ := New(l.toServer(), 0, 50*time.Millisecond, nil)
	server, _ := New(l.toClient(), 0, 50*time.Millisecond, nil)
	l.setEnds(client, server)
	defer client.Close()
	defer server.Close()

	// Drive one exchange so the hard resets cross.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rs, ok := client.RemoteSessionID(); ok && rs == server.LocalSessionID() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("client never learned the server session ID")
}
