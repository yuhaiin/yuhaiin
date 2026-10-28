package sstp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
    "github.com/Asutorufa/yuhaiin/pkg/net/proxyauth"
    "github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/mschap"
    "crypto/subtle"
    "errors"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/vpnkit/dataplane"
)

type memorySSTPTUN struct {
	closed chan struct{}
	once   sync.Once
}

func (t *memorySSTPTUN) Read([]byte) (int, error) {
	<-t.closed
	return 0, net.ErrClosed
}

func (t *memorySSTPTUN) Write(packet []byte) (int, error) {
	return len(packet), nil
}

func (t *memorySSTPTUN) Close() error {
	t.once.Do(func() { close(t.closed) })
	return nil
}

type sstpTestHandler struct{}

func (sstpTestHandler) HandleStream(stream *netapi.StreamMeta) {
	_ = stream.Src.Close()
}

func (sstpTestHandler) HandlePacket(packet *netapi.Packet) {
	packet.DecRef()
}

func (sstpTestHandler) HandlePing(*netapi.PingMeta) {}

func testSSTPCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func TestRootlessSSTPClientServerHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	server, err := NewServer(ServerConfig{
		ServerAddress:   "10.90.0.1",
		ClientAddresses: []string{"10.90.0.2"},
		Authenticate: func(ctx context.Context, username string, server, peer [16]byte, response [24]byte) (*proxyauth.Identity, [16]byte, error) {
            if username != "alice" { return nil, [16]byte{}, proxyauth.ErrUnauthorized }
            hash := mschap.NTPasswordHash("secret")
            expected := mschap.GenerateNTResponseFromHash(server, peer, username, hash)
            if subtle.ConstantTimeCompare(expected[:], response[:]) != 1 {
                return nil, [16]byte{}, errors.New("unauthorized")
            }
            return &proxyauth.Identity{UserID: "test-user", CredentialID: "test-credential", Context: ctx}, hash, nil
        },
	}, &tls.Config{Certificates: []tls.Certificate{testSSTPCertificate(t)}}, listener, sstpTestHandler{})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	device := &memorySSTPTUN{closed: make(chan struct{})}
	release, err := dataplane.RegisterVirtualTUN("sstp-integration-test", device)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, result, err := Dial(ctx, Config{
		Server:     "127.0.0.1",
		Port:       listener.Addr().(*net.TCPAddr).Port,
		Username:   "alice",
		Password:   "secret",
		TUNName:    "sstp-integration-test",
		SkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if !result.AssignedIP.Equal(net.IPv4(10, 90, 0, 2)) {
		t.Fatalf("assigned IP = %v, want 10.90.0.2", result.AssignedIP)
	}
}
