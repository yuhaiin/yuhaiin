package aead

import (
	"net"
	"testing"
)

func TestHandshakeServerMultiAcceptsNonFirstCredential(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	client := NewHandshaker(false, []byte("second-password"), CryptoMethodChacha20Poly1305)
	servers := []*encryptedHandshaker{
		NewHandshaker(true, []byte("first-password"), CryptoMethodChacha20Poly1305),
		NewHandshaker(true, []byte("second-password"), CryptoMethodChacha20Poly1305),
	}
	clientResult := make(chan error, 1)
	go func() {
		_, err := client.Handshake(clientConn)
		clientResult <- err
	}()

	serverResult, err := handshakeServerMulti(serverConn, servers)
	if err != nil {
		t.Fatal(err)
	}
	serverResult.Close()
	if err := <-clientResult; err != nil {
		t.Fatal(err)
	}
}
