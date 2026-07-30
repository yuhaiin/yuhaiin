package yuubinsya

import (
	"bytes"
	"crypto/sha256"
	"net"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/pool"
)

func TestDecodeHeaderWithAuthReturnsMatchedCredential(t *testing.T) {
	password := bytes.Repeat([]byte{0x42}, sha256.Size)
	buf := pool.NewBufferSize(256)
	EncodeHeader(password, Header{Protocol: TCP, Addr: netapi.ParseIPAddr("tcp", net.ParseIP("127.0.0.1"), 443)}, buf)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write(buf.Bytes())
	}()

	conn := pool.NewBufioConnSize(server, 1024)
	got, matched, err := DecodeHeaderWithAuth(func(candidate []byte) bool {
		return bytes.Equal(candidate, password)
	}, conn)
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != TCP || got.Addr == nil || !bytes.Equal(matched, password) {
		t.Fatalf("decoded header = %+v, matched=%x", got, matched)
	}
}

func TestDecodeHeaderWithAuthRejectsWrongCredential(t *testing.T) {
	password := bytes.Repeat([]byte{0x42}, sha256.Size)
	buf := pool.NewBufferSize(256)
	EncodeHeader(password, Header{Protocol: TCP, Addr: netapi.ParseIPAddr("tcp", net.ParseIP("127.0.0.1"), 443)}, buf)

	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write(buf.Bytes())
	}()

	conn := pool.NewBufioConnSize(server, 1024)
	_, _, err := DecodeHeaderWithAuth(func(candidate []byte) bool {
		return bytes.Equal(candidate, bytes.Repeat([]byte{0x24}, sha256.Size))
	}, conn)
	if err == nil {
		t.Fatal("wrong credential was accepted")
	}
}
