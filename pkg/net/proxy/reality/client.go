package reality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	mRand "math/rand"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	proxy "github.com/Asutorufa/yuhaiin/pkg/net/interfaces"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node/protocol"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/net/http2"
)

type RealityClient struct {
	proxy.EmptyDispatch
	proxy     proxy.Proxy
	utls      *utls.Config
	publicKey []byte
	shortID   [8]byte

	// TODO: remove debug log
	Deubg bool
}

func NewRealityClient(config *protocol.Protocol_Reality) protocol.WrapProxy {
	return func(p proxy.Proxy) (proxy.Proxy, error) {
		publicKey, err := base64.RawURLEncoding.DecodeString(config.Reality.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("decode public_key failed: %w", err)
		}
		if len(publicKey) != 32 {
			return nil, fmt.Errorf("invalid public_key")
		}
		var shortID [8]byte
		decodedLen, err := hex.Decode(shortID[:], []byte(config.Reality.ShortId))
		if err != nil {
			return nil, fmt.Errorf("decode short_id failed: %w", err)
		}
		if decodedLen > 8 {
			return nil, fmt.Errorf("invalid short_id")
		}
		return &RealityClient{
			proxy: p,
			utls: &utls.Config{
				ServerName: config.Reality.ServerName,
			},
			publicKey: publicKey,
			shortID:   shortID,
			Deubg:     config.Reality.Debug,
		}, nil
	}
}

func (e *RealityClient) Conn(ctx context.Context, addr proxy.Address) (net.Conn, error) {
	con, err := e.proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	conn, err := e.ClientHandshake(ctx, con)
	if err != nil {
		con.Close()
		return nil, err
	}

	return conn, nil
}

func (e *RealityClient) PacketConn(ctx context.Context, addr proxy.Address) (net.PacketConn, error) {
	return e.proxy.PacketConn(ctx, addr)
}

func (e *RealityClient) ClientHandshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	verifier := &realityVerifier{
		serverName: e.utls.ServerName,
	}
	uConfig := e.utls.Clone()
	uConfig.InsecureSkipVerify = true
	uConfig.SessionTicketsDisabled = true
	uConfig.VerifyPeerCertificate = verifier.VerifyPeerCertificate
	uConn := utls.UClient(conn, uConfig, utls.HelloChrome_Auto)
	verifier.UConn = uConn
	err := uConn.BuildHandshakeState()
	if err != nil {
		return nil, err
	}

	if len(uConfig.NextProtos) > 0 {
		for _, extension := range uConn.Extensions {
			if alpnExtension, isALPN := extension.(*utls.ALPNExtension); isALPN {
				alpnExtension.AlpnProtocols = uConfig.NextProtos
				break
			}
		}
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)

	var nowTime time.Time
	if uConfig.Time != nil {
		nowTime = uConfig.Time()
	} else {
		nowTime = time.Now()
	}
	binary.BigEndian.PutUint64(hello.SessionId, uint64(nowTime.Unix()))

	hello.SessionId[0] = 1
	hello.SessionId[1] = 8
	hello.SessionId[2] = 1
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(time.Now().Unix()))
	copy(hello.SessionId[8:], e.shortID[:])

	if e.Deubg {
		log.Debug("REALITY", "hello.sessionId[:16]", hello.SessionId[:16])
	}

	peerKey, err := uConn.HandshakeState.State13.EcdheKey.Curve().NewPublicKey(e.publicKey)
	if err != nil {
		return nil, fmt.Errorf("new ecdhe public key failed: %w", err)
	}
	authKey, err := uConn.HandshakeState.State13.EcdheKey.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh key failed: %w", err)
	}
	verifier.authKey = authKey
	_, err = hkdf.New(sha256.New, authKey, hello.Random[:20], []byte("REALITY")).Read(authKey)
	if err != nil {
		return nil, err
	}
	aesBlock, _ := aes.NewCipher(authKey)
	aesGcmCipher, _ := cipher.NewGCM(aesBlock)
	aesGcmCipher.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	if e.Deubg {
		log.Debug("REALITY", "hello.sessionId", hello.SessionId)
		log.Debug("REALITY", "uConn.AuthKey", authKey)
	}

	err = uConn.HandshakeContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	if e.Deubg {
		log.Debug("REALITY", "Conn.Verified", verifier.verified)
	}

	if !verifier.verified {
		go realityClientFallback(uConn, e.utls.ServerName, utls.HelloChrome_Auto)
		return nil, fmt.Errorf("reality verification failed")
	}

	return uConn, nil
}

func realityClientFallback(uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	client := &http.Client{
		Transport: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, config *tls.Config) (net.Conn, error) {
				return uConn, nil
			},
		},
	}
	request, _ := http.NewRequest("GET", "https://"+serverName, nil)
	request.Header.Set("User-Agent", fingerprint.Client)
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", mRand.Intn(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
}

type realityVerifier struct {
	*utls.UConn
	serverName string
	authKey    []byte
	verified   bool
}

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	p, _ := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(c.Conn)) + p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			c.verified = true
			return nil
		}
	}
	opts := x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: x509.NewCertPool(),
	}
	for _, cert := range certs[1:] {
		opts.Intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(opts); err != nil {
		return err
	}
	return nil
}
