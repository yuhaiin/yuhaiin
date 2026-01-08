package reality

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
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
	"math/rand/v2"
	"net"
	"net/http"
	"reflect"
	"strings"
	"unsafe"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type Client struct {
	netapi.EmptyDispatch
	proxy         netapi.Proxy
	utls          *utls.Config
	publicKey     []byte
	mldsa65verify []byte
	shortID       [8]byte

	// TODO: remove debug log
	Deubg bool
}

func init() {
	register.RegisterPoint(NewClient)
}

func NewClient(config *node.Reality, p netapi.Proxy) (netapi.Proxy, error) {
	publicKey, err := base64.RawURLEncoding.DecodeString(config.GetPublicKey())
	if err != nil {
		return nil, fmt.Errorf("decode public_key failed: %w", err)
	}
	if len(publicKey) != 32 {
		return nil, fmt.Errorf("invalid public_key")
	}

	var mldsa65Verify []byte
	if config.GetMldsa65Verify() != "" {
		mldsa65Verify, err = base64.RawURLEncoding.DecodeString(config.GetMldsa65Verify())
		if err != nil || len(mldsa65Verify) != 1952 {
			return nil, fmt.Errorf(`invalid "mldsa65Verify": %s`, config.GetMldsa65Verify())
		}
	}

	var shortID [8]byte
	decodedLen, err := hex.Decode(shortID[:], []byte(config.GetShortId()))
	if err != nil {
		return nil, fmt.Errorf("decode short_id failed: %w", err)
	}
	if decodedLen > 8 {
		return nil, fmt.Errorf("invalid short_id")
	}
	return &Client{
		proxy: p,
		utls: &utls.Config{
			ServerName:             config.GetServerName(),
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
		},
		publicKey:     publicKey,
		mldsa65verify: mldsa65Verify,
		shortID:       shortID,
		Deubg:         config.GetDebug(),
	}, nil
}

func (e *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	con, err := e.proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	conn, err := e.ClientHandshake(ctx, con)
	if err != nil {
		con.Close()
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	return conn, nil
}

func (e *Client) PacketConn(ctx context.Context, addr netapi.Address) (net.PacketConn, error) {
	return e.proxy.PacketConn(ctx, addr)
}

func (e *Client) Ping(ctx context.Context, addr netapi.Address) (uint64, error) {
	return e.proxy.Ping(ctx, addr)
}

func (e *Client) Close() error { return e.proxy.Close() }

func (e *Client) ClientHandshake(ctx context.Context, conn net.Conn) (net.Conn, error) {
	verifier := &realityVerifier{
		serverName:    e.utls.ServerName,
		mldsa65verify: e.mldsa65verify,
	}

	uConfig := e.utls.Clone()
	uConfig.VerifyPeerCertificate = verifier.VerifyPeerCertificate
	uConn := utls.UClient(conn, uConfig, utls.HelloChrome_Auto)
	verifier.UConn = uConn
	err := uConn.BuildHandshakeState()
	if err != nil {
		return nil, err
	}

	hello := uConn.HandshakeState.Hello
	hello.SessionId = make([]byte, 32)
	copy(hello.Raw[39:], hello.SessionId)
	hello.SessionId[0] = 25
	hello.SessionId[1] = 7
	hello.SessionId[2] = 23
	hello.SessionId[3] = 0
	binary.BigEndian.PutUint32(hello.SessionId[4:], uint32(system.NowUnix()))
	copy(hello.SessionId[8:], e.shortID[:])

	if e.Deubg {
		log.Debug("REALITY", "hello.sessionId[:16]", hello.SessionId[:16])
	}

	ecdhe := uConn.HandshakeState.State13.KeyShareKeys.Ecdhe
	if ecdhe == nil {
		ecdhe = uConn.HandshakeState.State13.KeyShareKeys.MlkemEcdhe
	}
	if ecdhe == nil {
		return nil, fmt.Errorf("current fingerprint %s %s does not support TLS 1.3, REALITY handshake cannot establish", uConn.ClientHelloID.Client, uConn.ClientHelloID.Version)
	}

	peerKey, err := ecdhe.Curve().NewPublicKey(e.publicKey)
	if err != nil {
		return nil, fmt.Errorf("new ecdhe public key failed: %w", err)
	}

	authKey, err := ecdhe.ECDH(peerKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh key failed: %w", err)
	}

	prt, err := hkdf.Extract(sha256.New, authKey, hello.Random[:20])
	if err != nil {
		return nil, err
	}

	authKey, err = hkdf.Expand(sha256.New, prt, "REALITY", len(authKey))
	if err != nil {
		return nil, err
	}

	verifier.authKey = authKey

	block, _ := aes.NewCipher(authKey)
	aead, _ := cipher.NewGCM(block)

	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
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
	request.AddCookie(&http.Cookie{Name: "padding", Value: strings.Repeat("0", rand.IntN(32)+30)})
	response, err := client.Do(request)
	if err != nil {
		return
	}
	_, _ = relay.Copy(io.Discard, response.Body)
	response.Body.Close()
}

type realityVerifier struct {
	*utls.UConn
	serverName    string
	authKey       []byte
	mldsa65verify []byte
	verified      bool
}

func (c *realityVerifier) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	p, _ := reflect.TypeOf(c.Conn).Elem().FieldByName("peerCertificates")
	certs := *(*([]*x509.Certificate))(unsafe.Pointer(uintptr(unsafe.Pointer(c.Conn)) + p.Offset))
	if pub, ok := certs[0].PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		h.Write(pub)
		if bytes.Equal(h.Sum(nil), certs[0].Signature) {
			if len(c.mldsa65verify) > 0 {
				if len(certs[0].Extensions) > 0 {
					h.Write(c.HandshakeState.Hello.Raw)
					h.Write(c.HandshakeState.ServerHello.Raw)
					verify, _ := mldsa65.Scheme().UnmarshalBinaryPublicKey(c.mldsa65verify)
					if mldsa65.Verify(verify.(*mldsa65.PublicKey), h.Sum(nil), nil, certs[0].Extensions[0].Value) {
						c.verified = true
						return nil
					}
				}
			} else {
				c.verified = true
				return nil
			}
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
