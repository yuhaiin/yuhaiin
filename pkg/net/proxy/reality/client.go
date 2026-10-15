package reality

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/relay"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
	utls "github.com/refraction-networking/utls"
)

var errRealityVerificationFailed = errors.New("reality verification failed")

type Client struct {
	netapi.EmptyDispatch
	proxy         netapi.Proxy
	utls          *utls.Config
	publicKey     *ecdh.PublicKey
	mldsa65verify *mldsa.PublicKey
	shortID       [8]byte

	// TODO: remove debug log
	Deubg bool
}

func init() {
	register.RegisterContractPoint("reality", func(config contractnode.Reality, p netapi.Proxy) (netapi.Proxy, error) {
		return NewClient(Config{
			ServerName:    config.ServerName,
			PublicKey:     config.PublicKey,
			MLDSA65Verify: config.MLDSA65Verify,
			ShortID:       config.ShortID,
			Debug:         config.Debug,
		}, p)
	})
}

type Config struct {
	ServerName    string `json:"server_name"`
	PublicKey     string `json:"public_key"`
	MLDSA65Verify string `json:"mldsa65_verify"`
	ShortID       string `json:"short_id"`
	Debug         bool   `json:"debug"`
}

func NewClient(config Config, p netapi.Proxy) (netapi.Proxy, error) {
	decodedPublicKey, err := base64.RawURLEncoding.DecodeString(config.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode public_key failed: %w", err)
	}
	publicKey, err := ecdh.X25519().NewPublicKey(decodedPublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid public_key: %w", err)
	}

	var mldsa65Verify *mldsa.PublicKey
	if config.MLDSA65Verify != "" {
		encodedKey, err := base64.RawURLEncoding.DecodeString(config.MLDSA65Verify)
		if err != nil {
			return nil, fmt.Errorf("decode mldsa65_verify: %w", err)
		}
		mldsa65Verify, err = mldsa.NewPublicKey(mldsa.MLDSA65(), encodedKey)
		if err != nil {
			return nil, fmt.Errorf("invalid mldsa65_verify: %w", err)
		}
	}

	var shortID [8]byte
	decodedLen, err := hex.Decode(shortID[:], []byte(config.ShortID))
	if err != nil {
		return nil, fmt.Errorf("decode short_id failed: %w", err)
	}
	if decodedLen > 8 {
		return nil, fmt.Errorf("invalid short_id")
	}
	return &Client{
		proxy: p,
		utls: &utls.Config{
			ServerName:             config.ServerName,
			InsecureSkipVerify:     true,
			SessionTicketsDisabled: true,
		},
		publicKey:     publicKey,
		mldsa65verify: mldsa65Verify,
		shortID:       shortID,
		Deubg:         config.Debug,
	}, nil
}

func (e *Client) Conn(ctx context.Context, addr netapi.Address) (net.Conn, error) {
	con, err := e.proxy.Conn(ctx, addr)
	if err != nil {
		return nil, err
	}

	conn, err := e.ClientHandshake(ctx, con)
	if err != nil {
		// A successfully established TLS connection may be used by the
		// background decoy request. In that case, it owns the connection.
		if !errors.Is(err, errRealityVerificationFailed) {
			_ = con.Close()
		}
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
	uConfig.VerifyConnection = verifier.VerifyConnection
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

	authKey, err := ecdhe.ECDH(e.publicKey)
	if err != nil {
		return nil, fmt.Errorf("ecdh key failed: %w", err)
	}

	authKey, err = hkdf.Key(sha256.New, authKey, hello.Random[:20], "REALITY", 32)
	if err != nil {
		return nil, err
	}

	verifier.authKey = authKey

	block, err := aes.NewCipher(authKey)
	if err != nil {
		return nil, fmt.Errorf("create reality cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create reality AEAD: %w", err)
	}

	aead.Seal(hello.SessionId[:0], hello.Random[20:], hello.SessionId[:16], hello.Raw)
	copy(hello.Raw[39:], hello.SessionId)

	if e.Deubg {
		log.Debug("REALITY", "hello.sessionId", hello.SessionId)
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
		return nil, errRealityVerificationFailed
	}

	return uConn, nil
}

func realityClientFallback(uConn net.Conn, serverName string, fingerprint utls.ClientHelloID) {
	defer uConn.Close()
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return uConn, nil
			},
		},
	}
	request, err := http.NewRequest(http.MethodGet, "https://"+serverName, nil)
	if err != nil {
		return
	}
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
	mldsa65verify *mldsa.PublicKey
	verified      bool
}

func (c *realityVerifier) VerifyConnection(state utls.ConnectionState) error {
	// uTLS has already parsed the certificates before calling VerifyConnection.
	// This avoids depending on unexported fields or parsing the chain twice.
	certs := state.PeerCertificates
	if len(certs) == 0 {
		return errors.New("reality: no peer certificates")
	}

	leaf := certs[0]
	if pub, ok := leaf.PublicKey.(ed25519.PublicKey); ok {
		h := hmac.New(sha512.New, c.authKey)
		_, _ = h.Write(pub)
		if hmac.Equal(h.Sum(nil), leaf.Signature) {
			if c.mldsa65verify != nil {
				if len(leaf.Extensions) > 0 {
					_, _ = h.Write(c.HandshakeState.Hello.Raw)
					_, _ = h.Write(c.HandshakeState.ServerHello.Raw)
					if mldsa.Verify(c.mldsa65verify, h.Sum(nil), leaf.Extensions[0].Value, nil) == nil {
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

	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       c.serverName,
		Intermediates: intermediates,
	})
	return err
}
