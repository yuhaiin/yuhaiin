package masque

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"time"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/quic-go/quic-go/http3"
)

const (
	ApiUrl      = "https://api.cloudflareclient.com"
	ApiVersion  = "v0a4471"
	ConnectSNI  = "consumer-masque.cloudflareclient.com"
	ConnectSNI2 = "masque.cloudflareclient.com"
	// unused for now
	ZeroTierSNI   = "zt-masque.cloudflareclient.com"
	ConnectURI    = "https://cloudflareaccess.com"
	DefaultModel  = "PC"
	KeyTypeWg     = "curve25519"
	TunTypeWg     = "wireguard"
	KeyTypeMasque = "secp256r1"
	TunTypeMasque = "masque"
	DefaultLocale = "en_US"
)

var Headers = map[string]string{
	"User-Agent":        "WARP for Android",
	"CF-Client-Version": "a-6.35-4471",
	"Content-Type":      "application/json; charset=UTF-8",
	"Connection":        "Keep-Alive",
}

func PrepareTlsConfig(privKey *ecdsa.PrivateKey, peerPubKey *ecdsa.PublicKey, cert [][]byte, sni string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{
			{
				Certificate: cert,
				PrivateKey:  privKey,
			},
		},
		ServerName: sni,
		NextProtos: []string{http3.NextProtoH3},
		// WARN: SNI is usually not for the endpoint, so we must skip verification
		InsecureSkipVerify: true,
		// Cloudflare's SNI does not match the pinned endpoint certificate.
		// Verify the leaf's public key; rejecting an absent leaf is essential
		// when standard certificate chain verification is disabled.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("masque: peer did not present a certificate")
			}
			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("masque: parse peer certificate: %w", err)
			}
			key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
			if !ok {
				return x509.ErrUnsupportedAlgorithm
			}
			if !key.Equal(peerPubKey) {
				return x509.CertificateInvalidError{
					Cert: leaf, Reason: x509.NotAuthorizedToSign,
					Detail: "MASQUE endpoint certificate does not match the configured public key",
				}
			}
			return nil
		},
	}

	// The self-issued client certificate only lasts one day. Generate a fresh
	// certificate at each TLS handshake so an unattended proxy can reconnect
	// after running for more than 24 hours.
	tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		certs, err := GenerateCert(privKey, &privKey.PublicKey)
		if err != nil {
			return nil, err
		}
		return &tls.Certificate{Certificate: certs, PrivateKey: privKey}, nil
	}

	return tlsConfig, nil
}

func GenerateCert(privKey *ecdsa.PrivateKey, pubKey *ecdsa.PublicKey) ([][]byte, error) {
	cert, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * 24 * time.Hour),
	}, &x509.Certificate{}, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, err
	}

	return [][]byte{cert}, nil
}

func init() {
	register.RegisterContractPoint("cloudflare_warp_masque", func(config contractnode.CloudflareWarpMasque, p netapi.Proxy) (netapi.Proxy, error) {
		return NewCloudflareWarpMasque(Config{
			PrivateKey:        config.PrivateKey,
			Endpoint:          config.Endpoint,
			EndpointPublicKey: config.EndpointPublicKey,
			LocalAddresses:    config.LocalAddresses,
			MTU:               config.MTU,
		}, p)
	})
}

type Config struct {
	PrivateKey        string   `json:"private_key"`
	Endpoint          string   `json:"endpoint"`
	EndpointPublicKey string   `json:"endpoint_public_key"`
	LocalAddresses    []string `json:"local_addresses,omitzero"`
	MTU               int32    `json:"mtu,omitzero"`
}

func NewCloudflareWarpMasque(o Config, p netapi.Proxy) (netapi.Proxy, error) {
	localAddresses, err := wireguard.ParseEndpoints(o.LocalAddresses)
	if err != nil {
		return nil, err
	}

	udpAddr, err := netip.ParseAddrPort(o.Endpoint)
	if err != nil {
		addr, er := netip.ParseAddr(o.Endpoint)
		if er != nil {
			return nil, fmt.Errorf("failed to parse endpoint: %v", err)
		}

		udpAddr = netip.AddrPortFrom(addr, 443)
	}

	privKeyB64, err := base64.StdEncoding.DecodeString(o.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	privKey, err := x509.ParseECPrivateKey(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	endpointPubKeyB64, _ := pem.Decode([]byte(o.EndpointPublicKey))
	if endpointPubKeyB64 == nil {
		return nil, fmt.Errorf("failed to decode endpoint public key")
	}

	pubKey, err := x509.ParsePKIXPublicKey(endpointPubKeyB64.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	ecPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("failed to assert public key as ECDSA")
	}

	cert, err := GenerateCert(privKey, ecPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate cert: %v", err)
	}

	tlsConfig, err := PrepareTlsConfig(privKey, ecPubKey, cert, ConnectSNI2)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare tls config: %v", err)
	}

	if o.MTU == 0 {
		o.MTU = 1280
	}
	if o.MTU < 1280 {
		return nil, fmt.Errorf("invalid MASQUE MTU %d: minimum is 1280", o.MTU)
	}

	return NewMasque(p, tlsConfig, net.UDPAddrFromAddrPort(udpAddr), localAddresses, int(o.MTU))
}
