package masque

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/wireguard"
	"github.com/Asutorufa/yuhaiin/pkg/protos/node"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/quic-go/quic-go/http3"
)

const (
	ApiUrl     = "https://api.cloudflareclient.com"
	ApiVersion = "v0a4471"
	ConnectSNI = "consumer-masque.cloudflareclient.com"
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
		// we pin to the endpoint public key
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return nil
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return err
			}

			if _, ok := cert.PublicKey.(*ecdsa.PublicKey); !ok {
				// we only support ECDSA
				// TODO: don't hardcode cert type in the future
				// as backend can start using different cert types
				return x509.ErrUnsupportedAlgorithm
			}

			if !cert.PublicKey.(*ecdsa.PublicKey).Equal(peerPubKey) {
				// reason is incorrect, but the best I could figure
				// detail explains the actual reason

				//10 is NoValidChains, but we support go1.22 where it's not defined
				return x509.CertificateInvalidError{Cert: cert, Reason: 10, Detail: "remote endpoint has a different public key than what we trust in config.json"}
			}

			return nil
		},
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
	register.RegisterPoint(NewCloudflareWarpMasque)
}

func NewCloudflareWarpMasque(o *node.CloudflareWarpMasque, p netapi.Proxy) (netapi.Proxy, error) {
	localAddresses, err := wireguard.ParseEndpoints(o.GetLocalAddresses())
	if err != nil {
		return nil, err
	}

	udpAddr, err := netip.ParseAddrPort(o.GetEndpoint())
	if err != nil {
		addr, er := netip.ParseAddr(o.GetEndpoint())
		if er != nil {
			return nil, fmt.Errorf("failed to parse endpoint: %v", err)
		}

		udpAddr = netip.AddrPortFrom(addr, 443)
	}

	privKeyB64, err := base64.StdEncoding.DecodeString(o.GetPrivateKey())
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %v", err)
	}

	privKey, err := x509.ParseECPrivateKey(privKeyB64)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	endpointPubKeyB64, _ := pem.Decode([]byte(o.GetEndpointPublicKey()))
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

	tlsConfig, err := PrepareTlsConfig(privKey, ecPubKey, cert, ConnectSNI)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare tls config: %v", err)
	}

	if o.GetMtu() == 0 {
		o.SetMtu(1280)
	}

	return NewMasque(p, tlsConfig, net.UDPAddrFromAddrPort(udpAddr), localAddresses, int(o.GetMtu()))
}
