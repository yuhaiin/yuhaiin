package reality

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/Asutorufa/yuhaiin/pkg/register"
	"github.com/xtls/reality"
	"golang.org/x/crypto/curve25519"
)

/*
Private key: CKr8-tipwbEwwDa97S3Rwqzs9L8AlcLOCZJah1zjLlw
Public key: SOW7P-17ibm_-kz-QUQwGGyitSbsa5wOmRGAigGvDH8
*/

func ShortIDMap(s *listener.Reality) (map[[8]byte]bool, error) {
	maps := make(map[[8]byte]bool, len(s.GetShortId()))

	for _, v := range s.GetShortId() {
		var id [8]byte
		length, err := hex.Decode(id[:], []byte(v))
		if err != nil {
			return nil, fmt.Errorf("decode hex failed: %w", err)
		}

		if length > 8 {
			return nil, fmt.Errorf("short id length is large than 8")
		}

		maps[id] = true
	}

	return maps, nil
}

func ServerNameMap(s *listener.Reality) map[string]bool {
	maps := make(map[string]bool, len(s.GetServerName()))

	for _, v := range s.GetServerName() {
		maps[v] = true
	}

	return maps
}

func NewServer(config *listener.Reality, ii netapi.Listener) (netapi.Listener, error) {
	var ids map[[8]byte]bool
	privateKey, err := base64.RawURLEncoding.DecodeString(config.GetPrivateKey())
	if err == nil {
		ids, err = ShortIDMap(config)
	}
	if err != nil {
		return nil, err
	}

	realityConfig := &reality.Config{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			addr, err := netapi.ParseAddress(network, address)
			if err != nil {
				return nil, err
			}
			return dialer.DialHappyEyeballsv2(ctx, addr)
		},
		Show:                   config.GetDebug(),
		Type:                   "tcp",
		ShortIds:               ids,
		ServerNames:            ServerNameMap(config),
		Dest:                   config.GetDest(),
		PrivateKey:             privateKey,
		SessionTicketsDisabled: true,
	}

	lis := reality.NewListener(ii, realityConfig)

	return netapi.NewListener(lis, ii), nil
}

func init() {
	register.RegisterTransport(NewServer)
}

func GenerateKey() (string, string, error) {
	privateKey := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(privateKey); err != nil {
		return "", "", err
	}

	// Modify random bytes using algorithm described at:
	// https://cr.yp.to/ecdh.html.
	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}

	return base64.RawURLEncoding.EncodeToString(privateKey), base64.RawURLEncoding.EncodeToString(publicKey), nil
}
