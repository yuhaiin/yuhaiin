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
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/xtls/reality"
	"golang.org/x/crypto/curve25519"
)

/*
Private key: CKr8-tipwbEwwDa97S3Rwqzs9L8AlcLOCZJah1zjLlw
Public key: SOW7P-17ibm_-kz-QUQwGGyitSbsa5wOmRGAigGvDH8
*/

type ServerConfig struct {
	Dest        string   `json:"dest"`
	ShortID     []string `json:"short_id,omitzero"`
	ServerName  []string `json:"server_name,omitzero"`
	PrivateKey  string   `json:"private_key"`
	MLDSA65Seed string   `json:"mldsa65_seed,omitzero"`
	Debug       bool     `json:"debug,omitzero"`
}

func ShortIDMap(s []string) (map[[8]byte]bool, error) {
	maps := make(map[[8]byte]bool, len(s))

	for _, v := range s {
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

func ServerNameMap(s []string) map[string]bool {
	maps := make(map[string]bool, len(s))

	for _, v := range s {
		maps[v] = true
	}

	return maps
}

func NewServer(config ServerConfig, ii netapi.Listener) (netapi.Listener, error) {
	var ids map[[8]byte]bool
	privateKey, err := base64.RawURLEncoding.DecodeString(config.PrivateKey)
	if err == nil {
		ids, err = ShortIDMap(config.ShortID)
	}
	if err != nil {
		return nil, err
	}

	var mldsa65Key []byte
	if config.MLDSA65Seed != "" {
		mldsa65Seed, err := base64.RawURLEncoding.DecodeString(config.MLDSA65Seed)
		if err != nil || len(mldsa65Seed) != 32 {
			return nil, fmt.Errorf("mldsa65 seed is invalid: %w, %s", err, config.MLDSA65Seed)
		}

		_, key := mldsa65.NewKeyFromSeed((*[32]byte)(mldsa65Seed))
		mldsa65Key = key.Bytes()
	}

	realityConfig := &reality.Config{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			addr, err := netapi.ParseAddress(network, address)
			if err != nil {
				return nil, err
			}
			return dialer.DialHappyEyeballsv2(ctx, addr)
		},
		Show:                   config.Debug,
		Type:                   "tcp",
		ShortIds:               ids,
		ServerNames:            ServerNameMap(config.ServerName),
		Dest:                   config.Dest,
		PrivateKey:             privateKey,
		Mldsa65Key:             mldsa65Key,
		SessionTicketsDisabled: true,
	}

	lis := reality.NewListener(ii, realityConfig)

	return netapi.NewListener(lis, ii), nil
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
