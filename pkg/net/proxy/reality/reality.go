package reality

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/protos/config/listener"
	"github.com/xtls/reality"
)

/*
Private key: CKr8-tipwbEwwDa97S3Rwqzs9L8AlcLOCZJah1zjLlw
Public key: SOW7P-17ibm_-kz-QUQwGGyitSbsa5wOmRGAigGvDH8
*/

func ShortIDMap(s *listener.Transport_Reality) (map[[8]byte]bool, error) {
	maps := make(map[[8]byte]bool, len(s.Reality.ShortId))

	for _, v := range s.Reality.ShortId {
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

func ServerNameMap(s *listener.Transport_Reality) map[string]bool {
	maps := make(map[string]bool, len(s.Reality.ServerName))

	for _, v := range s.Reality.ServerName {
		maps[v] = true
	}

	return maps
}

func NewServer(config *listener.Transport_Reality) func(netapi.Listener) (netapi.Listener, error) {
	privateKey, err := base64.RawURLEncoding.DecodeString(config.Reality.PrivateKey)
	if err != nil {
		return listener.ErrorTransportFunc(err)
	}

	ids, err := ShortIDMap(config)
	if err != nil {
		return listener.ErrorTransportFunc(err)
	}

	return func(ii netapi.Listener) (netapi.Listener, error) {
		lis, err := ii.Stream(context.TODO())
		if err != nil {
			return nil, err
		}

		config := &reality.Config{
			DialContext:            dialer.DialContext,
			Show:                   config.Reality.Debug,
			Type:                   "tcp",
			ShortIds:               ids,
			ServerNames:            ServerNameMap(config),
			Dest:                   config.Reality.Dest,
			PrivateKey:             privateKey,
			SessionTicketsDisabled: true,
		}

		lis = reality.NewListener(lis, config)

		return netapi.NewListener(lis, ii), nil

	}
}

func init() {
	listener.RegisterTransport(NewServer)
}
