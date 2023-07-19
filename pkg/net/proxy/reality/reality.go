package reality

import (
	"encoding/hex"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/dialer"
	"github.com/xtls/reality"
)

type Server struct {
	net.Listener
}

/*
Private key: CKr8-tipwbEwwDa97S3Rwqzs9L8AlcLOCZJah1zjLlw
Public key: SOW7P-17ibm_-kz-QUQwGGyitSbsa5wOmRGAigGvDH8
*/

type ServerConfig struct {
	ShortID     []string // "0123456789abcdef", ""
	ServerNames []string
	Dest        string
	PrivateKey  []byte
	Debug       bool
}

func (s *ServerConfig) ShortIDMap() (map[[8]byte]bool, error) {
	maps := make(map[[8]byte]bool, len(s.ShortID))

	for _, v := range s.ShortID {
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

func (s *ServerConfig) ServerNameMap() map[string]bool {
	maps := make(map[string]bool, len(s.ServerNames))

	for _, v := range s.ServerNames {
		maps[v] = true
	}

	return maps
}

func NewServer(lis net.Listener, config ServerConfig) (*Server, error) {
	ids, err := config.ShortIDMap()
	if err != nil {
		return nil, err
	}

	return &Server{
		reality.NewListener(lis, &reality.Config{
			DialContext:            dialer.DialContext,
			Show:                   config.Debug,
			Type:                   "tcp",
			ShortIds:               ids,
			ServerNames:            config.ServerNameMap(),
			Dest:                   config.Dest,
			PrivateKey:             config.PrivateKey,
			SessionTicketsDisabled: true,
		}),
	}, nil
}
