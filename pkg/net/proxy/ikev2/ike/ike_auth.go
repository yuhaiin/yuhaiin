package ike

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/ikev2/payload"
)

func equalBytes(a, b []byte) bool { return bytes.Equal(a, b) }

func allTrafficV4() payload.TrafficSelector {
	return payload.TrafficSelector{
		Type: payload.TSIPv4AddrRange, EndPort: 65535,
		StartAddr: net.IP{0, 0, 0, 0}, EndAddr: net.IP{255, 255, 255, 255},
	}
}

func allTrafficV6() payload.TrafficSelector {
	return payload.TrafficSelector{
		Type: payload.TSIPv6AddrRange, EndPort: 65535,
		StartAddr: net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		EndAddr:   net.IP{255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255},
	}
}

func findInner(inners []payload.RawPayload, t payload.PayloadType) *payload.RawPayload {
	for i := range inners {
		if inners[i].Type == t {
			return &inners[i]
		}
	}
	return nil
}

func findAllInner(inners []payload.RawPayload, t payload.PayloadType) []payload.RawPayload {
	var out []payload.RawPayload
	for i := range inners {
		if inners[i].Type == t {
			out = append(out, inners[i])
		}
	}
	return out
}

func parseCertChain(certs []payload.RawPayload) (leafDER []byte, intermediates [][]byte, err error) {
	for i, cp := range certs {
		cert, err := payload.ParseCert(cp.Body)
		if err != nil {
			return nil, nil, err
		}
		if cert.Encoding != payload.CertX509Signature {
			return nil, nil, fmt.Errorf("ike: unsupported certificate encoding %d", cert.Encoding)
		}
		if i == 0 {
			leafDER = cert.Data
		} else {
			intermediates = append(intermediates, cert.Data)
		}
	}
	if len(leafDER) == 0 {
		return nil, nil, fmt.Errorf("ike: empty certificate payload")
	}
	return leafDER, intermediates, nil
}

func beU32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func u32BE(v uint32) []byte {
	return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}
}

func u64BE(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func beU64(b []byte) uint64 { return binary.BigEndian.Uint64(b) }
