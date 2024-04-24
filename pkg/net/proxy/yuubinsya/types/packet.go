package types

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"net"

	"github.com/Asutorufa/yuhaiin/pkg/net/netapi"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/socks5/tools"
	"github.com/Asutorufa/yuhaiin/pkg/protos/statistic"
)

func EncodePacket(w PacketBuffer, addr net.Addr, buf []byte, auth Auth, prefix bool) error {
	ad, err := netapi.ParseSysAddr(addr)
	if err != nil {
		return fmt.Errorf("parse addr failed: %w", err)
	}

	if auth != nil {
		if auth.NonceSize() > 0 {
			w.Advance(auth.NonceSize())

			_, err = rand.Read(w.Bytes())
			if err != nil {
				return err
			}
		}

		if auth.KeySize() > 0 {
			_, err = w.Write(auth.Key())
			if err != nil {
				return err
			}
		}
	}

	if prefix {
		_, err = w.Write([]byte{0, 0, 0})
		if err != nil {
			return err
		}
	}

	tools.EncodeAddr(ad, w)

	_, err = w.Write(buf)
	if err != nil {
		return err
	}

	if auth == nil {
		return nil
	}

	w.Advance(auth.Overhead())

	if auth.NonceSize() > 0 {
		nonce := w.Bytes()[:auth.NonceSize()]
		data := w.Bytes()[auth.NonceSize() : w.Len()-auth.Overhead()]
		cryptext := w.Bytes()[auth.NonceSize():]

		auth.Seal(cryptext[:0], nonce, data, nil)
	}

	return nil
}

func DecodePacket(r []byte, auth Auth, prefix bool) ([]byte, netapi.Address, error) {
	if auth != nil {
		if auth.NonceSize() > 0 {
			if len(r) < auth.NonceSize() {
				return nil, nil, fmt.Errorf("nonce is not enough")
			}

			nonce := r[:auth.NonceSize()]
			cryptext := r[auth.NonceSize():]
			r = r[auth.NonceSize() : len(r)-auth.Overhead()]

			_, err := auth.Open(r[:0], nonce, cryptext, nil)
			if err != nil {
				return nil, nil, err
			}
		}

		if auth.KeySize() > 0 {
			if len(r) < auth.KeySize() {
				return nil, nil, fmt.Errorf("key is not enough")
			}

			rkey := r[:auth.KeySize()]
			r = r[auth.KeySize():]

			if subtle.ConstantTimeCompare(rkey, auth.Key()) == 0 {
				return nil, nil, fmt.Errorf("key is incorrect")
			}
		}
	}

	n := 3
	if !prefix {
		n = 0
	}

	if len(r) < n {
		return nil, nil, fmt.Errorf("packet is not enough")
	}

	addr, err := tools.ResolveAddr(bytes.NewReader(r[n:]))
	if err != nil {
		return nil, nil, err
	}
	defer addr.Free()

	return r[n+addr.Len():], addr.Address(statistic.Type_udp), nil
}
