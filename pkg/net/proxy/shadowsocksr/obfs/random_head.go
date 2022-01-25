package obfs

import (
	"math/rand"
	"net"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
)

type randomHead struct {
	rawTransSent     bool
	rawTransReceived bool
	hasSentHeader    bool
	dataBuffer       []byte

	net.Conn
}

func init() {
	register("random_head", newRandomHead)
}

func newRandomHead(conn net.Conn, _ ssr.ServerInfo) IObfs {
	p := &randomHead{Conn: conn}
	return p
}

func (r *randomHead) Encode(data []byte) (encodedData []byte, err error) {
	if r.rawTransSent {
		return data, nil
	}

	dataLength := len(data)
	if r.hasSentHeader {
		if dataLength > 0 {
			d := make([]byte, len(r.dataBuffer)+dataLength)
			copy(d, r.dataBuffer)
			copy(d[len(r.dataBuffer):], data)
			r.dataBuffer = d
		} else {
			encodedData = r.dataBuffer
			r.dataBuffer = nil
			r.rawTransSent = true
		}
	} else {
		size := rand.Intn(96) + 8
		encodedData = make([]byte, size)
		rand.Read(encodedData)
		ssr.SetCRC32(encodedData, size)

		d := make([]byte, dataLength)
		copy(d, data)
		r.dataBuffer = d
	}
	r.hasSentHeader = true
	return
}

func (r *randomHead) Write(b []byte) (int, error) {
	if r.rawTransSent {
		return r.Conn.Write(b)
	}

	data, err := r.Encode(b)
	if err != nil {
		return 0, err
	}
	_, err = r.Conn.Write(data)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (r *randomHead) Decode(data []byte) (decodedData []byte, needSendBack bool, err error) {
	if r.rawTransReceived {
		return data, false, nil
	}
	r.rawTransReceived = true
	return data, true, nil
}

func (r *randomHead) Read(b []byte) (n int, err error) {
	if r.rawTransReceived {
		return r.Conn.Read(b)
	}

	r.rawTransReceived = true
	r.Conn.Write(nil)
	return 0, nil
}

func (r *randomHead) GetOverhead() int {
	return 0
}
