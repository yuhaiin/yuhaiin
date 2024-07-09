package bittorrent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/utils/system"
)

type SniffHeader struct{}

func (h *SniffHeader) Protocol() string {
	return "bittorrent"
}

func (h *SniffHeader) Domain() string {
	return ""
}

var errNotBittorrent = errors.New("not bittorrent header")
var ErrNoClue = errors.New("no rule")

func SniffBittorrent(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, ErrNoClue
	}

	if b[0] == 19 && string(b[1:20]) == "BitTorrent protocol" {
		return &SniffHeader{}, nil
	}

	return nil, errNotBittorrent
}

func SniffUTP(b []byte) (*SniffHeader, error) {
	if len(b) < 20 {
		return nil, ErrNoClue
	}

	buffer := bytes.NewBuffer(b)

	var typeAndVersion uint8

	if binary.Read(buffer, binary.BigEndian, &typeAndVersion) != nil {
		return nil, ErrNoClue
	} else if b[0]>>4&0xF > 4 || b[0]&0xF != 1 {
		return nil, errNotBittorrent
	}

	var extension uint8

	if binary.Read(buffer, binary.BigEndian, &extension) != nil {
		return nil, ErrNoClue
	} else if extension != 0 && extension != 1 {
		return nil, errNotBittorrent
	}

	for extension != 0 {
		if extension != 1 {
			return nil, errNotBittorrent
		}
		if binary.Read(buffer, binary.BigEndian, &extension) != nil {
			return nil, ErrNoClue
		}

		var length uint8
		if err := binary.Read(buffer, binary.BigEndian, &length); err != nil {
			return nil, ErrNoClue
		}
		if ReadBytes(buffer, int(length)) != nil {
			return nil, ErrNoClue
		}
	}

	if ReadBytes(buffer, 2) != nil {
		return nil, ErrNoClue
	}

	var timestamp uint32
	if err := binary.Read(buffer, binary.BigEndian, &timestamp); err != nil {
		return nil, ErrNoClue
	}
	if math.Abs(float64(system.NowUnixMicro()-int64(timestamp))) > float64(24*time.Hour) {
		return nil, errNotBittorrent
	}

	return &SniffHeader{}, nil
}

func ReadBytes(buf *bytes.Buffer, n int) error {
	if buf.Len() < n {
		return io.EOF
	}

	buf.Next(n)
	return nil
}
