package lightweight

import "encoding/binary"

const (
	flagFIN = 1
	flagSYN = 2
	flagRST = 4
	flagPSH = 8
	flagACK = 16
)

type sackBlock struct{ start, end uint32 }
type tcpOptions struct {
	mss    int
	scale  int
	sack   bool
	blocks [4]sackBlock
	count  int
}

func parseTCPOptions(b []byte) (tcpOptions, error) {
	o := tcpOptions{scale: -1}
	for len(b) > 0 {
		if b[0] == 0 {
			return o, nil
		}
		if b[0] == 1 {
			b = b[1:]
			continue
		}
		if len(b) < 2 || b[1] < 2 || int(b[1]) > len(b) {
			return o, ErrMalformed
		}
		n := int(b[1])
		switch b[0] {
		case 2:
			if n != 4 {
				return o, ErrMalformed
			}
			o.mss = int(binary.BigEndian.Uint16(b[2:4]))
			if o.mss == 0 {
				return o, ErrMalformed
			}
		case 3:
			if n != 3 {
				return o, ErrMalformed
			}
			o.scale = min(int(b[2]), 14)
		case 4:
			if n != 2 {
				return o, ErrMalformed
			}
			o.sack = true
		case 5:
			if n < 10 || (n-2)%8 != 0 || n > 34 {
				return o, ErrMalformed
			}
			o.count = (n - 2) / 8
			for i := range o.count {
				o.blocks[i] = sackBlock{binary.BigEndian.Uint32(b[2+8*i:]), binary.BigEndian.Uint32(b[6+8*i:])}
			}
		case 8:
			if n != 10 {
				return o, ErrMalformed
			}
		}
		b = b[n:]
	}
	return o, nil
}
func before(a, b uint32) bool { return int32(a-b) < 0 }
func after(a, b uint32) bool  { return before(b, a) }
