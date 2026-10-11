package payload

import (
	"encoding/binary"
	"fmt"
)

// Transform is a single algorithm choice within a proposal.
type Transform struct {
	Type   TransformType
	ID     uint16
	KeyLen uint16 // key length attribute in bits; 0 means unset
}

// Proposal is one SA proposal: a protocol plus a set of transforms. For a
// received ESP proposal the SPI identifies the child SA.
type Proposal struct {
	Num        uint8
	Protocol   ProtocolID
	SPI        []byte
	Transforms []Transform
}

// SAPayload is the decoded body of an SA payload: an ordered list of
// proposals (RFC 7296 section 3.3).
type SAPayload struct {
	Proposals []Proposal
}

// Get returns the first transform of the given type, or (Transform{}, false).
func (p *Proposal) Get(t TransformType) (Transform, bool) {
	for _, tr := range p.Transforms {
		if tr.Type == t {
			return tr, true
		}
	}
	return Transform{}, false
}

// MarshalSA encodes an SA payload body.
func MarshalSA(sa SAPayload) []byte {
	var out []byte
	for i, prop := range sa.Proposals {
		last := i == len(sa.Proposals)-1
		out = append(out, marshalProposal(prop, last)...)
	}
	return out
}

func marshalProposal(p Proposal, last bool) []byte {
	// Proposal substructure header (RFC 7296 3.3.1):
	//  0/2: 0(more) or 0(last); Reserved; Proposal Length(2)
	//  Proposal Num(1); Protocol ID(1); SPI Size(1); # Transforms(1); SPI; transforms
	var body []byte
	for i, tr := range p.Transforms {
		lastTr := i == len(p.Transforms)-1
		body = append(body, marshalTransform(tr, lastTr)...)
	}
	hdrLen := 8 + len(p.SPI)
	total := hdrLen + len(body)
	out := make([]byte, hdrLen)
	if last {
		out[0] = 0
	} else {
		out[0] = 2
	}
	out[1] = 0
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	out[4] = p.Num
	out[5] = byte(p.Protocol)
	out[6] = byte(len(p.SPI))
	out[7] = byte(len(p.Transforms))
	copy(out[8:], p.SPI)
	out = append(out, body...)
	return out
}

func marshalTransform(t Transform, last bool) []byte {
	var attr []byte
	if t.KeyLen != 0 {
		// TV-format attribute: high bit set, type=14, value=keylen bits.
		attr = make([]byte, 4)
		binary.BigEndian.PutUint16(attr[0:2], 0x8000|AttrKeyLength)
		binary.BigEndian.PutUint16(attr[2:4], t.KeyLen)
	}
	total := 8 + len(attr)
	out := make([]byte, 8)
	if last {
		out[0] = 0
	} else {
		out[0] = 3
	}
	out[1] = 0
	binary.BigEndian.PutUint16(out[2:4], uint16(total))
	out[4] = byte(t.Type)
	out[5] = 0
	binary.BigEndian.PutUint16(out[6:8], t.ID)
	out = append(out, attr...)
	return out
}

// ParseSA decodes an SA payload body into proposals.
func ParseSA(buf []byte) (SAPayload, error) {
	var sa SAPayload
	off := 0
	for off < len(buf) {
		if off+8 > len(buf) {
			return sa, ErrTruncated
		}
		more := buf[off]
		plen := int(binary.BigEndian.Uint16(buf[off+2 : off+4]))
		if plen < 8 || off+plen > len(buf) {
			return sa, fmt.Errorf("payload: bad proposal length %d", plen)
		}
		num := buf[off+4]
		proto := ProtocolID(buf[off+5])
		spiSize := int(buf[off+6])
		numTr := int(buf[off+7])
		if 8+spiSize > plen {
			return sa, ErrTruncated
		}
		spi := append([]byte(nil), buf[off+8:off+8+spiSize]...)
		trs, err := parseTransforms(buf[off+8+spiSize:off+plen], numTr)
		if err != nil {
			return sa, err
		}
		sa.Proposals = append(sa.Proposals, Proposal{
			Num: num, Protocol: proto, SPI: spi, Transforms: trs,
		})
		off += plen
		if more == 0 {
			break
		}
	}
	return sa, nil
}

func parseTransforms(buf []byte, count int) ([]Transform, error) {
	var out []Transform
	off := 0
	for i := 0; i < count; i++ {
		if off+8 > len(buf) {
			return nil, ErrTruncated
		}
		more := buf[off]
		tlen := int(binary.BigEndian.Uint16(buf[off+2 : off+4]))
		if tlen < 8 || off+tlen > len(buf) {
			return nil, fmt.Errorf("payload: bad transform length %d", tlen)
		}
		tr := Transform{
			Type: TransformType(buf[off+4]),
			ID:   binary.BigEndian.Uint16(buf[off+6 : off+8]),
		}
		if err := parseTransformAttrs(buf[off+8:off+tlen], &tr); err != nil {
			return nil, err
		}
		out = append(out, tr)
		off += tlen
		if more == 0 {
			break
		}
	}
	return out, nil
}

func parseTransformAttrs(buf []byte, tr *Transform) error {
	off := 0
	for off < len(buf) {
		if off+4 > len(buf) {
			return ErrTruncated
		}
		af := binary.BigEndian.Uint16(buf[off : off+2])
		atype := af & 0x7fff
		if af&0x8000 != 0 {
			// TV format: 2-octet value.
			val := binary.BigEndian.Uint16(buf[off+2 : off+4])
			if atype == AttrKeyLength {
				tr.KeyLen = val
			}
			off += 4
		} else {
			// TLV format: length then value.
			l := int(binary.BigEndian.Uint16(buf[off+2 : off+4]))
			off += 4 + l
		}
	}
	return nil
}
