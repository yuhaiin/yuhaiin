package resolver

import (
	"errors"
	"fmt"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/tls"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	TypeSVCB  dnsmessage.Type = 64
	TypeHTTPS dnsmessage.Type = 65
)

type ParamKey uint16

func (p ParamKey) String() string {
	return paramNames[p]
}

const (
	ParamMandatory     ParamKey = 0
	ParamALPN          ParamKey = 1
	ParamNoDefaultALPN ParamKey = 2
	ParamPort          ParamKey = 3
	ParamIPv4Hint      ParamKey = 4
	ParamECHConfig     ParamKey = 5
	ParamIPv6Hint      ParamKey = 6
)

var paramNames = map[ParamKey]string{
	ParamMandatory:     "mandatory",
	ParamALPN:          "alpn",
	ParamNoDefaultALPN: "no-default-alpn",
	ParamPort:          "port",
	ParamIPv4Hint:      "ipv4hint",
	ParamECHConfig:     "echconfig",
	ParamIPv6Hint:      "ipv6hint",
}

func skipName(msg []byte, off int) (int, error) {
	// newOff is the offset where the next record will start. Pointers lead
	// to data that belongs to other names and thus doesn't count towards to
	// the usage of this name.
	newOff := off

Loop:
	for {
		if newOff >= len(msg) {
			return off, errors.New("errBaseLen")
		}
		c := int(msg[newOff])
		newOff++
		switch c & 0xC0 {
		case 0x00:
			if c == 0x00 {
				// A zero length signals the end of the name.
				break Loop
			}
			// literal string
			newOff += c
			if newOff > len(msg) {
				return off, errors.New("errCalcLen")
			}
		case 0xC0:
			// Pointer to somewhere else in msg.

			// Pointers are two bytes.
			newOff++

			// Don't follow the pointer as the data here has ended.
			break Loop
		default:
			// Prefixes 0x80 and 0x40 are reserved.
			return off, errors.New("errReserved")
		}
	}

	return newOff, nil
}

func unpackSVCBResource(msg []byte, f func(ParamKey, []byte) error) error {
	endOff := len(msg)
	_, off, err := unpackUint16(msg, 0)
	if err != nil {
		return err
	}
	if off, err = skipName(msg, off); err != nil {
		return err
	}
	for off < endOff {
		var err error
		var k uint16
		k, off, err = unpackUint16(msg, off)
		if err != nil {
			return err
		}
		var l uint16
		l, off, err = unpackUint16(msg, off)
		if err != nil {
			return err
		}
		dataOff := off
		off += int(l)
		if err := f(ParamKey(k), msg[dataOff:off]); err != nil {
			return err
		}
	}
	return nil
}

func unpackUint16(msg []byte, off int) (uint16, int, error) {
	if off+2 > len(msg) {
		return 0, off, errors.New("errBaseLen")
	}
	return uint16(msg[off])<<8 | uint16(msg[off+1]), off + 2, nil
}

func GetECHConfig(msg []byte) ([]tls.ECHConfigSpec, error) {
	var echConfig []byte
	if err := unpackSVCBResource(msg, func(k ParamKey, v []byte) error {
		if k == ParamECHConfig {
			echConfig = v
		}
		return nil
	}); err != nil {
		return nil, err
	}
	if echConfig == nil {
		return nil, fmt.Errorf("echconfig not found")
	}

	return tls.ParseECHConfigList(echConfig)
}
