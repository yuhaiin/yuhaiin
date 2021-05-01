package dns

import (
	"bytes"
	"net"
)

type EDNSOPT [2]byte

//https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
var (
	Reserved         = EDNSOPT{0b00000000, 0b00000000} //0
	LLQ              = EDNSOPT{0b00000000, 0b00000001} //1 Optional
	UL               = EDNSOPT{0b00000000, 0b00000010} //2 On-hold
	NSID             = EDNSOPT{0b00000000, 0b00000011} //3 Standard
	Reserved2        = EDNSOPT{0b00000000, 0b00000100} //4
	DAU              = EDNSOPT{0b00000000, 0b00000101} //5 Standard
	DHU              = EDNSOPT{0b00000000, 0b00000110} //6 Standard
	N3U              = EDNSOPT{0b00000000, 0b00000111} //7 Standard
	EdnsClientSubnet = EDNSOPT{0b00000000, 0b00001000} //8 Optional
	EDNSEXPIRE       = EDNSOPT{0b00000000, 0b00001001} //9 Optional
	COOKIE           = EDNSOPT{0b00000000, 0b00001010} //10 Standard
	TcpKeepalive     = EDNSOPT{0b00000000, 0b00001011} //11 Standard
	Padding          = EDNSOPT{0b00000000, 0b00001100} //12 Standard
	CHAIN            = EDNSOPT{0b00000000, 0b00001101} //13 Standard
	KEYTAG           = EDNSOPT{0b00000000, 0b00001110} //14 Optional
	ExtendedDNSError = EDNSOPT{0b00000000, 0b00001111} //15 Standard
	EDNSClientTag    = EDNSOPT{0b00000000, 0b00010000} //16 Optional
	EDNSServerTag    = EDNSOPT{0b00000000, 0b00010001} //17 Optional

)

type eDNSHeader struct {
	DnsHeader   []byte
	Name        [1]byte
	Type        [2]byte
	PayloadSize [2]byte
	ExtendRCode [1]byte
	EDNSVersion [1]byte
	Z           [2]byte
	Data        []byte
}

func createEDNSRequ(header eDNSHeader) []byte {
	header.DnsHeader[10] = 0b00000000
	header.DnsHeader[11] = 0b00000001
	length := getLength(len(header.Data))
	return bytes.Join([][]byte{header.DnsHeader, header.Name[:], header.Type[:], header.PayloadSize[:], header.ExtendRCode[:], header.EDNSVersion[:], header.Z[:], length[:], header.Data}, []byte{})
}

// https://tools.ietf.org/html/rfc7871
// https://tools.ietf.org/html/rfc2671
func createEDNSReq(domain string, reqType2 reqType, eDNS []byte) []byte {
	data := bytes.NewBuffer(creatRequest(domain, reqType2, true))
	data.WriteByte(0b00000000)                 // name
	data.Write([]byte{0b00000000, 0b00101001}) // type 41
	data.Write([]byte{0b00010000, 0b00000000}) // payloadSize 4096
	data.WriteByte(0b00000000)                 // extendRcode
	data.WriteByte(0b00000000)                 // EDNS Version
	data.Write([]byte{0b00000000, 0b00000000}) // Z
	data.Write(getLength(len(eDNS)))           // data length
	data.Write(eDNS)                           // data
	return data.Bytes()
}

func createEdnsClientSubnet(ip *net.IPNet) []byte {
	optionData := bytes.NewBuffer(nil)
	mask, _ := ip.Mask.Size()
	subnet := ip.IP.To4()
	if subnet == nil { // family https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
		optionData.Write([]byte{0b00000000, 0b00000010}) // family ipv6 2
		subnet = ip.IP.To16()
	} else {
		optionData.Write([]byte{0b00000000, 0b00000001}) // family ipv4 1
	}
	optionData.WriteByte(byte(mask)) // mask
	optionData.WriteByte(0b00000000) // 0 In queries, it MUST be set to 0.
	optionData.Write(subnet)         // subnet IP

	data := bytes.NewBuffer(nil)
	data.Write([]byte{EdnsClientSubnet[0], EdnsClientSubnet[1]}) // option Code
	data.Write(getLength(optionData.Len()))                      // option data length
	data.Write(optionData.Bytes())                               // option data
	return data.Bytes()
}

func getLength(length int) []byte {
	return []byte{byte(length >> 8), byte(length - ((length >> 8) << 8))}
}

func resolveAdditional(b []byte, arCount int) {
	for arCount != 0 {
		arCount--
		//name := b[:1]
		b = b[1:] // name
		typeE := b[:2]
		b = b[2:] // type
		b = b[2:] // payLoadSize
		b = b[1:] // rCode
		b = b[1:] // version
		b = b[2:] // Z
		dataLength := int(b[0])<<8 + int(b[1])
		b = b[2:]
		if typeE[0] != 0 || typeE[1] != 41 {
			//optData := b[:dataLength]
			b = b[dataLength:] // optData
			continue
		}

		if dataLength == 0 {
			continue
		}
		optCode := EDNSOPT{b[0], b[1]}
		b = b[2:]
		optionLength := int(b[0])<<8 + int(b[1])
		b = b[2:]
		switch optCode {
		case EdnsClientSubnet:
			b = b[2:]              // family
			b = b[1:]              // source Netmask
			b = b[1:]              // scope Netmask
			b = b[optionLength-4:] // Subnet IP
		default:
			b = b[optionLength:] // opt data
		}
	}
}
