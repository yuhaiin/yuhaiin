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

// https://tools.ietf.org/html/rfc7871
func createEDNSReq(domain string, subnet string) []byte {
	normalReq := creatRequest(domain, A)
	normalReq[10] = 0b00000000
	normalReq[11] = 0b00000001
	name := []byte{0b00000000}
	typeR := []byte{0b00000000, 0b00101001}       //41
	payloadSize := []byte{0b00010000, 0b00000000} //4096
	extendRcode := []byte{0b00000000}
	eDNSVersion := []byte{0b00000000}
	z := []byte{0b00000000, 0b00000000}
	data := createEdnsClientSubnet(net.ParseIP(subnet))
	dataLength := getLength(len(subnet))
	return bytes.Join([][]byte{normalReq, name, typeR, payloadSize, extendRcode, eDNSVersion, z, dataLength[:], data}, []byte{})
}

func createEdnsClientSubnet(ip net.IP) []byte {
	optionCode := []byte{EdnsClientSubnet[0], EdnsClientSubnet[1]}

	family := []byte{0b00000000, 0b00000001} // 1:Ipv4 2:IPv6 https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
	sourceNetmask := []byte{0b00100000}      // 32
	scopeNetmask := []byte{0b00000000}       //0 In queries, it MUST be set to 0.
	subnet := ip.To4()                       //depending family
	if subnet == nil {
		subnet = ip.To16()
		family = []byte{0b00000000, 0b00000010}
	}
	optionData := bytes.Join([][]byte{family, sourceNetmask, scopeNetmask, subnet}, []byte{})

	optionLength := getLength(len(optionData))

	return bytes.Join([][]byte{optionCode, optionLength[:], optionData}, []byte{})
}

func getLength(length int) [2]byte {
	return [2]byte{byte(length >> 8), byte(length - ((length >> 8) << 8))}
}
