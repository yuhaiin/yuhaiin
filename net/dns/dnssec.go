package dns

//protocol change https://tools.ietf.org/html/rfc3225
//https://tools.ietf.org/html/rfc4034
//https://tools.ietf.org/html/rfc4035
//Algorithm https://tools.ietf.org/html/rfc4034#appendix-A.1
func createDNSSEC(domain string, reqType2 reqType) (header eDNSHeader, b []byte) {
	//eDNSHeader := createEDNSReq(domain,reqType2,[]byte{})
	header = eDNSHeader{}
	header.DnsHeader = creatRequest(domain, reqType2)
	header.Name[0] = 0b0
	header.Type = [2]byte{0b00000000, 0b00101001}
	header.PayloadSize = [2]byte{0b00010000, 0b00000000} //4096
	header.ExtendRCode = [1]byte{0b00000000}
	header.EDNSVersion = [1]byte{0b00000000}
	header.Z = [2]byte{0b10000000, 0b00000000} // Do bit = 1
	return header, createEDNSRequ(header)
}
