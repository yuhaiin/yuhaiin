package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
)

func TestXxx(t *testing.T) {
	f, err := os.Open("/proc/net/udp")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)

	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if fs[0] == "sl" {
			continue
		}
		t.Log(DecodeAddr(fs[1]), DecodeAddr(fs[2]))
	}
}

func DecodeAddr(s string) string {
	ss := strings.Split(s, ":")
	addr, _ := hex.DecodeString(ss[0])
	port, _ := hex.DecodeString(ss[1])
	return fmt.Sprintf("%v:%d", net.IP(nativeEndianIP(addr)), binary.BigEndian.Uint16(port))
}

func nativeEndianIP(ip []byte) []byte {
	result := make([]byte, len(ip))

	for i := 0; i < len(ip); i += 4 {
		value := binary.BigEndian.Uint32(ip[i:])
		binary.LittleEndian.PutUint32(result[i:], value)
	}

	return result
}
