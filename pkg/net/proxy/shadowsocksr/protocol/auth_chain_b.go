package protocol

import (
	"sort"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
)

func NewAuthChainB(info Protocol) protocol {
	a := newAuthChain(info, authChainBGetRandLen)
	a.authChainBInitDataSize()
	return a
}

func (a *authChainA) authChainBInitDataSize() {
	if len(a.Key()) == 0 {
		return
	}
	// libev version
	random := &a.randomServer
	random.InitFromBin(a.Key())
	length := random.Next()%8 + 4
	a.dataSizeList = make([]int, length)
	for i := range int(length) {
		a.dataSizeList[i] = int(random.Next() % 2340 % 2040 % 1440)
	}
	sort.Ints(a.dataSizeList)

	length = random.Next()%16 + 8
	a.dataSizeList2 = make([]int, length)
	for i := range int(length) {
		a.dataSizeList2[i] = int(random.Next() % 2340 % 2040 % 1440)
	}
	sort.Ints(a.dataSizeList2)
}

func authChainBGetRandLen(dataLength int, random *ssr.Shift128plusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int {
	if dataLength > 1440 {
		return 0
	}
	random.InitFromBinDatalen(lastHash[:16], dataLength)
	// libev version, upper_bound
	pos := sort.Search(len(dataSizeList), func(i int) bool { return dataSizeList[i] > dataLength+overhead })
	finalPos := uint64(pos) + random.Next()%uint64(len(dataSizeList))
	if finalPos < uint64(len(dataSizeList)) {
		return dataSizeList[finalPos] - dataLength - overhead
	}
	// libev version, upper_bound
	pos = sort.Search(len(dataSizeList2), func(i int) bool { return dataSizeList2[i] > dataLength+overhead })
	finalPos = uint64(pos) + random.Next()%uint64(len(dataSizeList2))
	if finalPos < uint64(len(dataSizeList2)) {
		return dataSizeList2[finalPos] - dataLength - overhead
	}
	if finalPos < uint64(pos+len(dataSizeList2)-1) {
		return 0
	}

	if dataLength > 1300 {
		return int(random.Next() % 31)
	}
	if dataLength > 900 {
		return int(random.Next() % 127)
	}
	if dataLength > 400 {
		return int(random.Next() % 521)
	}
	return int(random.Next() % 1021)
}
