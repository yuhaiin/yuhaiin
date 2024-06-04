// https://github.com/shadowsocksr-backup/shadowsocks-rss/blob/master/doc/auth_chain_a.md

package protocol

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"strconv"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks/core"
	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
)

type authChainA struct {
	Protocol
	randomClient ssr.Shift128plusContext
	randomServer ssr.Shift128plusContext
	recvID       uint32

	encrypter      cipher.Stream
	decrypter      cipher.Stream
	hasSentHeader  bool
	lastClientHash []byte
	lastServerHash []byte
	userKey        []byte
	userKeyLen     int
	uid            [4]byte
	salt           string
	hmac           ssr.HMAC
	rnd            func(dataLength int, random *ssr.Shift128plusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int
	dataSizeList   []int
	dataSizeList2  []int
	chunkID        uint32

	overhead int
}

func NewAuthChainA(info Protocol) protocol { return newAuthChain(info, authChainAGetRandLen) }

func newAuthChain(info Protocol, rnd func(dataLength int, random *ssr.Shift128plusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int) *authChainA {
	return &authChainA{
		salt:     info.Name,
		hmac:     ssr.HMAC(crypto.MD5),
		rnd:      rnd,
		recvID:   1,
		Protocol: info,
		overhead: 4 + info.ObfsOverhead,
	}
}

func authChainAGetRandLen(dataLength int, random *ssr.Shift128plusContext, lastHash []byte, dataSizeList, dataSizeList2 []int, overhead int) int {
	if dataLength > 1440 {
		return 0
	}
	random.InitFromBinDatalen(lastHash[:16], dataLength)
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

func getRandStartPos(random *ssr.Shift128plusContext, randLength int) int {
	if randLength > 0 {
		return int(random.Next() % 8589934609 % uint64(randLength))
	}
	return 0
}

func (a *authChainA) getClientRandLen(dataLength int, overhead int) int {
	return a.rnd(dataLength, &a.randomClient, a.lastClientHash, a.dataSizeList, a.dataSizeList2, overhead)
}

func (a *authChainA) getServerRandLen(dataLength int, overhead int) int {
	return a.rnd(dataLength, &a.randomServer, a.lastServerHash, a.dataSizeList, a.dataSizeList2, overhead)
}

func (a *authChainA) packedDataLen(data []byte) (chunkLength, randLength int) {
	dataLength := len(data)
	randLength = a.getClientRandLen(dataLength, a.overhead)
	chunkLength = randLength + dataLength + 2 + 2
	return
}

func (a *authChainA) packData(outData []byte, data []byte, randLength int) {
	dataLength := len(data)
	outLength := randLength + dataLength + 2
	outData[0] = byte(dataLength) ^ a.lastClientHash[14]
	outData[1] = byte(dataLength>>8) ^ a.lastClientHash[15]

	{
		if dataLength > 0 {
			randPart1Length := getRandStartPos(&a.randomClient, randLength)
			crand.Read(outData[2 : 2+randPart1Length])
			a.encrypter.XORKeyStream(outData[2+randPart1Length:], data)
			crand.Read(outData[2+randPart1Length+dataLength : outLength])
		} else {
			crand.Read(outData[2 : 2+randLength])
		}
	}

	keyLen := a.userKeyLen + 4
	key := make([]byte, keyLen)
	copy(key, a.userKey)
	a.chunkID++
	binary.LittleEndian.PutUint32(key[a.userKeyLen:], a.chunkID)
	a.lastClientHash = a.hmac.HMAC(key, outData[:outLength], nil)
	copy(outData[outLength:], a.lastClientHash[:2])
}

const authheadLength = 4 + 8 + 4 + 16 + 4

func (a *authChainA) packAuthData(data []byte) (outData []byte) {
	outData = make([]byte, authheadLength, authheadLength+1500)

	a.Protocol.Auth.nextAuth()

	var key = make([]byte, a.IVSize()+len(a.Key()))
	copy(key, a.IV)
	copy(key[a.IVSize():], a.Key())

	encrypt := make([]byte, 20)
	t := time.Now().Unix()
	binary.LittleEndian.PutUint32(encrypt[:4], uint32(t))
	copy(encrypt[4:8], a.Protocol.Auth.clientID[:])
	binary.LittleEndian.PutUint32(encrypt[8:], a.Protocol.Auth.connectionID.Load())
	binary.LittleEndian.PutUint16(encrypt[12:], uint16(a.overhead))
	binary.LittleEndian.PutUint16(encrypt[14:16], 0)

	// first 12 bytes
	{
		crand.Read(outData[:4])
		a.lastClientHash = a.hmac.HMAC(key, outData[:4], nil)
		copy(outData[4:], a.lastClientHash[:8])
	}
	var base64UserKey string
	// uid & 16 bytes auth data
	{
		uid := make([]byte, 4)
		if a.userKey == nil {
			params := strings.Split(a.Param, ":")
			if len(params) >= 2 {
				if userID, err := strconv.ParseUint(params[0], 10, 32); err == nil {
					binary.LittleEndian.PutUint32(a.uid[:], uint32(userID))
					a.userKeyLen = len(params[1])
					a.userKey = []byte(params[1])
				}
			}
			if a.userKey == nil {
				crand.Read(a.uid[:])

				a.userKeyLen = len(a.Key())
				a.userKey = make([]byte, len(a.Key()))
				copy(a.userKey, a.Key())
			}
		}
		for i := 0; i < 4; i++ {
			uid[i] = a.uid[i] ^ a.lastClientHash[8+i]
		}
		base64UserKey = base64.StdEncoding.EncodeToString(a.userKey)
		aesCipherKey := core.KDF(base64UserKey+a.salt, 16)
		block, err := aes.NewCipher(aesCipherKey)
		if err != nil {
			return
		}
		encryptData := make([]byte, 16)
		iv := make([]byte, aes.BlockSize)
		cbc := cipher.NewCBCEncrypter(block, iv)
		cbc.CryptBlocks(encryptData, encrypt[:16])
		copy(encrypt[:4], uid[:])
		copy(encrypt[4:4+16], encryptData)
	}
	// final HMAC
	{
		a.lastServerHash = a.hmac.HMAC(a.userKey, encrypt[0:20], nil)

		copy(outData[12:], encrypt)
		copy(outData[12+20:], a.lastServerHash[:4])
	}

	// init cipher
	password := make([]byte, len(base64UserKey)+base64.StdEncoding.EncodedLen(16))
	copy(password, base64UserKey)
	base64.StdEncoding.Encode(password[len(base64UserKey):], a.lastClientHash[:16])
	a.initRC4Cipher(password)

	// data
	chunkLength, randLength := a.packedDataLen(data)
	if authheadLength+chunkLength <= cap(outData) {
		outData = outData[:authheadLength+chunkLength]
	} else {
		newOutData := make([]byte, authheadLength+chunkLength)
		copy(newOutData, outData[:authheadLength])
		outData = newOutData
	}
	a.packData(outData[authheadLength:], data, randLength)
	return outData
}

func (a *authChainA) initRC4Cipher(key []byte) {
	a.encrypter, _ = rc4.NewCipher(key)
	a.decrypter, _ = rc4.NewCipher(key)
}

func (a *authChainA) EncryptStream(wbuf *pool.Buffer, plainData []byte) (err error) {
	dataLength := len(plainData)
	offset := 0
	if dataLength > 0 && !a.hasSentHeader {
		headSize := 1200
		if headSize > dataLength {
			headSize = dataLength
		}
		wbuf.Write(a.packAuthData(plainData[:headSize]))
		offset += headSize
		dataLength -= headSize
		a.hasSentHeader = true
	}
	var unitSize = a.TcpMss - a.overhead
	for dataLength > unitSize {
		dataLen, randLength := a.packedDataLen(plainData[offset : offset+unitSize])
		b := make([]byte, dataLen)
		a.packData(b, plainData[offset:offset+unitSize], randLength)
		wbuf.Write(b)
		dataLength -= unitSize
		offset += unitSize
	}
	if dataLength > 0 {
		dataLen, randLength := a.packedDataLen(plainData[offset:])
		b := make([]byte, dataLen)
		a.packData(b, plainData[offset:], randLength)
		wbuf.Write(b)
	}
	return nil
}

func (a *authChainA) DecryptStream(rbuf *pool.Buffer, plainData []byte) (n int, err error) {
	key := make([]byte, len(a.userKey)+4)
	readlenth := 0
	copy(key, a.userKey)
	for len(plainData) > 4 {
		binary.LittleEndian.PutUint32(key[len(a.userKey):], a.recvID)
		dataLen := (int)((uint(plainData[1]^a.lastServerHash[15]) << 8) + uint(plainData[0]^a.lastServerHash[14]))
		randLen := a.getServerRandLen(dataLen, a.overhead)
		length := randLen + dataLen
		if length >= 4096 {
			return 0, ssr.ErrAuthChainDataLengthError
		}

		length += 4
		if length > len(plainData) {
			break
		}

		hash := a.hmac.HMAC(key, plainData[:length-2], nil)
		if !bytes.Equal(hash[:2], plainData[length-2:length]) {
			return 0, ssr.ErrAuthChainIncorrectHMAC
		}

		dataPos := 2
		if dataLen > 0 && randLen > 0 {
			dataPos = 2 + getRandStartPos(&a.randomServer, randLen)
		}

		b := make([]byte, dataLen)
		a.decrypter.XORKeyStream(b, plainData[dataPos:dataPos+dataLen])
		rbuf.Write(b)
		if a.recvID == 1 {
			a.TcpMss = int(binary.LittleEndian.Uint16(rbuf.Next(2)))
		}
		a.lastServerHash = hash
		a.recvID++
		plainData = plainData[length:]
		readlenth += length

	}
	return readlenth, nil
}

func (a *authChainA) GetOverhead() int {
	return a.overhead
}

func (a *authChainA) EncryptPacket(b []byte) ([]byte, error) {
	if a.userKey == nil {
		params := strings.Split(a.Param, ":")
		if len(params) >= 2 {
			if userID, err := strconv.ParseUint(params[0], 10, 32); err == nil {
				binary.LittleEndian.PutUint32(a.uid[:], uint32(userID))
				a.userKeyLen = len(params[1])
				a.userKey = []byte(params[1])
			}
		}
		if a.userKey == nil {
			crand.Read(a.uid[:])

			a.userKeyLen = len(a.Key())
			a.userKey = make([]byte, len(a.Key()))
			copy(a.userKey, a.Key())
		}
	}
	authData := make([]byte, 3)
	crand.Read(authData)

	md5Data := a.hmac.HMAC(a.userKey, authData, nil)
	randDataLength := udpGetRandLength(md5Data, &a.randomClient)

	key := core.KDF(base64.StdEncoding.EncodeToString(a.userKey)+base64.StdEncoding.EncodeToString(md5Data), 16)
	rc4Cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	wantedData := b[:len(b)-8-randDataLength]
	rc4Cipher.XORKeyStream(wantedData, wantedData)
	return wantedData, nil
}

func (a *authChainA) DecryptPacket(b []byte) ([]byte, error) {
	if len(b) < 9 {
		return nil, ssr.ErrAuthChainDataLengthError
	}
	if !bytes.Equal(a.hmac.HMAC(a.userKey, b[:len(b)-1], nil)[:1], b[len(b)-1:]) {
		return nil, ssr.ErrAuthChainIncorrectHMAC
	}
	md5Data := a.hmac.HMAC(a.Key(), b[len(b)-8:len(b)-1], nil)

	randDataLength := udpGetRandLength(md5Data, &a.randomServer)

	key := core.KDF(base64.StdEncoding.EncodeToString(a.userKey)+base64.StdEncoding.EncodeToString(md5Data), 16)
	rc4Cipher, err := rc4.NewCipher(key)
	if err != nil {
		return nil, err
	}
	wantedData := b[:len(b)-8-randDataLength]
	rc4Cipher.XORKeyStream(wantedData, wantedData)
	return wantedData, nil
}

func udpGetRandLength(lastHash []byte, random *ssr.Shift128plusContext) int {
	random.InitFromBin(lastHash)
	return int(random.Next() % 127)
}
