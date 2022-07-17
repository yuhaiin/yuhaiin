package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"log"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"time"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

func init() {
	register("auth_aes128_md5", NewAuthAES128MD5)
}

func NewAuthAES128MD5(info ProtocolInfo) IProtocol {
	a := &authAES128{
		salt:       "auth_aes128_md5",
		hmac:       ssr.HmacMD5,
		hashDigest: ssr.MD5Sum,
		packID:     1,
		recvID:     1,
		key:        info.Key,
		keyLen:     info.KeySize,
		iv:         info.IV,
		ivLen:      info.IVSize,
		param:      info.Param,
		auth:       info.Auth,
		tcpMSS:     info.TcpMss,
	}
	a.initUserKey()
	return a
}

type authAES128 struct {
	recvID        uint32
	auth          *AuthData
	hasSentHeader bool
	rawTrans      bool
	packID        uint32
	userKey       []byte
	uid           [4]byte
	salt          string
	hmac          hmacMethod
	hashDigest    hashDigestMethod

	key, iv       []byte
	keyLen, ivLen int
	tcpMSS        int

	param string
}

func (a *authAES128) packData(wbuf *bytes.Buffer, data []byte, fullDataSize int) {
	dataLength := len(data)
	if dataLength == 0 {
		return
	}
	randLength := a.rndDataLen(dataLength, fullDataSize)

	// 1: randLengthData Length
	outLength := 1 + randLength + dataLength + 8

	key := make([]byte, len(a.userKey)+4)
	copy(key, a.userKey)
	binary.LittleEndian.PutUint32(key[len(key)-4:], a.packID)

	a.packID = (a.packID + 1) & 0xFFFFFFFF

	// 0~1, out length
	binary.Write(wbuf, binary.LittleEndian, uint16(outLength))

	// 2~3, hmac
	wbuf.Write(a.hmac(key, wbuf.Bytes()[wbuf.Len()-2:])[:2])

	// 4, rand length
	if randLength < 128 {
		wbuf.WriteByte(byte(randLength + 1))
	} else {
		// 4, magic number 255
		wbuf.WriteByte(255)
		// 5~6, rand length
		binary.Write(wbuf, binary.LittleEndian, uint16(randLength+1))
		randLength -= 2
	}

	// 4~rand length+4, rand number
	if _, err := io.CopyN(wbuf, crand.Reader, int64(randLength)); err != nil {
		log.Printf("copy rand bytes failed: %s\n", err)
	}

	// rand length+4~out length-4, data
	wbuf.Write(data)

	start := wbuf.Len() - outLength + 4
	if start < 0 {
		log.Println("---------------start < 0, buf len: ", wbuf.Len(), "out length: ", outLength)
		start = 0
	}
	// hmac
	wbuf.Write(a.hmac(key, wbuf.Bytes()[start:])[:4])
}

func (a *authAES128) initUserKey() {
	if a.userKey != nil {
		return
	}

	params := strings.Split(a.param, ":")
	if len(params) >= 2 {
		userID, err := strconv.ParseUint(params[0], 10, 32)
		if err == nil {
			binary.LittleEndian.PutUint32(a.uid[:], uint32(userID))
			a.userKey = a.hashDigest([]byte(params[1]))
		}
	}

	if a.userKey == nil {
		rand.Read(a.uid[:])
		a.userKey = make([]byte, a.keyLen)
		copy(a.userKey, a.key)
	}
}

// https://github.com/shadowsocksrr/shadowsocksr/blob/fd723a92c488d202b407323f0512987346944136/shadowsocks/obfsplugin/auth.py#L501
func (a *authAES128) rndDataLen(bufSize, fullBufSize int) int {
	trapezoidRandomFLoat := func(maxVal int, d float64) int {
		var r float64
		if d == 0 {
			r = rand.Float64()
		} else {
			s := rand.Float64()
			a := 1 - d
			r = (math.Sqrt(a*a+4*d*s) - a) / (2 * d)
		}

		return int(float64(maxVal) * r)
	}

	if fullBufSize >= utils.DefaultSize {
		return 0
	}

	revLen := a.tcpMSS - bufSize - a.GetOverhead()
	if revLen == 0 {
		return 0
	}
	if revLen < 0 {
		if revLen > -a.tcpMSS {
			return trapezoidRandomFLoat(revLen+a.tcpMSS, -0.3)
		}

		return rand.Intn(32)
	}

	if bufSize > 900 {
		return rand.Intn(revLen)
	}

	return trapezoidRandomFLoat(revLen, -0.3)
}

func (a *authAES128) packAuthData(wbuf *bytes.Buffer, data []byte) {
	dataLength := len(data)
	if dataLength == 0 {
		return
	}

	var randLength int
	if dataLength > 400 {
		randLength = rand.Intn(512)
	} else {
		randLength = rand.Intn(1024)
	}

	outLength := 7 + 4 + 16 + 4 + dataLength + randLength + 4

	aesCipherKey := ssr.KDF(base64.StdEncoding.EncodeToString(a.userKey)+a.salt, 16)
	block, err := aes.NewCipher(aesCipherKey)
	if err != nil {
		return
	}

	encrypt := utils.GetBytes(16)
	defer utils.PutBytes(encrypt)

	a.auth.nextAuth()
	binary.LittleEndian.PutUint32(encrypt[0:4], uint32(time.Now().Unix()))
	copy(encrypt[4:], a.auth.clientID)
	binary.LittleEndian.PutUint32(encrypt[8:], a.auth.connectionID)
	binary.LittleEndian.PutUint16(encrypt[12:], uint16(outLength))
	binary.LittleEndian.PutUint16(encrypt[14:], uint16(randLength))

	iv := make([]byte, aes.BlockSize)
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(encrypt[:16], encrypt[:16])

	key := make([]byte, a.ivLen+a.keyLen)
	copy(key, a.iv)
	copy(key[a.ivLen:], a.key)

	wbuf.Write([]byte{byte(rand.Intn(256))})
	wbuf.Write(a.hmac(key, wbuf.Bytes()[wbuf.Len()-1:])[:6])
	wbuf.Write(a.uid[:])
	wbuf.Write(encrypt[:16])
	wbuf.Write(a.hmac(key, wbuf.Bytes()[wbuf.Len()-20:])[:4])
	io.CopyN(wbuf, crand.Reader, int64(randLength))
	wbuf.Write(data)
	start := wbuf.Len() - outLength + 4
	if start < 0 {
		log.Println("---------------start < 0, buf len: ", wbuf.Len(), "out length: ", outLength)
		start = 0
	}
	wbuf.Write(a.hmac(a.userKey, wbuf.Bytes()[start:])[:4])
}

func (a *authAES128) EncryptStream(wbuf *bytes.Buffer, data []byte) (err error) {
	dataLen := len(data)

	if dataLen <= 0 {
		return nil
	}

	if !a.hasSentHeader {
		authLen := GetHeadSize(data, 30) + rand.Intn(32)
		if authLen > dataLen {
			authLen = dataLen
		}

		a.packAuthData(wbuf, data[:authLen])
		data = data[authLen:]

		a.hasSentHeader = true
	}

	// https://github.com/shadowsocksrr/shadowsocksr/blob/fd723a92c488d202b407323f0512987346944136/shadowsocks/obfsplugin/auth.py#L459
	const unitLen = 8100
	for len(data) > unitLen {
		a.packData(wbuf, data[:unitLen], dataLen)
		data = data[unitLen:]
	}
	a.packData(wbuf, data, dataLen)

	return nil
}

func (a *authAES128) DecryptStream(rbuf *bytes.Buffer, data []byte) (int, error) {
	if a.rawTrans {
		return rbuf.Write(data)
	}

	datalen, readLen := len(data), 0

	keyLen := len(a.userKey) + 4

	key := utils.GetBytes(keyLen)
	defer utils.PutBytes(key)

	copy(key[0:], a.userKey)

	for datalen > 4 {
		binary.LittleEndian.PutUint32(key[keyLen-4:], a.recvID)
		if !bytes.Equal(a.hmac(key[:keyLen], data[0:2])[:2], data[2:4]) {
			return 0, ssr.ErrAuthAES128IncorrectHMAC
		}

		clen := int(binary.LittleEndian.Uint16(data[0:2]))
		if clen >= 8192 || clen < 7 {
			a.rawTrans = true
			return 0, ssr.ErrAuthAES128DataLengthError
		}
		if clen > datalen {
			break
		}

		if !bytes.Equal(a.hmac(key[:keyLen], data[:clen-4])[:4], data[clen-4:clen]) {
			a.rawTrans = true
			return 0, ssr.ErrAuthAES128IncorrectChecksum
		}

		a.recvID = (a.recvID + 1) & 0xFFFFFFFF

		pos := int(data[4])
		if pos < 255 {
			pos += 4
		} else {
			pos = int(binary.LittleEndian.Uint16(data[5:7])) + 4
		}

		if pos > clen-4 {
			return 0, ssr.ErrAuthAES128PosOutOfRange
		}

		rbuf.Write(data[pos : clen-4])

		data, datalen, readLen = data[clen:], datalen-clen, readLen+clen
	}

	return readLen, nil
}

// https://github.com/shadowsocksrr/shadowsocksr/blob/fd723a92c488d202b407323f0512987346944136/shadowsocks/obfsplugin/auth.py#L749
func (a *authAES128) EncryptPacket(b []byte) ([]byte, error) {
	wbuf := bytes.NewBuffer(nil)
	wbuf.Write(b)
	wbuf.Write(a.uid[:])
	wbuf.Write(a.hmac(a.userKey, wbuf.Bytes())[:4])
	return wbuf.Bytes(), nil
}

// https://github.com/shadowsocksrr/shadowsocksr/blob/fd723a92c488d202b407323f0512987346944136/shadowsocks/obfsplugin/auth.py#L764
func (a *authAES128) DecryptPacket(b []byte) ([]byte, error) {
	if !bytes.Equal(a.hmac(a.key, b[:len(b)-4])[:4], b[len(b)-4:]) {
		return nil, ssr.ErrAuthAES128IncorrectChecksum
	}

	return b[:len(b)-4], nil
}

func (a *authAES128) GetOverhead() int { return 9 }
