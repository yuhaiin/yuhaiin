package protocol

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
	"math"
	"math/big"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/log"
	"github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocks/core"
	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
	"github.com/Asutorufa/yuhaiin/pkg/utils/pool"
	"github.com/Asutorufa/yuhaiin/pkg/utils/yerror"
)

func NewAuthAES128MD5(info Protocol) protocol { return newAuthAES128(info, crypto.MD5) }

func newAuthAES128(info Protocol, hash crypto.Hash) protocol {
	a := &authAES128{
		salt:   strings.ToLower(info.Name),
		hmac:   ssr.HMAC(hash),
		packID: 1,
		recvID: 1,
		info:   info,
	}
	a.initUserKey()
	return a
}

type authAES128 struct {
	hasSentHeader, rawTrans bool
	recvID, packID          uint32
	uid                     [4]byte
	hmac                    ssr.HMAC
	userKey                 []byte
	salt                    string
	info                    Protocol
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

	hmacBuf := pool.GetBytes(6)
	defer pool.PutBytes(hmacBuf)

	// 2~3, hmac
	wbuf.Write(a.hmac.HMAC(key, wbuf.Bytes()[wbuf.Len()-2:], hmacBuf)[:2])

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
		log.Error("copy rand bytes failed", "err", err)
	}

	// rand length+4~out length-4, data
	wbuf.Write(data)

	start := wbuf.Len() - outLength + 4
	// hmac
	wbuf.Write(a.hmac.HMAC(key, wbuf.Bytes()[start:], hmacBuf)[:4])
}

func (a *authAES128) initUserKey() {
	if a.userKey != nil {
		return
	}

	params := strings.Split(a.info.Param, ":")
	if len(params) >= 2 {
		userID, err := strconv.ParseUint(params[0], 10, 32)
		if err == nil {
			binary.LittleEndian.PutUint32(a.uid[:], uint32(userID))
			a.userKey = a.hmac.HASH([]byte(params[1]))
		}
	}

	if a.userKey == nil {
		rand.Read(a.uid[:])
		a.userKey = make([]byte, len(a.info.Key()))
		copy(a.userKey, a.info.Key())
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

	if fullBufSize >= pool.DefaultSize {
		return 0
	}

	revLen := a.info.TcpMss - bufSize - a.GetOverhead()
	if revLen == 0 {
		return 0
	}
	if revLen < 0 {
		if revLen > -a.info.TcpMss {
			return trapezoidRandomFLoat(revLen+a.info.TcpMss, -0.3)
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

	aesCipherKey := core.KDF(base64.StdEncoding.EncodeToString(a.userKey)+a.salt, 16)
	block, err := aes.NewCipher(aesCipherKey)
	if err != nil {
		return
	}

	encrypt := pool.GetBytesV2(16)
	defer pool.PutBytesV2(encrypt)

	a.info.Auth.nextAuth()
	binary.LittleEndian.PutUint32(encrypt.Bytes(), uint32(time.Now().Unix()))
	copy(encrypt.After(4), a.info.Auth.clientID)
	binary.LittleEndian.PutUint32(encrypt.After(8), a.info.Auth.connectionID.Load())
	binary.LittleEndian.PutUint16(encrypt.After(12), uint16(outLength))
	binary.LittleEndian.PutUint16(encrypt.After(14), uint16(randLength))

	iv := make([]byte, aes.BlockSize)
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(encrypt.Bytes(), encrypt.Bytes())

	key := make([]byte, a.info.IVSize()+len(a.info.Key()))
	copy(key, a.info.IV)
	copy(key[a.info.IVSize():], a.info.Key())

	hmacBuf := pool.GetBytes(6)
	defer pool.PutBytes(hmacBuf)

	wbuf.WriteByte(byte(yerror.Ignore(crand.Int(crand.Reader, big.NewInt(256))).Uint64()))
	wbuf.Write(a.hmac.HMAC(key, wbuf.Bytes()[wbuf.Len()-1:], hmacBuf)[:6])
	wbuf.Write(a.uid[:])
	wbuf.Write(encrypt.Bytes())
	wbuf.Write(a.hmac.HMAC(key, wbuf.Bytes()[wbuf.Len()-20:], hmacBuf)[:4])
	io.CopyN(wbuf, crand.Reader, int64(randLength))
	wbuf.Write(data)
	start := wbuf.Len() - outLength + 4
	wbuf.Write(a.hmac.HMAC(a.userKey, wbuf.Bytes()[start:], hmacBuf)[:4])
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

	key := pool.GetBytesV2(keyLen)
	defer pool.PutBytesV2(key)

	copy(key.Bytes(), a.userKey)

	hmacBuf := pool.GetBytes(6)
	defer pool.PutBytes(hmacBuf)

	for remain := datalen; remain > 4; remain = datalen - readLen {
		binary.LittleEndian.PutUint32(key.After(keyLen-4), a.recvID)
		if !bytes.Equal(a.hmac.HMAC(key.Bytes(), data[0:2], hmacBuf)[:2], data[2:4]) {
			return 0, ssr.ErrAuthAES128IncorrectHMAC
		}

		clen := int(binary.LittleEndian.Uint16(data[0:2]))
		cdlen := clen - 4

		if clen >= 8192 || clen < 7 {
			a.rawTrans = true
			return 0, ssr.ErrAuthAES128DataLengthError
		}

		if clen > remain {
			break
		}

		if !bytes.Equal(a.hmac.HMAC(key.Bytes(), data[:cdlen], hmacBuf)[:4], data[cdlen:clen]) {
			a.rawTrans = true
			return 0, ssr.ErrAuthAES128IncorrectChecksum
		}

		a.recvID = (a.recvID + 1) & 0xFFFFFFFF

		pos := int(data[4])
		if pos >= 255 {
			pos = int(binary.LittleEndian.Uint16(data[5:7]))
		}
		pos += 4

		if pos > cdlen {
			return 0, ssr.ErrAuthAES128PosOutOfRange
		}

		rbuf.Write(data[pos:cdlen])

		data, readLen = data[clen:], readLen+clen
	}

	return readLen, nil
}

// https://github.com/shadowsocksrr/shadowsocksr/blob/fd723a92c488d202b407323f0512987346944136/shadowsocks/obfsplugin/auth.py#L749
func (a *authAES128) EncryptPacket(b []byte) ([]byte, error) {
	hmacBuf := pool.GetBytes(6)
	defer pool.PutBytes(hmacBuf)

	wbuf := make([]byte, 0, len(b)+len(a.uid)+4)
	wbuf = append(wbuf, b...)
	wbuf = append(wbuf, a.uid[:]...)
	wbuf = append(wbuf, a.hmac.HMAC(a.userKey, wbuf, hmacBuf)[:4]...)

	return wbuf, nil
}

// https://github.com/shadowsocksrr/shadowsocksr/blob/fd723a92c488d202b407323f0512987346944136/shadowsocks/obfsplugin/auth.py#L764
func (a *authAES128) DecryptPacket(b []byte) ([]byte, error) {
	hmacBuf := pool.GetBytes(6)
	defer pool.PutBytes(hmacBuf)
	if !bytes.Equal(a.hmac.HMAC(a.info.Key(), b[:len(b)-4], hmacBuf)[:4], b[len(b)-4:]) {
		return nil, ssr.ErrAuthAES128IncorrectChecksum
	}

	return b[:len(b)-4], nil
}

func (a *authAES128) GetOverhead() int { return 9 }
