package protocol

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"io"
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
		recvInfo: recvInfo{
			recvID: 1,
			rbuf:   ssr.GetBuffer(),
			wbuf:   ssr.GetBuffer(),
		},

		key:    info.Key,
		keyLen: info.KeyLen,
		iv:     info.IV,
		ivLen:  info.IVLen,
		param:  info.Param,
		auth:   info.Auth,
	}
	a.initUserKey()
	return a
}

type recvInfo struct {
	recvID uint32
	rbuf   *bytes.Buffer
	wbuf   *bytes.Buffer
}

type authAES128 struct {
	recvInfo
	auth          *AuthData
	hasSentHeader bool
	packID        uint32
	userKey       []byte
	uid           [4]byte
	salt          string
	hmac          hmacMethod
	hashDigest    hashDigestMethod

	key, iv       []byte
	keyLen, ivLen int

	param string
}

func (a *authAES128) packData(data []byte) {
	dataLength := len(data)
	randLength := 1

	if dataLength <= 1200 {
		if a.packID > 4 {
			randLength += rand.Intn(32)
		} else {
			if dataLength > 900 {
				randLength += rand.Intn(128)
			} else {
				randLength += rand.Intn(512)
			}
		}
	}

	outLength := randLength + dataLength + 8

	key := make([]byte, len(a.userKey)+4)
	copy(key, a.userKey)
	binary.LittleEndian.PutUint32(key[len(key)-4:], a.packID)

	a.packID++

	// 0~1, out length
	binary.Write(a.wbuf, binary.LittleEndian, uint16(outLength&0xFFFF))

	// 2~3, hmac
	a.wbuf.Write(a.hmac(key, a.wbuf.Bytes()[a.wbuf.Len()-2:])[:2])

	// 4, rand length
	if randLength < 128 {
		a.wbuf.WriteByte(byte(randLength & 0xFF))
		randLength -= 1
	} else {
		// 4, magic number 0xFF
		a.wbuf.WriteByte(0xFF)
		// 5~6, rand length
		binary.Write(a.wbuf, binary.LittleEndian, uint16(randLength&0xFFFF))
		randLength -= 3
	}

	// 4~rand length+4, rand number
	a.wbuf.ReadFrom(io.LimitReader(crand.Reader, int64(randLength)))

	// rand length+4~out length-4, data
	a.wbuf.Write(data)

	// hmac
	a.wbuf.Write(a.hmac(key, a.wbuf.Bytes()[a.wbuf.Len()-outLength+4:])[:4])

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

func (a *authAES128) packAuthData(data []byte) {
	dataLength := len(data)

	var randLength int
	if dataLength > 400 {
		randLength = rand.Intn(512)
	} else {
		randLength = rand.Intn(1024)
	}

	outLength := randLength + 16 + 4 + 4 + 7 + dataLength + 4

	aesCipherKey := ssr.EVPBytesToKey(base64.StdEncoding.EncodeToString(a.userKey)+a.salt, 16)
	block, err := aes.NewCipher(aesCipherKey)
	if err != nil {
		return
	}

	encrypt := utils.GetBytes(16)
	defer utils.PutBytes(encrypt)

	a.auth.nextAuth()
	now := time.Now().Unix()
	binary.LittleEndian.PutUint32(encrypt[0:4], uint32(now))
	copy(encrypt[4:], a.auth.clientID)
	binary.LittleEndian.PutUint32(encrypt[8:], a.auth.connectionID)
	binary.LittleEndian.PutUint16(encrypt[12:], uint16(outLength&0xFFFF))
	binary.LittleEndian.PutUint16(encrypt[14:], uint16(randLength&0xFFFF))

	iv := make([]byte, aes.BlockSize)
	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(encrypt[:16], encrypt[:16])

	key := make([]byte, a.ivLen+a.keyLen)
	copy(key, a.iv)
	copy(key[a.ivLen:], a.key)

	a.wbuf.Write([]byte{byte(rand.Intn(256))})
	a.wbuf.Write(a.hmac(key, a.wbuf.Bytes()[a.wbuf.Len()-1:])[0 : 7-1])
	a.wbuf.Write(a.uid[:])
	a.wbuf.Write(encrypt[:16])
	a.wbuf.Write(a.hmac(key, a.wbuf.Bytes()[a.wbuf.Len()-20:])[0:4])
	a.wbuf.ReadFrom(io.LimitReader(crand.Reader, int64(randLength)))
	a.wbuf.Write(data)
	a.wbuf.Write(a.hmac(a.userKey, a.wbuf.Bytes()[a.wbuf.Len()-outLength+4:])[0:4])
}

func (a *authAES128) EncryptStream(data []byte) (_ []byte, err error) {
	dataLen := len(data)

	if dataLen <= 0 {
		return nil, nil
	}

	a.wbuf.Reset()

	if !a.hasSentHeader {
		authLen := dataLen
		if authLen > 1200 {
			authLen = 1200
		}

		a.packAuthData(data[:authLen])

		a.hasSentHeader = true
		data = data[authLen:]
	}

	const blockSize = 4096
	for len(data) > blockSize {
		a.packData(data[:blockSize])
		data = data[blockSize:]
	}
	a.packData(data)

	return a.wbuf.Bytes(), nil
}

func (a *authAES128) DecryptStream(data []byte) ([]byte, int, error) {
	a.rbuf.Reset()

	datalen, readLen := len(data), 0

	keyLen := len(a.userKey) + 4
	key := utils.GetBytes(keyLen)
	defer utils.PutBytes(key)
	copy(key[0:], a.userKey)

	for datalen > 4 {
		clen := int(binary.LittleEndian.Uint16(data[0:2]))
		if clen >= 8192 || clen < 7 {
			return nil, 0, ssr.ErrAuthAES128DataLengthError
		}

		if clen > datalen {
			break
		}

		binary.LittleEndian.PutUint32(key[keyLen-4:], a.recvID)
		a.recvID++

		if !bytes.Equal(a.hmac(key[:keyLen], data[0:2])[:2], data[2:4]) {
			return nil, 0, ssr.ErrAuthAES128IncorrectHMAC
		}

		if !bytes.Equal(a.hmac(key[:keyLen], data[:clen-4])[:4], data[clen-4:clen]) {
			return nil, 0, ssr.ErrAuthAES128IncorrectChecksum
		}

		pos := int(data[4])
		if pos < 255 {
			pos += 4
		} else {
			pos = int(binary.LittleEndian.Uint16(data[5:7])) + 4
		}

		if pos > clen-4 {
			return nil, 0, ssr.ErrAuthAES128PosOutOfRange
		}

		a.rbuf.Write(data[pos : clen-4])

		data, datalen, readLen = data[clen:], datalen-clen, readLen+clen
	}

	return a.rbuf.Bytes(), readLen, nil
}

func (a *authAES128) EncryptPacket(b []byte) ([]byte, error) {
	a.wbuf.Reset()
	a.wbuf.Write(b)
	a.wbuf.Write(a.uid[:])
	a.wbuf.Write(a.hmac(a.userKey, a.wbuf.Bytes())[:4])
	return a.wbuf.Bytes(), nil
}

func (a *authAES128) DecryptPacket(b []byte) ([]byte, error) {
	if !bytes.Equal(a.hmac(a.key, b[:len(b)-4])[:4], b[len(b)-4:]) {
		return nil, ssr.ErrAuthAES128IncorrectChecksum
	}

	return b[:len(b)-4], nil
}

func (a *authAES128) GetOverhead() int {
	return 9
}

func (a *recvInfo) Close() error {
	ssr.PutBuffer(a.wbuf)
	ssr.PutBuffer(a.rbuf)

	return nil
}
