package protocol

import (
	"bytes"
	"encoding/binary"
	"math/rand"
	"time"

	ssr "github.com/Asutorufa/yuhaiin/pkg/net/proxy/shadowsocksr/utils"
)

func init() {
	register("auth_sha1_v4", NewAuthSHA1v4)
}

type authSHA1v4 struct {
	ProtocolInfo
	data          *AuthData
	hasSentHeader bool
	buffer        *bytes.Buffer
}

func NewAuthSHA1v4(info ProtocolInfo) IProtocol {
	a := &authSHA1v4{
		ProtocolInfo: info,
		data:         info.Auth,
		buffer:       ssr.GetBuffer(),
	}

	if a.data == nil {
		a.data = &AuthData{}
	}
	return a
}

func (a *authSHA1v4) packData(data []byte) (outData []byte) {
	dataLength := len(data)
	randLength := 1

	if dataLength <= 1300 {
		if dataLength > 400 {
			randLength += rand.Intn(128)
		} else {
			randLength += rand.Intn(1024)
		}
	}

	outLength := randLength + dataLength + 8
	outData = make([]byte, outLength)
	// 0~1, out length
	binary.BigEndian.PutUint16(outData[0:2], uint16(outLength&0xFFFF))
	// 2~3, crc of out length
	crc32 := ssr.CalcCRC32(outData, 2, 0xFFFFFFFF)
	binary.LittleEndian.PutUint16(outData[2:4], uint16(crc32&0xFFFF))
	// 4, rand length
	if randLength < 128 {
		outData[4] = uint8(randLength & 0xFF)
	} else {
		outData[4] = uint8(0xFF)
		binary.BigEndian.PutUint16(outData[5:7], uint16(randLength&0xFFFF))
	}
	// rand length+4~out length-4, data
	if dataLength > 0 {
		copy(outData[randLength+4:], data)
	}
	// out length-4~end, adler32 of full data
	adler := ssr.CalcAdler32(outData[:outLength-4])
	binary.LittleEndian.PutUint32(outData[outLength-4:], adler)

	return outData
}

func (a *authSHA1v4) packAuthData(data []byte) (outData []byte) {

	dataLength := len(data)
	randLength := 1
	if dataLength <= 1300 {
		if dataLength > 400 {
			randLength += rand.Intn(128)
		} else {
			randLength += rand.Intn(1024)
		}
	}
	dataOffset := randLength + 4 + 2
	outLength := dataOffset + dataLength + 12 + ssr.ObfsHMACSHA1Len
	outData = make([]byte, outLength)
	a.data.connectionID++
	if a.data.connectionID > 0xFF000000 {
		a.data.clientID = nil
	}
	if len(a.data.clientID) == 0 {
		a.data.clientID = make([]byte, 8)
		rand.Read(a.data.clientID)
		b := make([]byte, 4)
		rand.Read(b)
		a.data.connectionID = binary.LittleEndian.Uint32(b) & 0xFFFFFF
	}
	// 0-1, out length
	binary.BigEndian.PutUint16(outData[0:2], uint16(outLength&0xFFFF))

	// 2~6, crc of out length+salt+key
	salt := []byte("auth_sha1_v4")
	crcData := make([]byte, len(salt)+a.KeySize+2)
	copy(crcData[0:2], outData[0:2])
	copy(crcData[2:], salt)
	copy(crcData[2+len(salt):], a.Key)
	crc32 := ssr.CalcCRC32(crcData, len(crcData), 0xFFFFFFFF)
	// 2~6, crc of out length+salt+key
	binary.LittleEndian.PutUint32(outData[2:], crc32)
	// 6~rand length+6, rand numbers
	rand.Read(outData[dataOffset-randLength : dataOffset])
	// 6, rand length
	if randLength < 128 {
		outData[6] = byte(randLength & 0xFF)
	} else {
		// 6, magic number 0xFF
		outData[6] = 0xFF
		// 7-8, rand length
		binary.BigEndian.PutUint16(outData[7:9], uint16(randLength&0xFFFF))
	}
	// rand length+6~rand length+10, time stamp
	now := time.Now().Unix()
	binary.LittleEndian.PutUint32(outData[dataOffset:dataOffset+4], uint32(now))
	// rand length+10~rand length+14, client ID
	copy(outData[dataOffset+4:dataOffset+4+4], a.data.clientID[0:4])
	// rand length+14~rand length+18, connection ID
	binary.LittleEndian.PutUint32(outData[dataOffset+8:dataOffset+8+4], a.data.connectionID)
	// rand length+18~rand length+18+data length, data
	copy(outData[dataOffset+12:], data)

	key := make([]byte, a.IVSize+a.KeySize)
	copy(key, a.IV)
	copy(key[a.IVSize:], a.Key)

	h := ssr.HmacSHA1(key, outData[:outLength-ssr.ObfsHMACSHA1Len])
	// out length-10~out length/rand length+18+data length~end, hmac
	copy(outData[outLength-ssr.ObfsHMACSHA1Len:], h[0:ssr.ObfsHMACSHA1Len])
	return outData
}

func (a *authSHA1v4) EncryptStream(plainData []byte) (outData []byte, err error) {
	a.buffer.Reset()
	dataLength := len(plainData)
	offset := 0
	if !a.hasSentHeader && dataLength > 0 {
		headSize := GetHeadSize(plainData, 30)
		if headSize > dataLength {
			headSize = dataLength
		}
		a.buffer.Write(a.packAuthData(plainData[:headSize]))
		offset += headSize
		dataLength -= headSize
		a.hasSentHeader = true
	}
	const blockSize = 4096
	for dataLength > blockSize {
		a.buffer.Write(a.packData(plainData[offset : offset+blockSize]))
		offset += blockSize
		dataLength -= blockSize
	}
	if dataLength > 0 {
		a.buffer.Write(a.packData(plainData[offset:]))
	}

	return a.buffer.Bytes(), nil
}

func (a *authSHA1v4) DecryptStream(plainData []byte) (outData []byte, n int, err error) {
	a.buffer.Reset()
	dataLength := len(plainData)
	plainLength := dataLength
	for dataLength > 4 {
		crc32 := ssr.CalcCRC32(plainData, 2, 0xFFFFFFFF)
		if binary.LittleEndian.Uint16(plainData[2:4]) != uint16(crc32&0xFFFF) {
			//common.Error("auth_sha1_v4 post decrypt data crc32 error")
			return nil, 0, ssr.ErrAuthSHA1v4CRC32Error
		}
		length := int(binary.BigEndian.Uint16(plainData[0:2]))
		if length >= 8192 || length < 8 {
			//common.Error("auth_sha1_v4 post decrypt data length error")
			dataLength = 0
			plainData = nil
			return nil, 0, ssr.ErrAuthSHA1v4DataLengthError
		}
		if length > dataLength {
			break
		}

		if CheckAdler32(plainData, length) {
			pos := int(plainData[4])
			if pos != 0xFF {
				pos += 4
			} else {
				pos = int(binary.BigEndian.Uint16(plainData[5:5+2])) + 4
			}
			outLength := length - pos - 4
			a.buffer.Write(plainData[pos : pos+outLength])
			dataLength -= length
			plainData = plainData[length:]
		} else {
			//common.Error("auth_sha1_v4 post decrypt incorrect checksum")
			dataLength = 0
			plainData = nil
			return nil, 0, ssr.ErrAuthSHA1v4IncorrectChecksum
		}
	}
	return a.buffer.Bytes(), plainLength - dataLength, nil
}

func (a *authSHA1v4) GetOverhead() int {
	return 7
}

func (a *authSHA1v4) Close() error {
	ssr.PutBuffer(a.buffer)

	return nil
}

func calcShortAdler32(input []byte, a, b uint32) (uint32, uint32) {
	for _, i := range input {
		a += uint32(i)
		b += a
	}
	a %= 65521
	b %= 65521
	return a, b
}

func CalcAdler32(input []byte) uint32 {
	var a uint32 = 1
	var b uint32 = 0
	const nMax = 5552
	for length := len(input); length > nMax; length -= nMax {
		a, b = calcShortAdler32(input[:nMax], a, b)
		input = input[nMax:]
	}
	a, b = calcShortAdler32(input, a, b)
	return (b << 16) + a
}

func CheckAdler32(input []byte, l int) bool {
	adler32 := CalcAdler32(input[:l-4])
	checksum := binary.LittleEndian.Uint32(input[l-4:])
	return adler32 == checksum
}

func (a *authSHA1v4) EncryptPacket(b []byte) ([]byte, error) {
	return b, nil
}
func (a *authSHA1v4) DecryptPacket(b []byte) ([]byte, error) {
	return b, nil
}
