package vmess

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	rand3 "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"net"
	"time"

	"github.com/Asutorufa/yuhaiin/pkg/net/utils"
)

// copy from https://github.com/v2fly/v2ray-core/tree/054e6679830885c94cc37d27ab2aa96b5b37e019/proxy/vmess/aead
const (
	KDFSaltConstAuthIDEncryptionKey             = "AES Auth ID Encryption"
	KDFSaltConstAEADRespHeaderLenKey            = "AEAD Resp Header Len Key"
	KDFSaltConstAEADRespHeaderLenIV             = "AEAD Resp Header Len IV"
	KDFSaltConstAEADRespHeaderPayloadKey        = "AEAD Resp Header Key"
	KDFSaltConstAEADRespHeaderPayloadIV         = "AEAD Resp Header IV"
	KDFSaltConstVMessAEADKDF                    = "VMess AEAD KDF"
	KDFSaltConstVMessHeaderPayloadAEADKey       = "VMess Header AEAD Key"
	KDFSaltConstVMessHeaderPayloadAEADIV        = "VMess Header AEAD Nonce"
	KDFSaltConstVMessHeaderPayloadLengthAEADKey = "VMess Header AEAD Key_Length"
	KDFSaltConstVMessHeaderPayloadLengthAEADIV  = "VMess Header AEAD Nonce_Length"
)

func KDF(key []byte, path ...string) []byte {
	hmacCreator := &hMacCreator{value: []byte(KDFSaltConstVMessAEADKDF)}
	for _, v := range path {
		hmacCreator = &hMacCreator{value: []byte(v), parent: hmacCreator}
	}
	hmacf := hmacCreator.Create()
	hmacf.Write(key)
	return hmacf.Sum(nil)
}

type hMacCreator struct {
	parent *hMacCreator
	value  []byte
}

func (h *hMacCreator) Create() hash.Hash {
	if h.parent == nil {
		return hmac.New(sha256.New, h.value)
	}
	return hmac.New(h.parent.Create, h.value)
}

func KDF16(key []byte, path ...string) []byte {
	r := KDF(key, path...)
	return r[:16]
}

func CreateAuthID(cmdKey []byte, time int64) [16]byte {
	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.BigEndian, time)
	var zero uint32
	io.CopyN(buf, rand3.Reader, 4)
	zero = crc32.ChecksumIEEE(buf.Bytes())
	binary.Write(buf, binary.BigEndian, zero)
	aesBlock := NewCipherFromKey(cmdKey)
	if buf.Len() != 16 {
		panic("Size unexpected")
	}
	var result [16]byte
	aesBlock.Encrypt(result[:], buf.Bytes())
	return result
}

func NewCipherFromKey(cmdKey []byte) cipher.Block {
	aesBlock, err := aes.NewCipher(KDF16(cmdKey, KDFSaltConstAuthIDEncryptionKey))
	if err != nil {
		panic(err)
	}
	return aesBlock
}

func SealVMessAEADHeader(key [16]byte, data []byte) []byte {
	generatedAuthID := CreateAuthID(key[:], time.Now().Unix())

	connectionNonce := utils.GetBytes(8)
	defer utils.PutBytes(connectionNonce)

	connectionNonce = connectionNonce[:8]
	if _, err := io.ReadFull(rand3.Reader, connectionNonce); err != nil {
		panic(err.Error())
	}

	aeadPayloadLengthSerializeBuffer := bytes.NewBuffer(nil)

	headerPayloadDataLen := uint16(len(data))

	binary.Write(aeadPayloadLengthSerializeBuffer, binary.BigEndian, headerPayloadDataLen)

	aeadPayloadLengthSerializedByte := aeadPayloadLengthSerializeBuffer.Bytes()
	var payloadHeaderLengthAEADEncrypted []byte

	{
		payloadHeaderLengthAEADKey := KDF16(key[:], KDFSaltConstVMessHeaderPayloadLengthAEADKey, string(generatedAuthID[:]), string(connectionNonce))

		payloadHeaderLengthAEADNonce := KDF(key[:], KDFSaltConstVMessHeaderPayloadLengthAEADIV, string(generatedAuthID[:]), string(connectionNonce))[:12]

		payloadHeaderLengthAEADAESBlock, err := aes.NewCipher(payloadHeaderLengthAEADKey)
		if err != nil {
			panic(err.Error())
		}

		payloadHeaderAEAD, err := cipher.NewGCM(payloadHeaderLengthAEADAESBlock)
		if err != nil {
			panic(err.Error())
		}

		payloadHeaderLengthAEADEncrypted = payloadHeaderAEAD.Seal(nil, payloadHeaderLengthAEADNonce, aeadPayloadLengthSerializedByte, generatedAuthID[:])
	}

	var payloadHeaderAEADEncrypted []byte

	{
		payloadHeaderAEADKey := KDF16(key[:], KDFSaltConstVMessHeaderPayloadAEADKey, string(generatedAuthID[:]), string(connectionNonce))

		payloadHeaderAEADNonce := KDF(key[:], KDFSaltConstVMessHeaderPayloadAEADIV, string(generatedAuthID[:]), string(connectionNonce))[:12]

		payloadHeaderAEADAESBlock, err := aes.NewCipher(payloadHeaderAEADKey)
		if err != nil {
			panic(err.Error())
		}

		payloadHeaderAEAD, err := cipher.NewGCM(payloadHeaderAEADAESBlock)
		if err != nil {
			panic(err.Error())
		}

		payloadHeaderAEADEncrypted = payloadHeaderAEAD.Seal(nil, payloadHeaderAEADNonce, data, generatedAuthID[:])
	}

	outputBuffer := bytes.NewBuffer(nil)

	outputBuffer.Write(generatedAuthID[:])               // 16
	outputBuffer.Write(payloadHeaderLengthAEADEncrypted) // 2+16
	outputBuffer.Write(connectionNonce)                  // 8
	outputBuffer.Write(payloadHeaderAEADEncrypted)

	return outputBuffer.Bytes()
}

func OpenVMessAEADHeader(key [16]byte, authid [16]byte, data io.Reader) ([]byte, bool, int, error) {
	var payloadHeaderLengthAEADEncrypted [18]byte
	var nonce [8]byte

	var bytesRead int

	authidCheckValueReadBytesCounts, err := io.ReadFull(data, payloadHeaderLengthAEADEncrypted[:])
	bytesRead += authidCheckValueReadBytesCounts
	if err != nil {
		return nil, false, bytesRead, err
	}

	nonceReadBytesCounts, err := io.ReadFull(data, nonce[:])
	bytesRead += nonceReadBytesCounts
	if err != nil {
		return nil, false, bytesRead, err
	}

	// Decrypt Length

	var decryptedAEADHeaderLengthPayloadResult []byte

	{
		payloadHeaderLengthAEADKey := KDF16(key[:], KDFSaltConstVMessHeaderPayloadLengthAEADKey, string(authid[:]), string(nonce[:]))

		payloadHeaderLengthAEADNonce := KDF(key[:], KDFSaltConstVMessHeaderPayloadLengthAEADIV, string(authid[:]), string(nonce[:]))[:12]

		payloadHeaderAEADAESBlock, err := aes.NewCipher(payloadHeaderLengthAEADKey)
		if err != nil {
			panic(err.Error())
		}

		payloadHeaderLengthAEAD, err := cipher.NewGCM(payloadHeaderAEADAESBlock)
		if err != nil {
			panic(err.Error())
		}

		decryptedAEADHeaderLengthPayload, erropenAEAD := payloadHeaderLengthAEAD.Open(nil, payloadHeaderLengthAEADNonce, payloadHeaderLengthAEADEncrypted[:], authid[:])

		if erropenAEAD != nil {
			return nil, true, bytesRead, erropenAEAD
		}

		decryptedAEADHeaderLengthPayloadResult = decryptedAEADHeaderLengthPayload
	}

	var length uint16

	binary.Read(bytes.NewReader(decryptedAEADHeaderLengthPayloadResult), binary.BigEndian, &length)

	var decryptedAEADHeaderPayloadR []byte

	var payloadHeaderAEADEncryptedReadedBytesCounts int

	{
		payloadHeaderAEADKey := KDF16(key[:], KDFSaltConstVMessHeaderPayloadAEADKey, string(authid[:]), string(nonce[:]))

		payloadHeaderAEADNonce := KDF(key[:], KDFSaltConstVMessHeaderPayloadAEADIV, string(authid[:]), string(nonce[:]))[:12]

		// 16 == AEAD Tag size
		payloadHeaderAEADEncrypted := make([]byte, length+16)

		payloadHeaderAEADEncryptedReadedBytesCounts, err = io.ReadFull(data, payloadHeaderAEADEncrypted)
		bytesRead += payloadHeaderAEADEncryptedReadedBytesCounts
		if err != nil {
			return nil, false, bytesRead, err
		}

		payloadHeaderAEADAESBlock, err := aes.NewCipher(payloadHeaderAEADKey)
		if err != nil {
			panic(err.Error())
		}

		payloadHeaderAEAD, err := cipher.NewGCM(payloadHeaderAEADAESBlock)
		if err != nil {
			panic(err.Error())
		}

		decryptedAEADHeaderPayload, erropenAEAD := payloadHeaderAEAD.Open(nil, payloadHeaderAEADNonce, payloadHeaderAEADEncrypted, nil)

		if erropenAEAD != nil {
			return nil, true, bytesRead, erropenAEAD
		}

		decryptedAEADHeaderPayloadR = decryptedAEADHeaderPayload
	}

	return decryptedAEADHeaderPayloadR, false, bytesRead, nil
}

// from https://github.com/v2ray/v2ray-core/blob/5dffca84234a74da9e8174f1e0b0af3dfb2a58ce/proxy/vmess/encoding/client.go#L191
func DecodeResponseHeader(responseBodyKey, responseBodyIV []byte, reader net.Conn) ([]byte, error) {
	aeadResponseHeaderLengthEncryptionKey := KDF16(responseBodyKey[:], KDFSaltConstAEADRespHeaderLenKey)
	aeadResponseHeaderLengthEncryptionIV := KDF(responseBodyIV[:], KDFSaltConstAEADRespHeaderLenIV)[:12]

	aeadResponseHeaderLengthEncryptionKeyAESBlock, err := aes.NewCipher(aeadResponseHeaderLengthEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher failed: %w", err)
	}
	aeadResponseHeaderLengthEncryptionAEAD, err := cipher.NewGCM(aeadResponseHeaderLengthEncryptionKeyAESBlock)
	if err != nil {
		return nil, fmt.Errorf("create aead failed: %w", err)
	}

	var aeadEncryptedResponseHeaderLength [18]byte
	var decryptedResponseHeaderLength int
	var decryptedResponseHeaderLengthBinaryDeserializeBuffer uint16

	if _, err := io.ReadFull(reader, aeadEncryptedResponseHeaderLength[:]); err != nil {
		return nil, fmt.Errorf("read encrypted response header length failed: %w", err)
	}
	if decryptedResponseHeaderLengthBinaryBuffer, err := aeadResponseHeaderLengthEncryptionAEAD.Open(nil, aeadResponseHeaderLengthEncryptionIV, aeadEncryptedResponseHeaderLength[:], nil); err != nil {
		return nil, fmt.Errorf("decrypt response header length failed: %w", err)
	} else {
		binary.Read(bytes.NewReader(decryptedResponseHeaderLengthBinaryBuffer), binary.BigEndian, &decryptedResponseHeaderLengthBinaryDeserializeBuffer)
		decryptedResponseHeaderLength = int(decryptedResponseHeaderLengthBinaryDeserializeBuffer)
	}

	aeadResponseHeaderPayloadEncryptionKey := KDF16(responseBodyKey[:], KDFSaltConstAEADRespHeaderPayloadKey)
	aeadResponseHeaderPayloadEncryptionIV := KDF(responseBodyIV[:], KDFSaltConstAEADRespHeaderPayloadIV)[:12]

	aeadResponseHeaderPayloadEncryptionKeyAESBlock, err := aes.NewCipher(aeadResponseHeaderPayloadEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher failed: %w", err)
	}
	aeadResponseHeaderPayloadEncryptionAEAD, err := cipher.NewGCM(aeadResponseHeaderPayloadEncryptionKeyAESBlock)
	if err != nil {
		return nil, fmt.Errorf("create aead failed: %w", err)
	}

	encryptedResponseHeaderBuffer := make([]byte, decryptedResponseHeaderLength+16)

	if _, err := io.ReadFull(reader, encryptedResponseHeaderBuffer); err != nil {
		return nil, fmt.Errorf("read encrypted response header failed: %w", err)
	}

	decryptedResponseHeaderBuffer, err := aeadResponseHeaderPayloadEncryptionAEAD.Open(nil, aeadResponseHeaderPayloadEncryptionIV, encryptedResponseHeaderBuffer, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt response header failed: %w", err)
	}

	return decryptedResponseHeaderBuffer, nil
}
