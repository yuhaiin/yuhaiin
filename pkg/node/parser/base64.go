package parser

import (
	"bytes"
	"encoding/base64"
	"log"
	"strings"
)

// DecodeUrlBase64 decode url safe base64 string, auto add '=' if not enough
func DecodeUrlBase64(str string) string {
	if l := len(str) % 4; l != 0 {
		str += strings.Repeat("=", 4-l)
	}
	data, err := base64.URLEncoding.DecodeString(str)
	if err != nil {
		log.Println(err)
	}
	return string(data)
}

// DecodeUrlBase64Bytes decode url safe base64 string, auto add '=' if not enough
func DecodeUrlBase64Bytes(str []byte) []byte {
	if l := len(str) % 4; l != 0 {
		str = append(str, bytes.Repeat([]byte{'='}, 4-l)...)
	}
	data := make([]byte, base64.URLEncoding.DecodedLen(len(str)))
	_, err := base64.URLEncoding.Decode(data, str)
	if err != nil {
		log.Println(err)
	}
	return data
}

// DecodeBase64 decode base64 string, auto add '=' if not enough
func DecodeBase64(str string) string {
	if l := len(str) % 4; l != 0 {
		str += strings.Repeat("=", 4-l)
	}
	data, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		log.Println(err)
	}
	return string(data)
}

// DecodeBase64Bytes decode base64 string, auto add '=' if not enough
func DecodeBase64Bytes(str []byte) []byte {
	if l := len(str) % 4; l != 0 {
		str = append(str, bytes.Repeat([]byte{'='}, 4-l)...)
	}
	data := make([]byte, base64.StdEncoding.DecodedLen(len(str)))
	_, err := base64.StdEncoding.Decode(data, str)
	if err != nil {
		log.Println(err, string(str))
	}
	return data
}

// DecodeBytesBase64 decode base64 string, auto add '=' if not enough
func DecodeBytesBase64(str []byte) ([]byte, error) {
	if l := len(str) % 4; l != 0 {
		str = append(str, bytes.Repeat([]byte{'='}, 4-l)...)
	}

	data := make([]byte, base64.StdEncoding.DecodedLen(len(str)))
	_, err := base64.StdEncoding.Decode(data, str)
	return data, err
}
