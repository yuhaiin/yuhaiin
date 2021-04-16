package utils

import (
	"encoding/base64"
	"log"
)

// DecodeUrlBase64 decode url safe base64 string, auto add '=' if not enough
func DecodeUrlBase64(str string) string {
	l := len(str)
	if l%4 != 0 {
		for i := 0; i < 4-l%4; i++ {
			str += "="
		}
	}
	deStr, err := base64.URLEncoding.DecodeString(str)
	if err != nil {
		log.Println(err)
	}
	return string(deStr)
}

// DecodeBase64 decode base64 string, auto add '=' if not enough
func DecodeBase64(str string) string {
	l := len(str)
	if l%4 != 0 {
		for i := 0; i < 4-l%4; i++ {
			str += "="
		}
	}
	deStr, err := base64.StdEncoding.DecodeString(str)
	if err != nil {
		log.Println(err)
	}
	return string(deStr)
}

// DecodeBytesBase64 decode base64 string, auto add '=' if not enough
func DecodeBytesBase64(str []byte) ([]byte, error) {
	l := len(str)
	if l%4 != 0 {
		for i := 0; i < 4-l%4; i++ {
			str = append(str, '=')
		}
	}
	deStr := make([]byte, base64.StdEncoding.DecodedLen(len(str)))
	_, err := base64.StdEncoding.Decode(deStr, str)
	return deStr, err
}
