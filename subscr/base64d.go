package subscr

import (
	"encoding/base64"
	"log"
)

// Base64d 对base64进行长度补全(4的倍数)
func Base64d(str string) string {
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

// Base64d 对base64进行长度补全(4的倍数)
func Base64d3(str []byte) ([]byte, error) {
	l := len(str)
	if l%4 != 0 {
		for i := 0; i < 4-l%4; i++ {
			str = append(str, '=')
		}
	}
	dst := make([]byte, base64.URLEncoding.DecodedLen(len(str)))
	_, err := base64.URLEncoding.Decode(dst, str)
	return dst, err
}

// Base64d 对base64进行长度补全(4的倍数)
func Base64d2(str []byte) ([]byte, error) {
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
