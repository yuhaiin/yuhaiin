package base64d

import (
	"encoding/base64"
)

// Base64d 对base64进行长度补全(4的倍数)
func Base64d(str string) string {
	for i := 0; i <= len(str)%4; i++ {
		str += "="
	}
	deStr, _ := base64.URLEncoding.DecodeString(str)
	return string(deStr)
}

// Base64d 对base64进行长度补全(4的倍数)
func Base64d2(str []byte) ([]byte, error) {
	for i := 0; i <= len(str)%4; i++ {
		str = append(str, '=')
	}
	deStr := make([]byte, base64.StdEncoding.DecodedLen(len(str)))
	_, err := base64.StdEncoding.Decode(deStr, str)
	return deStr, err
}
