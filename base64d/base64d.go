package base64d

import (
	"encoding/base64"
)

//对base64进行长度补全(4的倍数)
func Base64d(str string) string {
	for i := 0; i <= len(str)%4; i++ {
		str += "="
	}
	de_str, _ := base64.URLEncoding.DecodeString(str)
	return string(de_str)
}
