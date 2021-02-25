package utils

const (
	Shadowsocks  float64 = 1
	Shadowsocksr float64 = 2
	Vmess        float64 = 3

	Remote float64 = 100
	Manual float64 = 101
)

type NodeMessage struct {
	NType   float64 `json:"n_type"`
	NHash   string  `json:"hash"`
	NName   string  `json:"name"`
	NGroup  string  `json:"group"`
	NOrigin float64 `json:"n_origin"`
}

func I2String(i interface{}) string {
	switch i.(type) {
	case string:
		return i.(string)
	default:
		return ""
	}
}

func I2Float64(i interface{}) float64 {
	x, ok := i.(float64)
	if !ok {
		return 0
	}
	return x
}

func I2Bool(i interface{}) bool {
	x, ok := i.(bool)
	if !ok {
		return false
	}
	return x
}
