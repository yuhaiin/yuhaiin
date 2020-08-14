package common

const (
	Shadowsocks  float64 = 1
	Shadowsocksr float64 = 2

	Remote float64 = 100
	Manual float64 = 101
)

type NodeMessage struct {
	NType   float64 `json:"type"`
	NHash   string  `json:"hash"`
	NName   string  `json:"name"`
	NGroup  string  `json:"group"`
	NOrigin float64 `json:"n_origin"`
}

func Interface2string(i interface{}) string {
	switch i.(type) {
	case string:
		return i.(string)
	default:
		return ""
	}
}
