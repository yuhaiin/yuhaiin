package subscr

const (
	shadowsocks  float64 = 1
	shadowsocksr float64 = 2
)

type NodeMessage struct {
	NType  float64 `json:"type"`
	NHash  string  `json:"hash"`
	NName  string  `json:"name"`
	NGroup string  `json:"group"`
}

func interface2string(i interface{}) string {
	switch i.(type) {
	case string:
		return i.(string)
	default:
		return ""
	}
}
