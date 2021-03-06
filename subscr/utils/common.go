package subscr

const (
	Shadowsocks  float64 = 1
	Shadowsocksr float64 = 2
	Vmess        float64 = 3

	Remote float64 = 100
	Manual float64 = 101
)

type NodeMessage struct {
	NType   float64 `json:"yuhaiin_type"`
	NHash   string  `json:"yuhaiin_hash"`
	NName   string  `json:"yuhaiin_name"`
	NGroup  string  `json:"yuhaiin_group"`
	NOrigin float64 `json:"yuhaiin_origin"`
}

type Link struct {
	Type string `json:"type"`
	Url  string `json:"url"`
}

type Node struct {
	NowNode *Point                       `json:"nowNode"`
	Link    []string                     `json:"link"`
	Links   map[string]Link              `json:"links"`
	Node    map[string]map[string]*Point `json:"node"`
}

type Point struct {
	NodeMessage
	Data []byte
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
