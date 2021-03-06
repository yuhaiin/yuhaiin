package utils

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
	Links   map[string]Link              `json:"links"`
	Node    map[string]map[string]*Point `json:"node"`
}

type Point struct {
	NodeMessage
	Data []byte
}
