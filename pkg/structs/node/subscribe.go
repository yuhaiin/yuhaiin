package node

type SubscribeType int32

const (
	SubscribeTypeReserve     SubscribeType = 0
	SubscribeTypeTrojan      SubscribeType = 1
	SubscribeTypeVmess       SubscribeType = 2
	SubscribeTypeShadowsocks SubscribeType = 3
	SubscribeTypeShadowsocksr SubscribeType = 4
)

type Link struct {
	Name string        `json:"name"`
	Type SubscribeType `json:"type"`
	Url  string        `json:"url"`
}

type Publish struct {
	Points   []string `json:"points"`
	Path     string   `json:"path"`
	Name     string   `json:"name"`
	Password string   `json:"password"`
}

type YuhaiinUrl struct {
	Url  YuhaiinUrlChoice `json:"url"`
	Name string            `json:"name"`
}

type YuhaiinUrlChoiceType int32

const (
	YuhaiinUrlChoiceTypeRemote YuhaiinUrlChoiceType = 0
	YuhaiinUrlChoiceTypePoints YuhaiinUrlChoiceType = 1
)

type YuhaiinUrlChoice struct {
	Type   YuhaiinUrlChoiceType `json:"type"`
	Remote *YuhaiinUrlRemote    `json:"remote,omitempty"`
	Points *YuhaiinUrlPoints    `json:"points,omitempty"`
}

type YuhaiinUrlRemote struct {
	Url      string   `json:"url"`
	Insecure bool     `json:"insecure"`
	Publish  *Publish `json:"publish"`
}

type YuhaiinUrlPoints struct {
	Points []Point `json:"points"`
}
