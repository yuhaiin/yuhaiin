package subscription

import contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"

type Link struct {
	Name string `json:"name"`
	URL  string `json:"url"`
	Type string `json:"type"`
}

type LinkList struct {
	Items []Link `json:"items"`
}

type LinkNames struct {
	Names []string `json:"names"`
}

type Publish struct {
	Name     string   `json:"name"`
	Points   []string `json:"points"`
	Path     string   `json:"path"`
	Password string   `json:"password"`
	Address  string   `json:"address"`
	Insecure bool     `json:"insecure"`
}

type PublishList struct {
	Items []Publish `json:"items"`
}

type ResolvePublishRequest struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Path     string `json:"path"`
}

type ResolvePublishResponse struct {
	Points []contractnode.Node `json:"points"`
}
