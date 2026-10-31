package subscription

import contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"

type Link struct {
	Name string `json:"name"`
	URL  string `json:"url" secret:"true"`
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
	Path     string   `json:"path" secret:"true"`
	Password string   `json:"password" secret:"true"`
	Address  string   `json:"address" privilege:"secrets:bound"`
	Insecure bool     `json:"insecure" privilege:"secrets:bound"`
}

type PublishList struct {
	Items []Publish `json:"items"`
}

type ResolvePublishRequest struct {
	Name     string `json:"name"`
	Password string `json:"password" secret:"true"`
	Path     string `json:"path" secret:"true"`
}

type ResolvePublishResponse struct {
	Points []contractnode.Node `json:"points"`
}

func (l Link) SecretResourceID() string    { return l.Name }
func (p Publish) SecretResourceID() string { return p.Name }
