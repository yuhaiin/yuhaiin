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

// ShareFeedContentType identifies a share feed document. Subscribers use it to
// tell a yuhaiin share feed apart from a base64 share-link subscription.
const ShareFeedContentType = "application/vnd.yuhaiin.share+json"

// Share feed entry kinds. A group entry follows the group as it changes.
const (
	ShareFeedEntryGroup = "group"
	ShareFeedEntryNode  = "node"
)

// Reasons a selected node is left out of a share feed.
const (
	ShareFeedSkipDisabled        = "disabled"
	ShareFeedSkipLocalReferences = "references_local_nodes"
	ShareFeedSkipLocalCredential = "uses_local_credential"
	ShareFeedSkipDuplicate       = "duplicate"
)

type ShareFeedEntry struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// ShareFeed publishes the nodes selected by Entries to anyone holding Token.
// The token is generated and rotated by the server; clients never set it.
type ShareFeed struct {
	ID          string           `json:"id"`
	Name        string           `json:"name"`
	Enabled     bool             `json:"enabled"`
	Token       string           `json:"token" secret:"true"`
	BaseURL     string           `json:"baseUrl"`
	Entries     []ShareFeedEntry `json:"entries"`
	CreatedAt   int64            `json:"createdAt"`
	UpdatedAt   int64            `json:"updatedAt"`
	LastAccess  int64            `json:"lastAccess"`
	AccessCount int64            `json:"accessCount"`
}

type ShareFeedList struct {
	Items []ShareFeed `json:"items"`
}

type ShareFeedID struct {
	ID string `json:"id"`
}

type ShareFeedPreviewRequest struct {
	Entries []ShareFeedEntry `json:"entries"`
}

type ShareFeedPreviewNode struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Group string `json:"group"`
	// From is "node" or "group:<name>".
	From string `json:"from"`
}

type ShareFeedSkippedNode struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Reason string `json:"reason"`
}

type ShareFeedPreview struct {
	Nodes   []ShareFeedPreviewNode `json:"nodes"`
	Skipped []ShareFeedSkippedNode `json:"skipped"`
	Missing []ShareFeedEntry       `json:"missing"`
}

// ShareFeedDocument is the public response body of a share feed.
type ShareFeedDocument struct {
	Version     int                 `json:"version"`
	Name        string              `json:"name"`
	GeneratedAt int64               `json:"generatedAt"`
	Nodes       []contractnode.Node `json:"nodes"`
}

func (l Link) SecretResourceID() string      { return l.Name }
func (f ShareFeed) SecretResourceID() string { return f.ID }
