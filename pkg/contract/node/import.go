package node

// ImportCommit retains preview IDs while submitting the caller's original
// source. Raw credentials never need to return through a preview response.
type ImportCommit struct {
	Text    string   `json:"text"`
	Group   string   `json:"group"`
	IDs     []string `json:"ids"`
	Indices []int    `json:"indices,omitzero"`
}

type ImportResult struct {
	Index int    `json:"index"`
	ID    string `json:"id"`
	Saved bool   `json:"saved"`
	Error string `json:"error,omitempty"`
}

type ImportResults struct {
	Items []ImportResult `json:"items"`
}
