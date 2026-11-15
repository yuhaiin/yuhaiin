package node

import (
	"bytes"
	json "encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	contractnode "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	contractsubscription "github.com/Asutorufa/yuhaiin/pkg/contract/subscription"
)

func fetchTestRuntime(t *testing.T) (*Subscribe, func() []string) {
	t.Helper()
	previous := newSubscriptionClient
	newSubscriptionClient = func() *http.Client { return http.DefaultClient }
	t.Cleanup(func() { newSubscriptionClient = previous })
	runtime := newTestRuntime(t)
	names := func() []string {
		nodes, err := runtime.openNodes(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		list, err := nodes.List(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, node := range list {
			if node.Group != "sub" || node.Origin != "remote" {
				t.Fatalf("subscribed node has group %q origin %q", node.Group, node.Origin)
			}
			out = append(out, node.Name)
		}
		return out
	}
	return &Subscribe{runtime: runtime}, names
}

const shareFeedFixture = `{"version":1,"name":"f","generatedAt":1,"nodes":[{"id":"n1","name":"shared","group":"theirs","origin":"manual","enabled":true,"chain":[{"type":"direct","direct":{}}]}]}`

func TestFetchShareFeedAndKeepNodesOnFailure(t *testing.T) {
	subscribe, names := fetchTestRuntime(t)
	response := struct {
		status      int
		contentType string
		body        string
	}{http.StatusOK, contractsubscription.ShareFeedContentType + "; charset=utf-8", shareFeedFixture}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept"), contractsubscription.ShareFeedContentType) {
			t.Errorf("Accept = %q", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", response.contentType)
		w.WriteHeader(response.status)
		_, _ = fmt.Fprint(w, response.body)
	}))
	defer server.Close()
	link := contractsubscription.Link{Name: "sub", URL: server.URL + "/share/token", Type: "reserve"}

	if err := subscribe.fetch(t.Context(), link); err != nil {
		t.Fatal(err)
	}
	if got := names(); len(got) != 1 || got[0] != "shared" {
		t.Fatalf("nodes = %v", got)
	}

	for _, failure := range []struct {
		status            int
		contentType, body string
	}{
		{http.StatusNotFound, "text/plain", "404 page not found"},
		{http.StatusOK, contractsubscription.ShareFeedContentType, `{"version":2,"nodes":[]}`},
		{http.StatusOK, contractsubscription.ShareFeedContentType, `not json`},
		{http.StatusOK, "text/html", "<html>login</html>"},
	} {
		response.status, response.contentType, response.body = failure.status, failure.contentType, failure.body
		if err := subscribe.fetch(t.Context(), link); err == nil {
			t.Fatalf("accepted %+v", failure)
		}
		if got := names(); len(got) != 1 {
			t.Fatalf("failed fetch %+v replaced nodes: %v", failure, got)
		}
	}

	// An empty share feed is the publisher's current selection.
	response.status, response.contentType, response.body = http.StatusOK, contractsubscription.ShareFeedContentType, `{"version":1,"nodes":[]}`
	if err := subscribe.fetch(t.Context(), link); err != nil {
		t.Fatal(err)
	}
	if got := names(); len(got) != 0 {
		t.Fatalf("empty feed kept nodes: %v", got)
	}
}

// The subscriber must read exactly what the publisher's handler encodes.
func TestReadShareFeedMatchesPublishedDocument(t *testing.T) {
	document := contractsubscription.ShareFeedDocument{Version: 1, Name: "f", GeneratedAt: 1, Nodes: []contractnode.Node{
		{ID: "n1", Name: "shared", Group: "g", Origin: "manual", Enabled: true, Chain: []contractnode.Protocol{{Type: "direct", Direct: &contractnode.Direct{}}}},
	}}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := readShareFeed(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 || nodes[0].ID != "n1" || nodes[0].Name != "shared" || len(nodes[0].Chain) != 1 {
		t.Fatalf("nodes = %+v", nodes)
	}
}
