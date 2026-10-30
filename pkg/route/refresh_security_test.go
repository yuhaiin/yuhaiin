package route

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Asutorufa/yuhaiin/pkg/configuration"
	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
	"github.com/Asutorufa/yuhaiin/pkg/log"
	plainstore "github.com/Asutorufa/yuhaiin/pkg/store"
)

type securityListBook struct {
	item contractroute.RouteListDetail
}

func TestGeoIPFailureDoesNotExposeSourcePath(t *testing.T) {
	oldDirectory := configuration.DataDir.Load()
	configuration.DataDir.Store(t.TempDir())
	defer configuration.DataDir.Store(oldDirectory)
	var logs bytes.Buffer
	oldLogger := log.Default()
	log.SetDefault(log.NewSLogger(&logs))
	defer log.SetDefault(oldLogger)
	target := (&url.URL{Scheme: "file", Path: filepath.Join(t.TempDir(), "path-secret")}).String()
	settings := &listSettingsStub{value: RouteListSettings{MaxMindDBDownloadURL: target}}
	lists := NewLists(nil, settings, t.TempDir())
	defer func() { _ = lists.Close() }()
	if lists.LoadGeoip() != nil {
		t.Fatal("missing GeoIP database was loaded")
	}
	_, err := lists.prepareSnapshot(t.Context(), plainstore.RouteSnapshot{ListSettings: settings.value})
	if err == nil {
		t.Fatal("missing GeoIP database was accepted")
	}
	if strings.Contains(err.Error(), "path-secret") || strings.Contains(logs.String(), "path-secret") {
		t.Fatal("GeoIP failure exposed its source path")
	}
}

func (s *securityListBook) ListRouteListDetails(context.Context) ([]contractroute.RouteListDetail, error) {
	return []contractroute.RouteListDetail{s.item}, nil
}

func (s *securityListBook) GetRouteList(context.Context, string) (contractroute.RouteListDetail, error) {
	return s.item, nil
}

func (s *securityListBook) SaveRouteList(_ context.Context, item contractroute.RouteListDetail, _ int64) error {
	s.item = item
	return nil
}

func TestRouteRefreshAndApplyDoNotExposeSourceCredentials(t *testing.T) {
	oldDirectory := configuration.DataDir.Load()
	configuration.DataDir.Store(t.TempDir())
	defer configuration.DataDir.Store(oldDirectory)
	var logs bytes.Buffer
	oldLogger := log.Default()
	log.SetDefault(log.NewSLogger(&logs))
	defer log.SetDefault(oldLogger)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, "server-response-secret")
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	target.User = url.UserPassword("username-secret", "password-secret")
	target.Path = "/path-secret"
	target.RawQuery = "token=query-secret"
	book := &securityListBook{item: contractroute.RouteListDetail{
		ID: "list", Name: "List", Type: "host",
		Source: contractroute.ListSource{Type: "remote", Remote: &contractroute.RemoteSource{URLs: []string{target.String()}}},
	}}
	settings := &listSettingsStub{value: RouteListSettings{MaxMindDBDownloadURL: target.String()}}
	lists := NewLists(book, settings, t.TempDir())
	defer func() { _ = lists.Close() }()
	refreshErr := lists.RefreshContract(t.Context())
	if refreshErr == nil || !strings.Contains(refreshErr.Error(), "403") || len(book.item.ErrorMsgs) != 1 {
		t.Fatal("failed refresh lost its status")
	}
	rule := contractroute.RouteRule{ID: "rule", Rules: []contractroute.RuleExpr{{Type: "host", Host: &contractroute.ListRef{List: "list"}}}}
	prepared, err := lists.prepareRules(t.Context(), []contractroute.RouteRule{rule})
	if err != nil || prepared == nil || len(prepared.listIssues) != 1 || !strings.Contains(prepared.listIssues[0].Error, "403") {
		t.Fatal("failed source lost its route activation status", err)
	}
	defer prepared.close()
	_, invalidErr := lists.downloader.GetReader("http://username-secret:password-secret@%zz/path-secret?token=query-secret")
	if invalidErr == nil {
		t.Fatal("malformed source accepted")
	}
	outputs := []string{refreshErr.Error(), settings.value.Error, settings.value.MaxMindDBError, book.item.ErrorMsgs[0], prepared.listIssues[0].Error, invalidErr.Error(), logs.String()}
	for _, output := range outputs {
		for _, marker := range []string{"username-secret", "password-secret", "path-secret", "query-secret", "server-response-secret"} {
			if strings.Contains(output, marker) {
				t.Fatal("route refresh or activation exposed source credentials")
			}
		}
	}
}
