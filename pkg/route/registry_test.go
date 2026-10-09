package route

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	contractroute "github.com/Asutorufa/yuhaiin/pkg/contract/route"
)

type registryBookStub struct {
	items []contractroute.Registry
}

func (s registryBookStub) ListRegistries(context.Context) (contractroute.RegistryList, error) {
	return contractroute.RegistryList{Items: s.items}, nil
}

func TestRegistryCatalogServiceFetchesAndCaches(t *testing.T) {
	var requests atomic.Int32
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{
			"schemaVersion": 1,
			"repository": "example/rules",
			"branch": "generated",
			"baseUrl": %q,
			"files": [
				{
					"id": "geosite/google",
					"name": "google",
					"category": "geosite",
					"kind": "domain",
					"usage": "route-list",
					"listType": "host",
					"format": "text",
					"path": "geosite/google.conf",
					"size": 42,
					"sha256": "abc",
					"selectable": true
				},
				{
					"id": "geoip/Country",
					"name": "Country",
					"category": "geoip",
					"kind": "database",
					"usage": "maxminddb",
					"format": "maxminddb",
					"url": %q,
					"size": 100,
					"sha256": "def",
					"selectable": true
				}
			]
		}`, server.URL+"/raw/", server.URL+"/Country.mmdb")
	}))
	defer server.Close()

	book := registryBookStub{items: []contractroute.Registry{
		{ID: "test", Name: "Test", URL: server.URL + "/manifest.json", Enabled: true},
		{ID: "disabled", Name: "Disabled", URL: server.URL + "/disabled.json", Enabled: false},
	}}
	service := newRegistryCatalogService(book, server.Client(), time.Hour)

	ctx := t.Context()
	first, err := service.Catalogs(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Items) != 1 {
		t.Fatalf("catalogs = %+v", first.Items)
	}
	catalog := first.Items[0]
	if catalog.Error != "" || catalog.SchemaVersion != 1 || len(catalog.Files) != 2 {
		t.Fatalf("catalog = %+v", catalog)
	}
	if got := catalog.Files[0].URL; got != server.URL+"/raw/geosite/google.conf" {
		t.Fatalf("resolved URL = %q", got)
	}

	if _, err := service.Catalogs(ctx, false); err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("request count after cache hit = %d, want 1", got)
	}

	if _, err := service.Catalogs(ctx, true); err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 2 {
		t.Fatalf("request count after forced refresh = %d, want 2", got)
	}
}

func TestRegistryCatalogServiceKeepsPerRegistryErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"schemaVersion":99,"files":[]}`)
	}))
	defer server.Close()

	service := newRegistryCatalogService(registryBookStub{items: []contractroute.Registry{
		{ID: "broken", Name: "Broken", URL: server.URL, Enabled: true},
	}}, server.Client(), time.Hour)

	got, err := service.Catalogs(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].Error == "" {
		t.Fatalf("catalog error was not preserved: %+v", got.Items)
	}
}
