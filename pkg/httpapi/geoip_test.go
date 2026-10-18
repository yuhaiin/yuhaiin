package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGeoIPCountriesRPC(t *testing.T) {
	mux := http.NewServeMux()
	RegisterV2(func(pattern string, handler func(http.ResponseWriter, *http.Request) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) { _ = handler(w, r) })
	}, V2Services{Lists: listConfigRuntimeStub{}})
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v2/rpc/route.geoip.countries", strings.NewReader(`{}`)))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"codes":["CN","JP"]`) || !strings.Contains(response.Body.String(), `"loaded":true`) {
		t.Fatalf("response = %d %s", response.Code, response.Body.String())
	}
}
