package configbackup

import (
	"strings"
	"testing"
)

func TestHTTPMockPayloadRedactionIsScoped(t *testing.T) {
	for _, document := range []string{
		`{"enabled":true,"other":{"data":"ordinary-data","dataBase64":"b3JkaW5hcnk="}}`,
		`{"enabled":true,"http_mock":{"data":"","dataBase64":null}}`,
	} {
		got, changed, err := Endpoint(document)
		if err != nil || changed || got != document {
			t.Fatalf("unrelated or empty payload changed: %q, %t, %v", got, changed, err)
		}
	}
}

func TestRealityIdentifierRedactionIsScoped(t *testing.T) {
	for _, document := range []string{
		`{"enabled":true,"other":{"short_id":"ordinary-id","shortIds":["ordinary-id"]}}`,
		`{"enabled":true,"reality":{"short_id":"","shortIds":[]}}`,
	} {
		got, changed, err := Endpoint(document)
		if err != nil || changed || got != document {
			t.Fatal("unrelated or empty identifiers changed", err)
		}
	}
	for _, document := range []string{
		`{"enabled":true,"transports":[{"type":"reality","reality":{"Short-IDs":["private-marker"]}}]}`,
		`{"enabled":true,"transports":[{"type":"reality","reality":{"shortIds":["private-marker"]}}]}`,
	} {
		if result, changed, err := Inbound(document); err != nil || !changed || strings.Contains(result, "private-marker") {
			t.Fatal("REALITY authentication array was not sanitized with its legacy aliases", err)
		}
	}
}
