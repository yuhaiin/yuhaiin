package configbackup

import "testing"

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
