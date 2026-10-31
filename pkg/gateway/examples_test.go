package gateway

import (
	json "encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/gateway"
)

func TestDocumentedConfigurationsCompile(t *testing.T) {
	directory := "../../docs/gateway/examples"
	files, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		t.Run(file.Name(), func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join(directory, file.Name()))
			if err != nil {
				t.Fatal(err)
			}
			var document contract.Workspace
			if err := json.Unmarshal(data, &document); err != nil {
				t.Fatal(err)
			}
			config, err := contract.ConfigFromWorkspace(document)
			if err != nil {
				t.Fatal(err)
			}
			// Validate complete policy/interception/CA references without binding the
			// example's administrator-selected public listen port on the test host.
			for n := range config.Gateways {
				config.Gateways[n].Listen = ""
			}
			manager, _ := newTestManager(t, contract.Config{}, nil)
			prepared, err := manager.prepare(t.Context(), config)
			if err != nil {
				t.Fatal(err)
			}
			prepared.close()
		})
	}
}
