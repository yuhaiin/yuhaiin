package nebula

import (
	"errors"
	"strings"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"go.yaml.in/yaml/v4"
)

// RecoveryFiles inventories explicit PKI filenames without constructing a tunnel
// or enforcing activation-only settings. Inline PEM stays in the node document.
func RecoveryFiles(input contract.Nebula) ([]string, error) {
	inventory, err := RecoveryInventory(input)
	return inventory.Files, err
}

type RecoveryDependencies struct {
	Files                []string
	NeedsReconfiguration bool
}

// RecoveryInventory never claims that a missing or hardware-bound key was
// backed up. Such a node is retained but disabled on restoration for review.
func RecoveryInventory(input contract.Nebula) (RecoveryDependencies, error) {
	inventory := RecoveryDependencies{}
	if strings.TrimSpace(input.ConfigYAML) == "" {
		inventory.NeedsReconfiguration = true
		return inventory, nil
	}
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(input.ConfigYAML), &document); err != nil {
		return inventory, err
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return inventory, errors.New("invalid Nebula recovery configuration")
	}
	values := map[string]string{}
	root := document.Content[0]
	seenPKI := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value == "<<" {
			return inventory, errors.New("nebula recovery requires explicit PKI without root merges")
		}
		if root.Content[i].Value != "pki" {
			continue
		}
		if seenPKI {
			return inventory, errors.New("duplicate Nebula recovery PKI")
		}
		seenPKI = true
		pki := root.Content[i+1]
		if pki.Kind == yaml.ScalarNode && pki.Tag == "!!null" {
			continue
		}
		if pki.Kind != yaml.MappingNode {
			return inventory, errors.New("nebula recovery PKI must be a mapping")
		}
		for j := 0; j+1 < len(pki.Content); j += 2 {
			key, value := pki.Content[j].Value, pki.Content[j+1]
			if key == "<<" {
				return inventory, errors.New("nebula recovery requires explicit PKI without merges")
			}
			if key != "ca" && key != "cert" && key != "key" {
				continue
			}
			if value.Kind != yaml.ScalarNode || (value.Tag != "!!str" && value.Tag != "!!null") {
				return inventory, errors.New("nebula recovery PKI must use explicit strings")
			}
			if _, exists := values[key]; exists {
				return inventory, errors.New("duplicate Nebula recovery PKI input")
			}
			if value.Tag == "!!null" {
				values[key] = ""
			} else {
				values[key] = value.Value
			}
		}
	}
	for _, key := range []string{"ca", "cert", "key"} {
		value := values[key]
		if value == "" || strings.HasPrefix(value, "pkcs11:") {
			inventory.NeedsReconfiguration = true
			continue
		}
		if !strings.Contains(value, "-----BEGIN") {
			inventory.Files = append(inventory.Files, value)
		}
	}
	return inventory, nil
}
