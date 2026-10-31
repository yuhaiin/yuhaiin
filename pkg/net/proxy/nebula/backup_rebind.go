package nebula

import (
	"errors"
	"strings"

	contract "github.com/Asutorufa/yuhaiin/pkg/contract/node"
	"go.yaml.in/yaml/v3"
)

// RebindRecoveryFiles changes only PKI filename scalars recognized by this
// protocol. Inline material and all unrelated options retain their meaning.
func RebindRecoveryFiles(raw string, resolve func(string) (string, error)) (string, error) {
	if _, err := RecoveryFiles(contract.Nebula{ConfigYAML: raw}); err != nil {
		return "", err
	}
	var document yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &document); err != nil || len(document.Content) != 1 {
		return "", errors.New("invalid Nebula recovery configuration")
	}
	root := document.Content[0]
	for i := 0; i+1 < len(root.Content); i += 2 {
		if root.Content[i].Value != "pki" {
			continue
		}
		pki := root.Content[i+1]
		if pki.Kind != yaml.MappingNode {
			return "", errors.New("nebula recovery PKI must be a mapping")
		}
		for j := 0; j+1 < len(pki.Content); j += 2 {
			key, value := pki.Content[j].Value, pki.Content[j+1]
			if key != "ca" && key != "cert" && key != "key" {
				continue
			}
			if value.Kind != yaml.ScalarNode {
				return "", errors.New("nebula recovery PKI must use explicit scalar values")
			}
			if strings.Contains(value.Value, "-----BEGIN") {
				continue
			}
			mapped, err := resolve(value.Value)
			if err != nil {
				return "", err
			}
			value.Value = mapped
		}
	}
	data, err := yaml.Marshal(&document)
	return string(data), err
}
