package compatibility

import (
	"debug/buildinfo"
	"errors"
	"strings"
)

// VerifyPlatform reads Go's embedded build information. It never starts the
// candidate, including old binaries which do not recognize a capability flag.
func (m Manifest) VerifyPlatform(path string) error {
	info, err := buildinfo.ReadFile(path)
	if err != nil {
		return errors.New("release executable has no Go build information")
	}
	expectedArch := m.Architecture
	if strings.HasPrefix(expectedArch, "amd64") {
		expectedArch = "amd64"
	}
	settings := make(map[string]string)
	for _, setting := range info.Settings {
		settings[setting.Key] = setting.Value
	}
	if settings["GOOS"] != m.Platform || settings["GOARCH"] != expectedArch {
		return errors.New("release executable platform differs from its schema manifest")
	}
	if expectedArch == "amd64" {
		expectedCPU := "v1"
		if m.Architecture != "amd64" {
			expectedCPU = strings.TrimPrefix(m.Architecture, "amd64")
		}
		if settings["GOAMD64"] != expectedCPU {
			return errors.New("release executable CPU level differs from its schema manifest")
		}
	}
	if expectedArch == "arm64" && settings["GOARM64"] != "v8.0" {
		return errors.New("release executable requires an unsupported ARM CPU level")
	}
	if expectedArch == "mipsle" && settings["GOMIPS"] != "softfloat" {
		return errors.New("release executable requires an unsupported MIPS ABI")
	}
	return nil
}
