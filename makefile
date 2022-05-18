MODULE := github.com/Asutorufa/yuhaiin

BUILD_COMMIT  := $(shell git rev-parse --short HEAD)
BUILD_VERSION := $(shell git describe --abbrev=0 --tags HEAD)
BUILD_ARCH	:= $(shell uname -a)
BUILD_TIME	:= $(shell date)

GO=$(shell command -v go | head -n1)

GO_LDFLAGS= -s -w -buildid=
GO_LDFLAGS += -X "$(MODULE)/internal/version.Version=$(BUILD_VERSION)"
GO_LDFLAGS += -X "$(MODULE)/internal/version.GitCommit=$(BUILD_COMMIT)"
GO_LDFLAGS += -X "$(MODULE)/internal/version.BuildArch=$(BUILD_ARCH)"
GO_LDFLAGS += -X "$(MODULE)/internal/version.BuildTime=$(BUILD_TIME)"

GO_GCFLAGS= -m

GO_BUILD_CMD=$(GO) build -ldflags='$(GO_LDFLAGS)' -gcflags='$(GO_GCFLAGS)' -trimpath

WINDOWS_AMD64=GOOS=windows GOARCH=amd64
ANDROID_ARM64=GOOS=android GOARCH=arm64

YUHAIIN=-v ./cmd/yuhaiin/...
CLI=-v ./cmd/cli/...

.PHONY: test
test:
	@echo "test"
	@echo ${GO_CMD}

.PHONY: all
all: yuhaiin cli yuhaiin_windows cli_windows

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: yuhaiin
yuhaiin:
	$(GO_BUILD_CMD) -o yuhaiin $(YUHAIIN)

.PHONY: cli
cli:
	$(GO_BUILD_CMD) -o yh $(CLI)

.PHONY: yuhaiin_windows
yuhaiin_windows:
	$(WINDOWS_AMD64) $(GO_BUILD_CMD) -o yuhaiin.exe $(YUHAIIN)

.PHONY: cli_windows
cli_windows:
	$(WINDOWS_AMD64) $(GO_BUILD_CMD) -o yh.exe $(CLI)

.PHONY: yuhaiin_android
yuhaiin_android:
	$(ANDROID_ARM64) $(GO_BUILD_CMD) -o yuhaiin_android $(YUHAIIN)

.PHONY: cli_android
cli_android:
	$(ANDROID_ARM64) $(GO_BUILD_CMD) -o yh_android $(CLI)


.PHONY: install
install: build cli
	install -s -b -v -m 644 yuhaiin ${HOME}/.local/bin/yuhaiin
	install -s -b -v -m 644 yh ${HOME}/.local/bin/yh
	install -b -v -m 644 scripts/systemd/yuhaiin.service ${HOME}/.config/systemd/user/yuhaiin.service
	echo "add ${HOME}/.local/bin to PATH env"

.PHONY: gofmt
gofmt: ## Verify the source code gofmt
	find . -name '*.go' -type f \
		-not \( \
			-name '.golangci.yml' -o \
			-name 'makefile' -o \
			-path './vendor/*' -prune -o \
			-path './contrib/*' -prune \
			-path './pkg/sysproxy/dll_windows/*' \
		\) -exec gofmt -d -e -s -w {} \+
	git diff --exit-code
