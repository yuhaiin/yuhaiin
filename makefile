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

# AMD64v3 https://github.com/golang/go/wiki/MinimumRequirements#amd64
LINUX_AMD64=GOOS=linux GOARCH=amd64
LINUX_AMD64v3=GOOS=linux GOARCH=amd64 GOAMD64=v3
WINDOWS_AMD64=GOOS=windows GOARCH=amd64
WINDOWS_AMD64v3=GOOS=windows GOARCH=amd64 GOAMD64=v3
LINUX_MIPSLE=GOOS=linux GOARCH=mipsle GOMIPS=softfloat
ANDROID_ARM64=GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang
ANDROID_AMD64=GOOS=android GOARCH=amd64 CGO_ENABLED=1 CC=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang

YUUBINSYA=-v ./cmd/yuubinsya/...
YUHAIIN=-v ./cmd/yuhaiin/...
CLI=-v ./cmd/cli/...
DNSRELAY= -v ./cmd/dnsrelay/...

.PHONY: test
test:
	@echo "test"
	@echo ${GO_CMD}

.PHONY: all
all: yuhaiin yuhaiin_windows dnsrelay dnsrelay_windows

.PHONY: vet
vet:
	$(GO) vet $(shell go list ./... | grep -v '/scripts/' | grep -v 'pkg/net/proxy/tun/tun2socket/checksum')

.PHONY: yuhaiin
yuhaiin:
	$(LINUX_AMD64) $(GO_BUILD_CMD) -pgo=./cmd/yuhaiin/yuhaiin.pprof -tags "debug" -o yuhaiin $(YUHAIIN)
	$(LINUX_AMD64v3) $(GO_BUILD_CMD) -pgo=./cmd/yuhaiin/yuhaiin.pprof -tags "debug" -o yuhaiin_v3 $(YUHAIIN)

.PHONY: dnsrelay
dnsrelay:
	# $(LINUX_AMD64) $(GO_BUILD_CMD) -o dnsrelay $(DNSRELAY)
	$(LINUX_AMD64v3) $(GO_BUILD_CMD) -o dnsrelay $(DNSRELAY)

.PHONY: dnsrelay_windows
dnsrelay_windows:
	# $(WINDOWS_AMD64) $(GO_BUILD_CMD) -o dnsrelay.exe $(DNSRELAY)
	$(WINDOWS_AMD64v3) $(GO_BUILD_CMD) -o dnsrelay.exe $(DNSRELAY)

.PHONY: cli
cli:
	$(LINUX_AMD64) $(GO_BUILD_CMD) -o yh $(CLI)
	$(LINUX_AMD64v3) $(GO_BUILD_CMD) -o yh_v3 $(CLI)

.PHONY: yuhaiin_windows
yuhaiin_windows:
	$(WINDOWS_AMD64) $(GO_BUILD_CMD) -pgo=./cmd/yuhaiin/yuhaiin.pprof -o yuhaiin.exe $(YUHAIIN)
	$(WINDOWS_AMD64v3) $(GO_BUILD_CMD) -pgo=./cmd/yuhaiin/yuhaiin.pprof -o yuhaiin_v3.exe $(YUHAIIN)

.PHONY: cli_windows
cli_windows:
	$(WINDOWS_AMD64) $(GO_BUILD_CMD) -o yh.exe $(CLI)
	$(WINDOWS_AMD64v3) $(GO_BUILD_CMD) -o yh_v3.exe $(CLI)

.PHONY: yuhaiin_android
yuhaiin_android:
	$(ANDROID_ARM64) $(GO_BUILD_CMD) -pgo=./cmd/yuhaiin/yuhaiin.pprof -o ./cmd/android/main/jniLibs/arm64-v8a/libyuhaiin.so -v ./cmd/android/main/...
	$(ANDROID_AMD64) $(GO_BUILD_CMD) -pgo=./cmd/yuhaiin/yuhaiin.pprof -o ./cmd/android/main/jniLibs/x86_64/libyuhaiin.so -v ./cmd/android/main/...

.PHONY: cli_android
cli_android:
	$(ANDROID_ARM64) $(GO_BUILD_CMD) -o yh_android $(CLI)

.PHONY: yuhaiin_mipsle
yuhaiin_mipsle:
	$(LINUX_MIPSLE) $(GO_BUILD_CMD) -pgo=./cmd/yuhaiin/yuhaiin.pprof -tags "openwrt" -o yuhaiin_mipsle $(YUHAIIN)

.PHONY: yuubinsya
yuubinsya:
	CGO_ENABLED=0 $(LINUX_AMD64v3) $(GO_BUILD_CMD) -pgo=./cmd/yuhaiin/yuhaiin.pprof -o yuubinsya $(YUUBINSYA)

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
