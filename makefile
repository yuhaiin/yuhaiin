MODULE := github.com/Asutorufa/yuhaiin

BUILD_COMMIT  := $(shell git rev-parse --short HEAD)
BUILD_VERSION := $(shell git describe --tags)
ifeq ($(OS),Windows_NT)
	BUILD_ARCH	:= Windows_NT
	BUILD_TIME	:= $(shell powershell Get-Date)
else
	BUILD_ARCH	:= $(shell uname -a)
	BUILD_TIME	:= $(shell date)
endif

CGO_ENABLED := 0

GOENV=GOEXPERIMENT=jsonv2,greenteagc

GO=$(GOENV) $(shell command -v go | head -n1)
GO_MOBILE=$(GOENV) $(shell command -v gomobile | head -n1)

GO_LDFLAGS= -s -w -buildid=
GO_LDFLAGS += -X "$(MODULE)/internal/version.Version=$(BUILD_VERSION)"
GO_LDFLAGS += -X "$(MODULE)/internal/version.GitCommit=$(BUILD_COMMIT)"
GO_LDFLAGS += -X "$(MODULE)/internal/version.BuildArch=$(BUILD_ARCH)"
GO_LDFLAGS += -X "$(MODULE)/internal/version.BuildTime=$(BUILD_TIME)"

GO_GCFLAGS=
# GO_GCFLAGS= -m

GO_TAGS=$(shell $(GO) run ./cmd/buildtags/...),stdlibjson,debug
GO_BUILD_ARGS=-ldflags='$(GO_LDFLAGS)' -gcflags='$(GO_GCFLAGS)' -tags='$(GO_TAGS)' -trimpath
GO_BUILD_CMD=CGO_ENABLED=$(CGO_ENABLED) $(GO) build $(GO_BUILD_ARGS)

GO_MOBILE_BIND_CMD=$(GO_MOBILE) bind $(GO_BUILD_ARGS)


# AMD64v3 https://github.com/golang/go/wiki/MinimumRequirements#amd64
LINUX_AMD64=GOOS=linux GOARCH=amd64
LINUX_AMD64v3=GOOS=linux GOARCH=amd64 GOAMD64=v3
DARWIN_AMD64=GOOS=darwin GOARCH=amd64
DARWIN_AMD64v3=GOOS=darwin GOARCH=amd64 GOAMD64=v3
WINDOWS_AMD64=GOOS=windows GOARCH=amd64
WINDOWS_AMD64v3=GOOS=windows GOARCH=amd64 GOAMD64=v3
LINUX_MIPSLE=GOOS=linux GOARCH=mipsle GOMIPS=softfloat
ANDROID_ARM64=GOOS=android GOARCH=arm64 CGO_ENABLED=1 CC=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang
ANDROID_AMD64=GOOS=android GOARCH=amd64 CGO_ENABLED=1 CC=${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android21-clang

YUHAIIN=-v ./cmd/yuhaiin/...
CLI=-v ./cmd/cli/...
DNSRELAY= -v ./cmd/dnsrelay/...

.PHONY: test
test:
	@echo "test"
	@echo ${GO_CMD}

.PHONY: vet
vet:
	$(GO) vet $(shell go list ./... | grep -v '/scripts/' | grep -v 'pkg/net/proxy/tun/tun2socket/checksum')

.PHONY: yuhaiin
yuhaiin:
	$(GO_BUILD_CMD) $(YUHAIIN)

define build 
	$(eval ARGS := $(subst -, ,$@))
	$(eval OS := $(word 2, $(ARGS)))
	$(eval ARCH := $(word 3, $(ARGS)))
	$(eval MODE := $(word 4, $(ARGS)))

	$(if $(filter amd64v3, $(ARCH)),$(eval AMD64V3 := v3),)
	$(if $(filter amd64v3, $(ARCH)),$(eval ARCH := amd64),)
	$(if $(filter mipsle, $(ARCH)),$(eval MIPS := softfloat),)
	$(if $(filter lite, $(MODE)),$(eval SUFFIX := _lite),)
	$(if $(filter windows, $(OS)),$(if $(SUFFIX), $(eval SUFFIX := $(addsuffix .exe, $(SUFFIX))), $(eval SUFFIX := .exe)),)

	$(info OS: $(OS), ARCH: $(ARCH), MODE: $(if $(MODE),$(MODE),full), SUFFIX: $(SUFFIX))
endef

.PHONY: yuhaiin-%
yuhaiin-%:
	$(build)
	GOOS=$(OS) GOARCH=$(ARCH) GOMIPS=$(MIPS) GOAMD64=$(AMD64V3) $(GO_BUILD_CMD) -o yuhaiin_$(OS)_$(ARCH)$(AMD64V3)$(SUFFIX) $(YUHAIIN)

	@if [ "$(OS)" = "darwin" ]; then \
		if [ -n "$(shell command -v codesign)" ]; then \
            echo "codesign found, signing..."; \
            codesign -s - --force --preserve-metadata=entitlements,requirements,flags,runtime yuhaiin_$(OS)_$(ARCH)$(AMD64V3)$(SUFFIX); \
            codesign -dv --verbose=4 yuhaiin_$(OS)_$(ARCH)$(AMD64V3)$(SUFFIX); \
        fi \
	fi

.PHONY: yuhaiin_android_aar
yuhaiin_android_aar:
	$(GO_MOBILE_BIND_CMD) -target="android/arm64,android/amd64" -androidapi 21 -o yuhaiin.aar -v ./cmd/android/

# sudo Xcode-select --switch /Applications/Xcode.app/Contents/Developer/
.PHONY: yuhaiin_macos
yuhaiin_macos:
	$(GO_MOBILE_BIND_CMD) -target="macos" -o yuhaiin.xcframework -v ./cmd/macos/

.PHONY: license
license:
	$(GOENV) GOFLAGS="-tags=android,cgo,darwin,freebsd,ios,js,linux,openbsd,wasm,windows,$(GO_TAGS)" go-licenses report github.com/Asutorufa/yuhaiin/cmd/yuhaiin > licenses/yuhaiin.md --template .github/licenses.tmpl
	$(GOENV) GOFLAGS="-tags=android,cgo,darwin,freebsd,ios,js,linux,openbsd,wasm,windows,$(GO_TAGS)" go-licenses report github.com/Asutorufa/yuhaiin/cmd/android > licenses/android.md --template .github/licenses.tmpl

.PHONY: install
install: build cli
	install -s -b -v -m 644 yuhaiin ${HOME}/.local/bin/yuhaiin
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
