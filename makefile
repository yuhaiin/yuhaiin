GO=$(shell command -v go | head -n1)
GO_LDFLAGS= -ldflags=\"-s -w\"
GO_GCFLAGS= -gcflags=\"-m\"
GO_CMD=$(GO) $(GO_LDFLAGS) $(GO_GCFLAGS)
.PHONY: test
test:
	@echo "test"
	@echo ${GO_CMD}

.PHONY: all
all: yuhaiin cli

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: yuhaiin
yuhaiin:
	go build -gcflags="-m" -ldflags="-s -w" -trimpath -o yuhaiin -v ./cmd/yuhaiin/...

.PHONY: yuhaiinns
yuhaiinns:
	go build -gcflags="-m" -tags="nostatic" -ldflags="-s -w" -trimpath -o yuhaiin -v ./cmd/yuhaiin/...

.PHONY: cli
cli:
	go build -gcflags="-m" -tags="nostatic" -ldflags="-s -w" -trimpath -o yh -v ./cmd/cli/...

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
