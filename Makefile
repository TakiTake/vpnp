PREFIX ?= $(shell brew --prefix 2>/dev/null || echo "$(HOME)/.local")
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Where a Homebrew-installed vpnp keeps its config/state (formula installs
# the example files there; arm64 macOS only, so the prefix is fixed).
BREW_ETC = /opt/homebrew/etc/vpnp

.PHONY: help install dist

help: ## Show this help
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
	@echo ""
	@echo "Everything else is a vpnp subcommand — run: vpnp help"
	@echo "  (vpnp up / down / status / dns / logs)"

install: ## Build & install the vpnp CLI to $(PREFIX)/bin — then just: vpnp up
	go build -ldflags "-X main.repoRoot=$(CURDIR) -X main.version=$(VERSION)" -o "$(PREFIX)/bin/vpnp" ./cmd/vpnp
	@echo "Installed $(PREFIX)/bin/vpnp — try: vpnp up"

dist: ## Build the Homebrew release tarball into dist/ (arm64 macOS)
	rm -rf dist/stage && mkdir -p dist/stage/config
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build \
		-ldflags "-X main.repoRoot=$(BREW_ETC) -X main.version=$(VERSION)" \
		-o dist/stage/vpnp ./cmd/vpnp
	cp config/vpn.dns.example config/vpn.access.example config/README.md dist/stage/config/
	cp .env.example dist/stage/
	tar -czf dist/vpnp-$(VERSION)-aarch64-apple-darwin.tar.gz -C dist/stage .
	@echo "dist/vpnp-$(VERSION)-aarch64-apple-darwin.tar.gz"
