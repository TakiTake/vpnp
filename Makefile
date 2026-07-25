PREFIX ?= $(shell brew --prefix 2>/dev/null || echo "$(HOME)/.local")

.PHONY: help install

help: ## Show this help
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
	@echo ""
	@echo "Everything else is a vpnp subcommand — run: vpnp help"
	@echo "  (vpnp up / down / status / dns / logs)"

install: ## Build & install the vpnp CLI to $(PREFIX)/bin — then just: vpnp up
	go build -ldflags "-X main.repoRoot=$(CURDIR)" -o "$(PREFIX)/bin/vpnp" ./cmd/vpnp
	@echo "Installed $(PREFIX)/bin/vpnp — try: vpnp up"
