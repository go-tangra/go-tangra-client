.PHONY: build clean run tidy install uninstall package help

BINARY_NAME := tangra-client
BUILD_DIR := .
INSTALL_DIR := /usr/local/bin
CONFIG_DIR := /etc/tangra-client
SYSTEMD_DIR := /etc/systemd/system

VERSION ?= 0.0.0-dev
COMMIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
LDFLAGS := -s -w \
	-X main.buildVersion=$(VERSION) \
	-X main.commitHash=$(COMMIT_HASH) \
	-X main.buildDate=$(BUILD_DATE)

GO := go
GOFLAGS := -v

# Build the binary
build:
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BUILD_DIR)/$(BINARY_NAME) .

# Clean build artifacts
clean:
	rm -f $(BUILD_DIR)/$(BINARY_NAME)
	rm -rf dist/

# Run the client
run: build
	./$(BINARY_NAME)

# Tidy dependencies
tidy:
	$(GO) mod tidy

# Install binary, config, and systemd service
install: build
	install -d $(CONFIG_DIR)
	install -d $(CONFIG_DIR)/live
	install -m 0755 $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/$(BINARY_NAME)
	install -m 0644 deploy/tangra-client.service $(SYSTEMD_DIR)/tangra-client.service
	@if [ ! -f $(CONFIG_DIR)/config.yaml ]; then \
		install -m 0600 deploy/config.yaml $(CONFIG_DIR)/config.yaml; \
		echo "Installed sample config to $(CONFIG_DIR)/config.yaml — edit before starting"; \
	else \
		echo "$(CONFIG_DIR)/config.yaml already exists, skipping"; \
	fi
	systemctl daemon-reload
	@echo ""
	@echo "Installed. Next steps:"
	@echo "  1. Edit $(CONFIG_DIR)/config.yaml"
	@echo "  2. Place mTLS certs in $(CONFIG_DIR)/"
	@echo "  3. systemctl enable --now tangra-client"

# Uninstall binary, service (preserves config)
uninstall:
	systemctl stop tangra-client 2>/dev/null || true
	systemctl disable tangra-client 2>/dev/null || true
	rm -f $(SYSTEMD_DIR)/tangra-client.service
	rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	systemctl daemon-reload
	@echo "Uninstalled. Config preserved at $(CONFIG_DIR)/"

# Build .deb and .rpm packages locally
ARCH ?= amd64
package:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS) -extldflags '-static'" -o dist/$(BINARY_NAME) .
	export VERSION=$(VERSION) ARCH=$(ARCH); \
	envsubst < nfpm.yaml | nfpm package -f /dev/stdin -p deb -t dist/; \
	envsubst < nfpm.yaml | nfpm package -f /dev/stdin -p rpm -t dist/
	@echo ""; ls -lh dist/*.deb dist/*.rpm

# Show help
help:
	@echo "Available targets:"
	@echo "  build     - Build the tangra-client binary"
	@echo "  clean     - Remove build artifacts"
	@echo "  run       - Build and run the client"
	@echo "  tidy      - Tidy Go module dependencies"
	@echo "  install   - Install binary, systemd service, and sample config (requires root)"
	@echo "  uninstall - Remove binary and service, preserve config (requires root)"
	@echo "  package   - Build .deb and .rpm packages (requires nfpm)"
	@echo "  help      - Show this help message"
