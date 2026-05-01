GO ?= go
BINARY := bin/cute-pcap-mcp
CMD := ./cmd/cute-pcap-mcp
BUILDINFO_PKG := cute-pcap-mcp/internal/buildinfo
DIST_DIR ?= dist
RELEASE_PLATFORMS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64
SKILLS ?= $(notdir $(wildcard skills/*))
SKILLS_BUNDLE ?= cute-pcap-mcp-skills-$(VERSION).zip

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo unknown)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X $(BUILDINFO_PKG).version=$(VERSION) \
           -X $(BUILDINFO_PKG).commit=$(COMMIT) \
           -X $(BUILDINFO_PKG).buildTime=$(BUILD_TIME)

.PHONY: build
build:
	$(GO) build -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

.PHONY: release-binaries
release-binaries:
	rm -rf $(DIST_DIR)
	mkdir -p $(DIST_DIR)
	set -eu; \
	for platform in $(RELEASE_PLATFORMS); do \
		os=$${platform%/*}; \
		arch=$${platform#*/}; \
		name="cute-pcap-mcp-$${os}-$${arch}"; \
		outdir="$(DIST_DIR)/$${name}"; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "building $${name}"; \
		mkdir -p "$$outdir"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o "$$outdir/cute-pcap-mcp$$ext" $(CMD); \
		cp README.md "$$outdir/README.md"; \
		cp config.docker.example.yaml "$$outdir/config.docker.example.yaml"; \
		mkdir -p "$$outdir/scripts"; \
		cp scripts/cute-pcap-mcp-docker "$$outdir/scripts/cute-pcap-mcp-docker"; \
		tar -C "$(DIST_DIR)" -czf "$(DIST_DIR)/$${name}.tar.gz" "$$name"; \
		rm -rf "$$outdir"; \
	done
	if command -v sha256sum >/dev/null 2>&1; then \
		( cd "$(DIST_DIR)" && sha256sum *.tar.gz > checksums.txt ); \
	else \
		( cd "$(DIST_DIR)" && shasum -a 256 *.tar.gz > checksums.txt ); \
	fi

.PHONY: skills-package
skills-package:
	rm -rf $(DIST_DIR)/skills
	mkdir -p $(DIST_DIR)/skills
	set -eu; \
	for name in $(SKILLS); do \
		skill="skills/$$name"; \
		[ -d "$$skill" ] || { echo "$$skill not found" >&2; exit 1; }; \
		[ -f "$$skill/SKILL.md" ] || { echo "$$skill missing SKILL.md" >&2; exit 1; }; \
		echo "packaging skill $$name"; \
		( cd "$$skill" && zip -qr "$(CURDIR)/$(DIST_DIR)/skills/$$name.zip" . ); \
	done
	if command -v sha256sum >/dev/null 2>&1; then \
		( cd "$(DIST_DIR)/skills" && sha256sum *.zip > checksums.txt ); \
	else \
		( cd "$(DIST_DIR)/skills" && shasum -a 256 *.zip > checksums.txt ); \
	fi

.PHONY: skills-bundle
skills-bundle: skills-package
	rm -f "$(DIST_DIR)/$(SKILLS_BUNDLE)"
	( cd "$(DIST_DIR)/skills" && zip -qr "$(CURDIR)/$(DIST_DIR)/$(SKILLS_BUNDLE)" *.zip checksums.txt )

.PHONY: test
test:
	$(GO) test ./...

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: ci
ci: vet test build

.PHONY: clean
clean:
	rm -rf bin dist

DOCKER ?= docker
DOCKER_IMAGE ?= cute-pcap-mcp
DOCKER_TAG ?= latest

.PHONY: docker-build
docker-build:
	$(DOCKER) build \
		--build-arg VERSION="$(VERSION)" \
		--build-arg COMMIT="$(COMMIT)" \
		--build-arg BUILD_TIME="$(BUILD_TIME)" \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_IMAGE):latest .

.PHONY: docker-version
docker-version:
	$(DOCKER) run --rm $(DOCKER_IMAGE):$(DOCKER_TAG) --version

# docker-smoke verifies that every analyzer the runtime promises is on
# PATH inside the built image. Fails loudly if any binary is missing.
# This is the same set the Dockerfile RUN-time check enforces; running
# it again from the runtime user catches breakage from layer-ordering
# refactors or future apt changes.
.PHONY: docker-smoke
docker-smoke:
	$(DOCKER) run --rm --entrypoint /bin/sh $(DOCKER_IMAGE):$(DOCKER_TAG) -c '\
		set -eu; \
		for bin in cute-pcap-mcp tshark capinfos tcpdump zeek jq python3; do \
			command -v "$$bin" >/dev/null 2>&1 || { echo "$$bin missing from runtime image" >&2; exit 1; }; \
		done; \
		echo "docker-smoke: all required binaries present"'

# integration-test runs the full Go test suite (including the
# integration tests that skip locally without tshark/zeek) on a host
# where those binaries are available. Used by CI's integration job;
# operators can run it locally on a machine with tshark + zeek
# installed.
.PHONY: integration-test
integration-test:
	$(GO) test ./...
