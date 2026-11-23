.PHONY: test lab-build lab-test clean-lab

CARGO_CACHE_VOL := nulkast-fw-cargo-cache
TARGET_CACHE_VOL := nulkast-fw-target-cache
LAB_IMAGE := nulkast-fw-lab:latest

# Layer 1: Pure Rust unit tests inside Docker (zero host installs)
test:
	docker run --rm \
		-v $(CURDIR):/src \
		-v $(CARGO_CACHE_VOL):/usr/local/cargo/registry \
		-v $(TARGET_CACHE_VOL):/src/target \
		-w /src \
		rust:1-bookworm \
		cargo test

# Build single-container netns virtual lab image
lab-build:
	docker build -f lab/Dockerfile.lab -t $(LAB_IMAGE) .

# Layer 2: Run full Phase 1 CORE real-packet smoke test in isolated netns lab
lab-test: lab-build
	docker run --rm --privileged $(LAB_IMAGE) /usr/local/bin/smoke_test.sh

# Clean up any leftover containers
clean-lab:
	docker compose -f lab/docker-compose.yml down -v --remove-orphans 2>/dev/null || true
