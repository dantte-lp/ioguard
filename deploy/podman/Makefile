# Makefile for ringwall Podman Container Management
# Production-grade container operations using Podman, Buildah, and Skopeo
#
# Quick Start:
#   make build-all     # Build all containers
#   make dev           # Start development environment
#   make test          # Run tests
#   make clean         # Clean up containers and images
#
# For detailed usage: make help

.PHONY: help build-all build-dev build-test build-build build-ci \
        dev test build ci \
        run-dev run-test run-build run-ci \
        shell-dev shell-test shell-build shell-ci \
        push-all push-dev push-test push-build push-ci \
        inspect-all inspect-dev inspect-test inspect-build inspect-ci \
        volumes-backup volumes-restore volumes-clean \
        clean clean-containers clean-images clean-volumes clean-all \
        lint validate verify-rootless verify-selinux \
        up down logs ps stats

# Configuration
PROJECT_NAME := ringwall
PROJECT_VERSION := 2.0.0-alpha.1
REGISTRY := ghcr.io/dantte-lp
IMAGE_PREFIX := $(PROJECT_NAME)

# Image names
DEV_IMAGE := localhost/$(IMAGE_PREFIX)-dev:latest
TEST_IMAGE := localhost/$(IMAGE_PREFIX)-test:latest
BUILD_IMAGE := localhost/$(IMAGE_PREFIX)-build:latest
CI_IMAGE := localhost/$(IMAGE_PREFIX)-ci:latest

# Build scripts
BUILD_DEV_SCRIPT := scripts/build-dev.sh
BUILD_TEST_SCRIPT := scripts/build-test.sh
BUILD_BUILD_SCRIPT := scripts/build-build.sh
BUILD_CI_SCRIPT := scripts/build-ci.sh

# Colors for output
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m # No Color

# Default target
.DEFAULT_GOAL := help

##@ General

help: ## Display this help message
	@echo "$(GREEN)ringwall Container Management$(NC)"
	@echo "$(BLUE)Version: $(PROJECT_VERSION)$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make $(YELLOW)<target>$(NC)\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  $(YELLOW)%-20s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(BLUE)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Build Images

build-all: build-dev build-test build-build build-ci ## Build all container images
	@echo "$(GREEN)All images built successfully!$(NC)"

build-dev: ## Build development container image
	@echo "$(YELLOW)Building development image...$(NC)"
	@bash $(BUILD_DEV_SCRIPT)
	@echo "$(GREEN)Development image built: $(DEV_IMAGE)$(NC)"

build-test: build-dev ## Build test container image (requires dev image)
	@echo "$(YELLOW)Building test image...$(NC)"
	@bash $(BUILD_TEST_SCRIPT)
	@echo "$(GREEN)Test image built: $(TEST_IMAGE)$(NC)"

build-build: build-dev ## Build build container image (requires dev image)
	@echo "$(YELLOW)Building build image...$(NC)"
	@bash $(BUILD_BUILD_SCRIPT)
	@echo "$(GREEN)Build image built: $(BUILD_IMAGE)$(NC)"

build-ci: build-build ## Build CI container image (requires build image)
	@echo "$(YELLOW)Building CI image...$(NC)"
	@bash $(BUILD_CI_SCRIPT)
	@echo "$(GREEN)CI image built: $(CI_IMAGE)$(NC)"

##@ Run Containers

dev: ## Start development environment (interactive)
	@echo "$(YELLOW)Starting development environment...$(NC)"
	@podman-compose up dev

test: ## Run tests in test container
	@echo "$(YELLOW)Running tests...$(NC)"
	@podman-compose up test

build: ## Build release artifacts in build container
	@echo "$(YELLOW)Building release artifacts...$(NC)"
	@podman-compose up build

ci: ## Run CI pipeline in CI container
	@echo "$(YELLOW)Running CI pipeline...$(NC)"
	@podman-compose up ci

##@ Interactive Shells

shell-dev: ## Open interactive shell in dev container
	@podman-compose run --rm dev /bin/bash

shell-test: ## Open interactive shell in test container
	@podman-compose run --rm test /bin/bash

shell-build: ## Open interactive shell in build container
	@podman-compose run --rm build /bin/bash

shell-ci: ## Open interactive shell in CI container
	@podman-compose run --rm ci /bin/bash

##@ Container Management

up: ## Start all services in background
	@podman-compose up -d

down: ## Stop all services
	@podman-compose down

logs: ## View logs from all services
	@podman-compose logs -f

ps: ## List running containers
	@podman-compose ps

stats: ## Display container resource usage statistics
	@podman stats --no-stream

##@ Push Images (Skopeo)

push-all: push-dev push-test push-build push-ci ## Push all images to registry

push-dev: ## Push development image to registry
	@echo "$(YELLOW)Pushing development image...$(NC)"
	@bash scripts/push-image.sh $(DEV_IMAGE) $(REGISTRY)/$(IMAGE_PREFIX)-dev:latest

push-test: ## Push test image to registry
	@echo "$(YELLOW)Pushing test image...$(NC)"
	@bash scripts/push-image.sh $(TEST_IMAGE) $(REGISTRY)/$(IMAGE_PREFIX)-test:latest

push-build: ## Push build image to registry
	@echo "$(YELLOW)Pushing build image...$(NC)"
	@bash scripts/push-image.sh $(BUILD_IMAGE) $(REGISTRY)/$(IMAGE_PREFIX)-build:latest

push-ci: ## Push CI image to registry
	@echo "$(YELLOW)Pushing CI image...$(NC)"
	@bash scripts/push-image.sh $(CI_IMAGE) $(REGISTRY)/$(IMAGE_PREFIX)-ci:latest

##@ Inspect Images

inspect-all: inspect-dev inspect-test inspect-build inspect-ci ## Inspect all images

inspect-dev: ## Inspect development image with Skopeo
	@echo "$(YELLOW)Inspecting development image:$(NC)"
	@skopeo inspect containers-storage:$(DEV_IMAGE) | jq -r '.Name, .Digest, .Created, .Labels'

inspect-test: ## Inspect test image with Skopeo
	@echo "$(YELLOW)Inspecting test image:$(NC)"
	@skopeo inspect containers-storage:$(TEST_IMAGE) | jq -r '.Name, .Digest, .Created, .Labels'

inspect-build: ## Inspect build image with Skopeo
	@echo "$(YELLOW)Inspecting build image:$(NC)"
	@skopeo inspect containers-storage:$(BUILD_IMAGE) | jq -r '.Name, .Digest, .Created, .Labels'

inspect-ci: ## Inspect CI image with Skopeo
	@echo "$(YELLOW)Inspecting CI image:$(NC)"
	@skopeo inspect containers-storage:$(CI_IMAGE) | jq -r '.Name, .Digest, .Created, .Labels'

##@ Volume Management

volumes-backup: ## Backup all named volumes
	@echo "$(YELLOW)Backing up volumes...$(NC)"
	@bash scripts/backup-volumes.sh

volumes-restore: ## Restore volumes from backup
	@echo "$(YELLOW)Restoring volumes...$(NC)"
	@bash scripts/restore-volumes.sh

volumes-clean: ## Remove all named volumes (WARNING: data loss!)
	@echo "$(RED)WARNING: This will delete all volume data!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		podman volume rm -f ringwall_dev-home ringwall_build-cache ringwall_test-results ringwall_ci-reports || true; \
		echo "$(GREEN)Volumes cleaned$(NC)"; \
	else \
		echo "$(YELLOW)Aborted$(NC)"; \
	fi

##@ Validation and Testing

lint: ## Run code quality checks in CI container
	@echo "$(YELLOW)Running lint checks...$(NC)"
	@podman-compose run --rm ci /usr/local/bin/run-lint

validate: ## Run quick validation in CI container
	@echo "$(YELLOW)Running quick validation...$(NC)"
	@podman-compose run --rm ci /usr/local/bin/quick-validate

verify-rootless: ## Verify containers can run in rootless mode
	@echo "$(YELLOW)Verifying rootless mode...$(NC)"
	@bash scripts/verify-rootless.sh

verify-selinux: ## Verify SELinux labels on volumes
	@echo "$(YELLOW)Verifying SELinux labels...$(NC)"
	@bash scripts/verify-selinux.sh

##@ Cleanup

clean-containers: ## Remove all stopped containers
	@echo "$(YELLOW)Removing stopped containers...$(NC)"
	@podman-compose down
	@podman container prune -f
	@echo "$(GREEN)Containers cleaned$(NC)"

clean-images: ## Remove all built images
	@echo "$(YELLOW)Removing built images...$(NC)"
	@podman rmi -f $(DEV_IMAGE) $(TEST_IMAGE) $(BUILD_IMAGE) $(CI_IMAGE) 2>/dev/null || true
	@echo "$(GREEN)Images cleaned$(NC)"

clean-volumes: volumes-clean ## Alias for volumes-clean

clean-build-cache: ## Clean build artifacts and cache
	@echo "$(YELLOW)Cleaning build cache...$(NC)"
	@rm -rf ../../build ../../build-quick
	@echo "$(GREEN)Build cache cleaned$(NC)"

clean: clean-containers clean-build-cache ## Clean containers and build cache (keeps images and volumes)
	@echo "$(GREEN)Cleanup completed (images and volumes preserved)$(NC)"

clean-all: clean-containers clean-images clean-volumes clean-build-cache ## Remove everything (WARNING: full cleanup!)
	@echo "$(RED)WARNING: This will remove all containers, images, volumes, and build cache!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		buildah rm --all 2>/dev/null || true; \
		podman system prune -af --volumes; \
		echo "$(GREEN)Full cleanup completed$(NC)"; \
	else \
		echo "$(YELLOW)Aborted$(NC)"; \
	fi

##@ Development Workflow

quick: ## Quick build and test cycle (fast feedback)
	@echo "$(YELLOW)Quick build and test...$(NC)"
	@podman-compose run --rm ci /usr/local/bin/quick-validate

full-test: ## Full test suite with coverage
	@echo "$(YELLOW)Running full test suite...$(NC)"
	@podman-compose run --rm test /usr/local/bin/run-tests

benchmark: ## Run performance benchmarks
	@echo "$(YELLOW)Running benchmarks...$(NC)"
	@podman-compose run --rm test /usr/local/bin/run-benchmarks

release: ## Build release artifacts
	@echo "$(YELLOW)Building release...$(NC)"
	@mkdir -p artifacts
	@podman-compose run --rm build /usr/local/bin/build-release
	@echo "$(GREEN)Release artifacts created in: artifacts/$(NC)"

##@ System Information

info: ## Display system and container information
	@echo "$(BLUE)System Information:$(NC)"
	@echo "  Podman version: $$(podman --version)"
	@echo "  Buildah version: $$(buildah --version)"
	@echo "  Skopeo version: $$(skopeo --version)"
	@echo "  crun version: $$(crun --version | head -1)"
	@echo ""
	@echo "$(BLUE)Container Images:$(NC)"
	@podman images | grep $(PROJECT_NAME) || echo "  No images found"
	@echo ""
	@echo "$(BLUE)Running Containers:$(NC)"
	@podman ps --filter "name=$(PROJECT_NAME)" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" || echo "  No containers running"
	@echo ""
	@echo "$(BLUE)Volumes:$(NC)"
	@podman volume ls --filter "name=$(PROJECT_NAME)" --format "table {{.Name}}\t{{.Mountpoint}}" || echo "  No volumes found"

version: ## Display project version
	@echo "$(PROJECT_NAME) version $(PROJECT_VERSION)"

##@ Advanced

rebuild-all: clean-images build-all ## Rebuild all images from scratch
	@echo "$(GREEN)All images rebuilt from scratch$(NC)"

prune: ## Prune unused resources (safe cleanup)
	@echo "$(YELLOW)Pruning unused resources...$(NC)"
	@podman system prune -f
	@echo "$(GREEN)Pruning completed$(NC)"

shell-host: ## Open shell on host with proper environment
	@echo "$(BLUE)Environment configured for Podman operations$(NC)"
	@bash --rcfile <(echo "PS1='[ocserv-podman] \w $$ '")
