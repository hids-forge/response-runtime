-include .env

PROJECT_NAME ?= response-runtime
VERSION_FILE ?= VERSION
VERSION ?= $(shell cat $(VERSION_FILE) 2>/dev/null || echo 0.1.0-dev)
GIT_HASH ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo nogit)
BUILD_VERSION ?= $(VERSION)+$(GIT_HASH)
DIST_DIR ?= dist
TARGETS ?= linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

ACTIVE_RESPONSE_BIN ?= active-response
EMERGENCY_RESPONSE_BIN ?= emergency-response

ACTIVE_RESPONSE_NAME_LINUX ?= $(ACTIVE_RESPONSE_BIN)-linux
ACTIVE_RESPONSE_NAME_DARWIN ?= $(ACTIVE_RESPONSE_BIN)-macos
ACTIVE_RESPONSE_NAME_WINDOWS ?= $(ACTIVE_RESPONSE_BIN).exe

EMERGENCY_RESPONSE_NAME_LINUX ?= $(EMERGENCY_RESPONSE_BIN)-linux
EMERGENCY_RESPONSE_NAME_DARWIN ?= $(EMERGENCY_RESPONSE_BIN)-macos
EMERGENCY_RESPONSE_NAME_WINDOWS ?= $(EMERGENCY_RESPONSE_BIN).exe

BUILD_EMERGENCY_RESPONSE ?= 0
ENABLE_DANGER_EMERGENCIES ?= 0
ENABLE_UNSAFE_FEATURES ?= 0
ENABLE_REMOTE_UPDATES ?= 0
ENABLE_JS_FILE_READS ?= 0
ENABLE_JS_SENSITIVE_READS ?= 0
ENABLE_JS_UNSAFE_FEATURES ?= 0
ENABLE_JS_HTTP_IMPORT ?= 0
ENABLE_HTTP_CLIENT ?= 0
ENABLE_JS_NETWORK_PROBES ?= 0
ENABLE_JS_WALK_DIR ?= 0
ENABLE_JS_UNSAFE_WITH_AUTH ?= 0
UPDATE_MANIFEST_URL ?= https://updates.example.invalid/response-runtime/manifest.json

FEATURE_TAGS :=
ifeq ($(ENABLE_DANGER_EMERGENCIES),1)
FEATURE_TAGS += danger_emergencies
endif
ifeq ($(ENABLE_UNSAFE_FEATURES),1)
FEATURE_TAGS += unsafe_features
endif
ifeq ($(ENABLE_REMOTE_UPDATES),1)
FEATURE_TAGS += enable_remote_updates
endif
ifeq ($(ENABLE_JS_FILE_READS),1)
FEATURE_TAGS += js_file_read
endif
ifeq ($(ENABLE_JS_SENSITIVE_READS),1)
FEATURE_TAGS += js_sensitive_reads
endif
ifeq ($(ENABLE_JS_UNSAFE_FEATURES),1)
FEATURE_TAGS += js_unsafe_features
endif
ifeq ($(ENABLE_JS_HTTP_IMPORT),1)
FEATURE_TAGS += js_enable_http_import
endif
ifeq ($(ENABLE_HTTP_CLIENT),1)
FEATURE_TAGS += enable_http_client
endif
ifeq ($(ENABLE_JS_NETWORK_PROBES),1)
FEATURE_TAGS += js_network_probes
endif
ifeq ($(ENABLE_JS_WALK_DIR),1)
FEATURE_TAGS += js_walk_dir
endif
ifeq ($(ENABLE_JS_UNSAFE_WITH_AUTH),1)
FEATURE_TAGS += js_unsafe_with_auth
endif

TAGS_FLAG :=
ifneq ($(strip $(FEATURE_TAGS)),)
TAGS_FLAG := -tags '$(strip $(FEATURE_TAGS))'
endif

LDFLAGS := -s -w \
	-X github.com/hids-forge/response-runtime/pkg/version.Version=$(BUILD_VERSION) \
	-X github.com/hids-forge/response-runtime/cmd/active-response/internal/version.Full=$(BUILD_VERSION) \
	-X github.com/hids-forge/response-runtime/cmd/active-response/internal/updateclient.DefaultManifestURL=$(UPDATE_MANIFEST_URL) \
	-X main.defaultActiveResponseBin=$(ACTIVE_RESPONSE_BIN)

.PHONY: help build build-host clean print-config test playbook-test-safe update-keygen

help:
	@echo "response-runtime build targets"
	@echo ""
	@echo "Targets:"
	@echo "  make build       Build the safe default cross-platform active-response artifacts"
	@echo "  make build-host  Build host-platform binaries using the current feature toggles"
	@echo "  make test        Run go test ./..."
	@echo "  make playbook-test-safe  Run the safe sample playbooks locally"
	@echo "  make update-keygen  Generate a fresh RSA update signing keypair under build/update-keys"
	@echo "  make clean       Remove dist/ artifacts and local binaries"
	@echo "  make print-config"
	@echo ""
	@echo "Default behavior:"
	@echo "  - builds active-response only"
	@echo "  - excludes emergency-response unless BUILD_EMERGENCY_RESPONSE=1"
	@echo "  - excludes unsafe, emergency, update, and HTTP-capable features unless explicitly enabled"
	@echo ""
	@echo "Environment toggles:"
	@echo "  BUILD_EMERGENCY_RESPONSE=1    Build the emergency-response MQTT control-plane binary"
	@echo "  ENABLE_DANGER_EMERGENCIES=1   Enable emergency-response RPC such as openShell and endpoint file extraction"
	@echo "  ENABLE_UNSAFE_FEATURES=1      Enable non-JS unsafe local control/destructive features"
	@echo "  ENABLE_REMOTE_UPDATES=1       Enable HTTP self-update and updater commands"
	@echo "  UPDATE_MANIFEST_URL=...       Default signed update manifest URL for updater-enabled builds"
	@echo "  ENABLE_JS_FILE_READS=1        Enable JS readFile/readTextFile helpers"
	@echo "  ENABLE_JS_SENSITIVE_READS=1   Enable JS hosts/auth/registry read helpers"
	@echo "  ENABLE_JS_UNSAFE_FEATURES=1   Enable JS exec/write/import-from-file helpers"
	@echo "  ENABLE_JS_HTTP_IMPORT=1       Enable JS importModule over HTTP(S)"
	@echo "  ENABLE_HTTP_CLIENT=1          Enable JS httpGet/httpPost helpers"
	@echo "  ENABLE_JS_NETWORK_PROBES=1    Enable JS active network probing helpers"
	@echo "  ENABLE_JS_WALK_DIR=1          Enable JS recursive directory walking"
	@echo "  ENABLE_JS_UNSAFE_WITH_AUTH=1  Enable authenticated JS helpers such as sshExec"
	@echo ""
	@echo "Output naming overrides:"
	@echo "  ACTIVE_RESPONSE_BIN=respd"
	@echo "  ACTIVE_RESPONSE_NAME_LINUX=respd-linux"
	@echo "  EMERGENCY_RESPONSE_BIN=emergency-response"
	@echo "  EMERGENCY_RESPONSE_NAME_WINDOWS=emergency-response.exe"
	@echo "  RESPONSE_RUNTIME_ACTIVE_RESPONSE_BIN=/path/to/active-response"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make build BUILD_EMERGENCY_RESPONSE=1"
	@echo "  make build ENABLE_JS_UNSAFE_WITH_AUTH=1"
	@echo "  make build BUILD_EMERGENCY_RESPONSE=1 ENABLE_DANGER_EMERGENCIES=1"
	@echo "  make build ENABLE_REMOTE_UPDATES=1 ENABLE_HTTP_CLIENT=1"
	@echo ""
	@echo "Runtime override:"
	@echo "  emergency-response locates the companion active-response binary by build-time name."
	@echo "  Set RESPONSE_RUNTIME_ACTIVE_RESPONSE_BIN to override the path explicitly."

print-config:
	@echo "Build configuration"
	@echo "  VERSION=$(VERSION)"
	@echo "  GIT_HASH=$(GIT_HASH)"
	@echo "  BUILD_VERSION=$(BUILD_VERSION)"
	@echo "  BUILD_EMERGENCY_RESPONSE=$(BUILD_EMERGENCY_RESPONSE)"
	@echo "  ENABLE_DANGER_EMERGENCIES=$(ENABLE_DANGER_EMERGENCIES)"
	@echo "  ENABLE_UNSAFE_FEATURES=$(ENABLE_UNSAFE_FEATURES)"
	@echo "  ENABLE_REMOTE_UPDATES=$(ENABLE_REMOTE_UPDATES)"
	@echo "  UPDATE_MANIFEST_URL=$(UPDATE_MANIFEST_URL)"
	@echo "  ENABLE_JS_FILE_READS=$(ENABLE_JS_FILE_READS)"
	@echo "  ENABLE_JS_SENSITIVE_READS=$(ENABLE_JS_SENSITIVE_READS)"
	@echo "  ENABLE_JS_UNSAFE_FEATURES=$(ENABLE_JS_UNSAFE_FEATURES)"
	@echo "  ENABLE_JS_HTTP_IMPORT=$(ENABLE_JS_HTTP_IMPORT)"
	@echo "  ENABLE_HTTP_CLIENT=$(ENABLE_HTTP_CLIENT)"
	@echo "  ENABLE_JS_NETWORK_PROBES=$(ENABLE_JS_NETWORK_PROBES)"
	@echo "  ENABLE_JS_WALK_DIR=$(ENABLE_JS_WALK_DIR)"
	@echo "  ENABLE_JS_UNSAFE_WITH_AUTH=$(ENABLE_JS_UNSAFE_WITH_AUTH)"
	@echo "  FEATURE_TAGS=$(strip $(FEATURE_TAGS))"

build: print-config
	@mkdir -p "$(DIST_DIR)/$(BUILD_VERSION)"
	@for target in $(TARGETS); do \
		GOOS=$${target%/*}; \
		GOARCH=$${target#*/}; \
		case $$GOOS in \
			linux) ar_name="$(ACTIVE_RESPONSE_NAME_LINUX)"; er_name="$(EMERGENCY_RESPONSE_NAME_LINUX)" ;; \
			darwin) ar_name="$(ACTIVE_RESPONSE_NAME_DARWIN)"; er_name="$(EMERGENCY_RESPONSE_NAME_DARWIN)" ;; \
			windows) ar_name="$(ACTIVE_RESPONSE_NAME_WINDOWS)"; er_name="$(EMERGENCY_RESPONSE_NAME_WINDOWS)" ;; \
			*) echo "Unsupported GOOS $$GOOS" >&2; exit 1 ;; \
		esac; \
		outdir="$(DIST_DIR)/$(BUILD_VERSION)/$$GOOS-$$GOARCH"; \
		mkdir -p "$$outdir"; \
		echo "Building active-response for $$GOOS/$$GOARCH -> $$outdir/$$ar_name"; \
		CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH go build $(TAGS_FLAG) -ldflags "$(LDFLAGS)" -o "$$outdir/$$ar_name" ./cmd/active-response; \
		if [ "$(BUILD_EMERGENCY_RESPONSE)" = "1" ]; then \
			echo "Building emergency-response for $$GOOS/$$GOARCH -> $$outdir/$$er_name"; \
			CGO_ENABLED=0 GOOS=$$GOOS GOARCH=$$GOARCH go build $(TAGS_FLAG) -ldflags "$(LDFLAGS)" -o "$$outdir/$$er_name" ./cmd/emergency-response; \
		fi; \
	done

build-host: print-config
	@mkdir -p "$(DIST_DIR)/host"
	@echo "Building active-response for host platform"
	@go build $(TAGS_FLAG) -ldflags "$(LDFLAGS)" -o "$(DIST_DIR)/host/$(ACTIVE_RESPONSE_BIN)" ./cmd/active-response
	@if [ "$(BUILD_EMERGENCY_RESPONSE)" = "1" ]; then \
		echo "Building emergency-response for host platform"; \
		go build $(TAGS_FLAG) -ldflags "$(LDFLAGS)" -o "$(DIST_DIR)/host/$(EMERGENCY_RESPONSE_BIN)" ./cmd/emergency-response; \
	fi

test:
	@go test ./...

playbook-test-safe: build-host
	@echo "Running safe sample playbooks"
	@./dist/host/$(ACTIVE_RESPONSE_BIN) local-run-js --playbook playbooks/hunt/hash_and_report_file.js --alert playbooks/testdata/hash_and_report_file.alert.json >/tmp/response-runtime-playbook-hash.out
	@./dist/host/$(ACTIVE_RESPONSE_BIN) local-run-js --playbook playbooks/hunt/find_process_by_exe_and_hash.js --alert playbooks/testdata/find_process_by_exe_and_hash.alert.json >/tmp/response-runtime-playbook-find.out
	@./dist/host/$(ACTIVE_RESPONSE_BIN) local-run-js --playbook playbooks/hunt/collect_process_network_context.js --alert playbooks/testdata/collect_process_network_context.alert.json >/tmp/response-runtime-playbook-process.out
	@echo "Safe playbooks passed"

update-keygen:
	@go run ./cmd/update-keygen --out-dir build/update-keys

clean:
	@rm -rf "$(DIST_DIR)"
	@rm -f ./active-response ./emergency-response
