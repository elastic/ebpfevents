SHELL := /bin/bash

BUILD_ARCH ?= amd64
OUT_PATH ?= $(shell pwd)/artifacts/$(BUILD_ARCH)

CLANG ?= clang-16
CLANG_FORMAT ?= clang-format-16
CFLAGS := -O2 -g -D__KERNEL__ $(CFLAGS)

.PHONY: generate build-eventstrace tidy clean lint test notice dependency-report write-license-headers

all: generate

generate:
	go generate ./event.go
	BPF_CLANG=$(CLANG) BPF_CFLAGS="$(CFLAGS)" BPF_TARGET=$(BUILD_ARCH) go generate ./gen_$(BUILD_ARCH).go

build-eventstrace:
	mkdir -p $(OUT_PATH)
	CGO_ENABLED=0 GOARCH=$(BUILD_ARCH) go build -v -o $(OUT_PATH)/eventstrace ./cmd/eventstrace

tidy:
	go mod tidy

clean:
	rm -rf artifacts/*
	rm -f bpf_*

lint:
	golangci-lint run -v --timeout=600s

test:
	go test -cover -v -race $(shell go list ./...)

notice:
	@echo "Generate NOTICE"
	go mod tidy
	go mod download
	go list -m -json all | go run go.elastic.co/go-licence-detector \
		-includeIndirect \
		-rules tools/notice/rules.json \
		-overrides tools/notice/overrides.json \
		-noticeTemplate tools/notice/NOTICE.txt.tmpl \
		-noticeOut NOTICE.txt \
		-depsOut ""

dependency-report:
	@echo "Generate dependencies.csv"
	go mod tidy
	go mod download
	go list -m -json all | go run go.elastic.co/go-licence-detector \
		-includeIndirect \
		-rules "tools/notice/rules.json" \
		-overrides "tools/notice/overrides.json" \
		-noticeTemplate "tools/notice/dependencies.csv.tmpl" \
		-noticeOut dependencies.csv \
		-depsOut ""

write-license-headers:
	@echo "Write license headers"
	go run github.com/elastic/go-licenser \
		-ext ".go" \
		-license ASL2 \
		-licensor "Elasticsearch B.V." \
		-exclude bpf_bpfel* \
		-exclude ebpf \
		.
