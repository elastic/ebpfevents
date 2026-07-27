#!/bin/bash
set -euo pipefail

# No -cover: it needs the covdata tool to report coverage for packages without
# test files, and covdata is missing from auto-downloaded Go toolchains (used
# until the image ships Go >= 1.25 natively).
go test -skip='(NewLoader|BpfTramp)' -v ./...
