#!/bin/bash
set -euo pipefail

go test -skip='(NewLoader|BpfTramp)' -cover -v ./...
