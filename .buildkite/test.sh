#!/bin/bash
set -euo pipefail

go test -skip='(NewLoader)' -cover -v ./...
