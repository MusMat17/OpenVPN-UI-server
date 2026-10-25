#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p bin
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o bin/openvpn-control-linux-amd64 ./cmd/openvpn-control
printf 'Built bin/openvpn-control-linux-amd64\n'
