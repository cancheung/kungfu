#!/usr/bin/env bash
set -e

CURRENT_DIR=$(cd $(dirname $0); pwd)
cd "$CURRENT_DIR"

GOPATH=$(cd ../../../../; pwd)
if [[ ! -d "$GOPATH" ]]; then
	echo >&2 'set GOPATH error'
	exit 1
fi

GIT_HASH=$((git show-ref --head --hash=8 2> /dev/null || echo 00000000) | head -n1)

RELEASE_DIR="$CURRENT_DIR/release"

BIN_DNS_SERVER="kungfu-dns-server"
BIN_GATEWAY_SERVER="kungfu-gateway-server"

echo "GOPATH: $GOPATH"
export GOPATH="$GOPATH"

echo "GIT_HASH: $GIT_HASH"

if [[ ! -d "$RELEASE_DIR" ]]; then
	mkdir -p "$RELEASE_DIR"
fi

go build -o "$RELEASE_DIR/$BIN_DNS_SERVER" -ldflags="-X main.build=$GIT_HASH -s -w" dns/server/main.go
go build -o "$RELEASE_DIR/$BIN_GATEWAY_SERVER" -ldflags="-X main.build=$GIT_HASH -s -w" gateway/server/main.go
cp "$CURRENT_DIR/config-example.yml" "$RELEASE_DIR/config.yml"

echo "Done!"
