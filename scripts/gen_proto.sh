#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "$0")"/.. && pwd)
PROTO_DIR="$ROOT_DIR/proto"
GO_OUT="$ROOT_DIR"
PY_OUT="$ROOT_DIR/python/worker/gen"
PROTO_FILE="$PROTO_DIR/ida/worker/v1/service.proto"
mkdir -p "$PY_OUT"
if ! command -v protoc >/dev/null 2>&1; then
  echo "protoc is required but not found in PATH" >&2
  exit 1
fi
protoc \
  -I"$PROTO_DIR" \
  --go_out="$GO_OUT" --go_opt=paths=source_relative \
  --connect-go_out="$GO_OUT" --connect-go_opt=paths=source_relative \
  "$PROTO_FILE"
protoc \
  -I"$PROTO_DIR" \
  --python_out="$PY_OUT" \
  "$PROTO_FILE"
