#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DAEMON_BIN="${DAEMON_BIN:-target/release/emukod}"
EMUKO_ADDR="${EMUKO_ADDR:-127.0.0.1:7788}"
SNAPSHOT="${SNAPSHOT:-/tmp/emuko-rd/snap-00000000002600400005.emuko.zst}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/tmp/emuko-rd}"
CHUNK_STEPS="${CHUNK_STEPS:-10000}"

exec "$DAEMON_BIN" \
  --snapshot "$SNAPSHOT" \
  --addr "$EMUKO_ADDR" \
  --snapshot-dir "$SNAPSHOT_DIR" \
  --chunk-steps "$CHUNK_STEPS"
