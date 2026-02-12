#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DAEMON_BIN="${DAEMON_BIN:-target/release/koriscvd}"
KOR_ADDR="${KOR_ADDR:-127.0.0.1:7788}"
SNAPSHOT="${SNAPSHOT:-/tmp/korisc5-rd/snap-00000000002600400005.kriscv.zst}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/tmp/korisc5-rd}"
CHUNK_STEPS="${CHUNK_STEPS:-10000}"

exec "$DAEMON_BIN" \
  --snapshot "$SNAPSHOT" \
  --addr "$KOR_ADDR" \
  --snapshot-dir "$SNAPSHOT_DIR" \
  --chunk-steps "$CHUNK_STEPS"
