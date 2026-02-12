#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

KOR_BIN="${KOR_BIN:-target/release/kor}"
KOR_ADDR="${KOR_ADDR:-127.0.0.1:7788}"
COUNT="${COUNT:-200}"
SLEEP_SECS="${SLEEP_SECS:-0.2}"

if [[ ! -x "$KOR_BIN" ]]; then
  echo "Missing $KOR_BIN. Run: cargo build --release" >&2
  exit 1
fi

for ((i = 1; i <= COUNT; i++)); do
  ts="$(date +%H:%M:%S)"
  if out="$(KOR_ADDR="$KOR_ADDR" "$KOR_BIN" dump 2>/dev/null)"; then
    printf '%s %s\n' "$ts" "$out"
  else
    printf '%s {"error":"dump failed"}\n' "$ts"
  fi
  sleep "$SLEEP_SECS"
done
