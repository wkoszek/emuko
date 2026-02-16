#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EMU_BIN="${EMU_BIN:-target/release/emuko}"
DAEMON_BIN="${DAEMON_BIN:-target/release/emukod}"
EMUKO_ADDR="${EMUKO_ADDR:-127.0.0.1:7788}"
SNAPSHOT="${SNAPSHOT:-/tmp/emuko-rd/snap-00000000002600400005.emuko.zst}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/tmp/emuko-rd}"
CHUNK_STEPS="${CHUNK_STEPS:-10000}"
LOG_DIR="${LOG_DIR:-/tmp/emuko-debug}"
STEP_SLEEP="${STEP_SLEEP:-0.08}"
WARMUP_LOOPS="${WARMUP_LOOPS:-2}"
LOOPS_PER_CMD="${LOOPS_PER_CMD:-14}"
KEEP_DAEMON="${KEEP_DAEMON:-0}"

mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
UART_LOG="$LOG_DIR/uart-basic-$TS.log"
STATE_LOG="$LOG_DIR/state-basic-$TS.jsonl"
DAEMON_LOG="$LOG_DIR/daemon-basic-$TS.log"
touch "$UART_LOG" "$STATE_LOG" "$DAEMON_LOG"

if [[ ! -x "$EMU_BIN" || ! -x "$DAEMON_BIN" ]]; then
  echo "Missing binaries. Run: cargo build --release" >&2
  exit 1
fi
if [[ ! -f "$SNAPSHOT" ]]; then
  echo "Missing snapshot: $SNAPSHOT" >&2
  exit 1
fi

kor() {
  EMUKO_ADDR="$EMUKO_ADDR" "$EMU_BIN" "$@"
}

kor_retry() {
  local out=""
  for _ in 1 2 3 4 5; do
    if out="$(kor "$@" 2>/dev/null)"; then
      printf '%s' "$out"
      return 0
    fi
    sleep 0.03
  done
  return 1
}

run_slice() {
  kor_retry start >/dev/null || true
  sleep "$STEP_SLEEP"
  kor_retry stop >/dev/null || true
  local out
  out="$(kor_retry uart-read 200000 || true)"
  if [[ -n "$out" ]]; then
    printf '%s' "$out" >>"$UART_LOG"
  fi
  local st
  st="$(kor_retry dump || true)"
  if [[ -n "$st" ]]; then
    printf '%s\n' "$st" >>"$STATE_LOG"
  fi
}

cleanup() {
  if [[ "$KEEP_DAEMON" == "1" ]]; then
    return
  fi
  if [[ -n "${DAEMON_PID:-}" ]]; then
    kill "$DAEMON_PID" >/dev/null 2>&1 || true
    wait "$DAEMON_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

echo "Starting daemon at $EMUKO_ADDR"
"$DAEMON_BIN" \
  --snapshot "$SNAPSHOT" \
  --addr "$EMUKO_ADDR" \
  --snapshot-dir "$SNAPSHOT_DIR" \
  --chunk-steps "$CHUNK_STEPS" \
  >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

ready=0
for _ in $(seq 1 30); do
  if kor_retry dump >/dev/null; then
    ready=1
    break
  fi
  sleep 0.05
done
if [[ "$ready" != "1" ]]; then
  echo "Daemon did not become ready. Daemon log:" >&2
  sed -n '1,120p' "$DAEMON_LOG" >&2 || true
  exit 1
fi

BASE_SNAP="$(basename "$SNAPSHOT")"
kor_retry restore "$BASE_SNAP" >/dev/null || {
  echo "restore failed" >&2
  exit 1
}
kor_retry uart-read 500000 >/dev/null || true

# No extended prompt wait: just a short warmup plus newline kick.
kor_retry uart-inject "\\n" >/dev/null || true
for _ in $(seq 1 "$WARMUP_LOOPS"); do
  run_slice
done

declare -a CMDS=(
  "ls"
  "ls -la"
  "time uname -a"
  "uname -a"
  "echo sample"
  "echo sample > file"
)

for cmd in "${CMDS[@]}"; do
  printf '\n\n===== CMD: %s =====\n' "$cmd" >>"$UART_LOG"
  echo "Inject: $cmd"
  kor_retry uart-inject "${cmd}\\n" >/dev/null || true
  for _ in $(seq 1 "$LOOPS_PER_CMD"); do
    run_slice
  done
done

echo "---- UART tail ----"
tail -n 140 "$UART_LOG" || true
echo "---- STATE tail ----"
tail -n 20 "$STATE_LOG" || true
echo "Logs:"
echo "  $UART_LOG"
echo "  $STATE_LOG"
echo "  $DAEMON_LOG"
