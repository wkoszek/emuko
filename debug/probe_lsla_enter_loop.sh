#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EMU_BIN="${EMU_BIN:-target/release/emuko}"
EMUKO_ADDR="${EMUKO_ADDR:-127.0.0.1:7788}"
LOG_DIR="${LOG_DIR:-/tmp/emuko-debug}"
POLL_COUNT="${POLL_COUNT:-24}"
POLL_SLEEP="${POLL_SLEEP:-0.25}"
UART_READ_MAX="${UART_READ_MAX:-200000}"

mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
STATE_LOG="$LOG_DIR/lsla-loop-state-$TS.log"
UART_LOG="$LOG_DIR/lsla-loop-uart-$TS.log"
SNAP_LOG="$LOG_DIR/lsla-loop-snapshot-$TS.log"

if [[ ! -x "$EMU_BIN" ]]; then
  echo "Missing binary: $EMU_BIN. Run: cargo build --release" >&2
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
    sleep 0.05
  done
  return 1
}

timestamp() {
  date "+%Y-%m-%d %H:%M:%S"
}

capture_state() {
  local tag="$1"
  {
    echo "=== $tag @ $(timestamp) ==="
    kor_retry dump || echo "dump_failed"
    kor_retry disas || echo "disas_failed"
    echo
  } >>"$STATE_LOG"
}

capture_uart() {
  local tag="$1"
  local out
  out="$(kor_retry uart-read "$UART_READ_MAX" || true)"
  if [[ -n "$out" ]]; then
    {
      echo "=== $tag @ $(timestamp) ==="
      printf '%s' "$out"
      echo
    } >>"$UART_LOG"
  fi
}

echo "Probing daemon at $EMUKO_ADDR"
if ! kor_retry dump >/dev/null; then
  echo "Daemon is not reachable at $EMUKO_ADDR" >&2
  exit 1
fi

# Ensure simulator is executing while we probe.
kor_retry con >/dev/null || true
sleep 0.05
capture_uart "warmup"

echo "Injecting partial command: ls -la"
kor_retry uart-inject "ls -la" >/dev/null
capture_state "after_partial_inject"
capture_uart "after_partial_inject"

echo "Taking snapshot before newline"
snap_json="$(kor_retry snap)"
printf '%s\n' "$snap_json" | tee "$SNAP_LOG" >/dev/null
capture_state "after_snapshot_before_newline"
capture_uart "after_snapshot_before_newline"

echo "Injecting newline"
kor_retry uart-inject "\\n" >/dev/null
capture_state "after_newline_inject"
capture_uart "after_newline_inject"

echo "Polling $POLL_COUNT times every ${POLL_SLEEP}s"
for i in $(seq 1 "$POLL_COUNT"); do
  sleep "$POLL_SLEEP"
  capture_state "poll_$i"
  capture_uart "poll_$i"
done

echo "Done."
echo "State log: $STATE_LOG"
echo "UART log:  $UART_LOG"
echo "Snap log:  $SNAP_LOG"
