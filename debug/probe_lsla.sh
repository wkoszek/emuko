#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EMU_BIN="${EMU_BIN:-target/release/emu}"
DAEMON_BIN="${DAEMON_BIN:-target/release/emukod}"
EMUKO_ADDR="${EMUKO_ADDR:-127.0.0.1:7788}"
SNAPSHOT="${SNAPSHOT:-/tmp/emuko-rd/snap-00000000002600400005.emuko.zst}"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/tmp/emuko-rd}"
CHUNK_STEPS="${CHUNK_STEPS:-10000}"
STEP_SLEEP="${STEP_SLEEP:-0.08}"
BOOT_LOOPS="${BOOT_LOOPS:-40}"
POST_LOOPS="${POST_LOOPS:-60}"
CMD_ESC="${CMD_ESC:-ls -la\\n}"
LOG_DIR="${LOG_DIR:-/tmp/emuko-debug}"
KEEP_DAEMON="${KEEP_DAEMON:-0}"

mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
UART_LOG="$LOG_DIR/uart-$TS.log"
STATE_LOG="$LOG_DIR/state-$TS.jsonl"
DAEMON_LOG="$LOG_DIR/daemon-$TS.log"
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
  local n
  for n in 1 2 3 4 5; do
    if out="$(kor "$@" 2>/dev/null)"; then
      printf '%s' "$out"
      return 0
    fi
    sleep 0.03
  done
  return 1
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

echo "Starting daemon at $EMUKO_ADDR (snapshot: $SNAPSHOT)"
"$DAEMON_BIN" \
  --snapshot "$SNAPSHOT" \
  --addr "$EMUKO_ADDR" \
  --snapshot-dir "$SNAPSHOT_DIR" \
  --chunk-steps "$CHUNK_STEPS" \
  >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

daemon_ready=0
for _ in $(seq 1 30); do
  if kor_retry dump >/dev/null; then
    daemon_ready=1
    break
  fi
  sleep 0.05
done

if [[ "$daemon_ready" != "1" ]]; then
  echo "Daemon did not become ready. Daemon log:" >&2
  sed -n '1,120p' "$DAEMON_LOG" >&2 || true
  exit 1
fi

BASE_SNAP="$(basename "$SNAPSHOT")"
kor_retry restore "$BASE_SNAP" >/dev/null || {
  echo "Failed to restore snapshot via daemon" >&2
  exit 1
}
kor_retry uart-read 500000 >/dev/null || true
# Force shell to re-emit prompt when snapshot already sits in an idle loop.
kor_retry uart-inject "\\n" >/dev/null || true

echo "Booting toward prompt..."
prompt_seen=0
for ((i = 1; i <= BOOT_LOOPS; i++)); do
  kor_retry start >/dev/null || true
  sleep "$STEP_SLEEP"
  kor_retry stop >/dev/null || true
  out="$(kor_retry uart-read 200000 || true)"
  if [[ -n "$out" ]]; then
    printf '%s' "$out" >>"$UART_LOG"
  fi
  st="$(kor_retry dump || true)"
  if [[ -n "$st" ]]; then
    printf '%s\n' "$st" >>"$STATE_LOG"
  fi
  if grep -q "~ #" "$UART_LOG"; then
    prompt_seen=1
    echo "Prompt seen at boot loop $i"
    break
  fi
done

if [[ "$prompt_seen" != "1" ]]; then
  echo "Prompt not seen. Tail UART log:"
  tail -n 40 "$UART_LOG" || true
  exit 0
fi

echo "Injecting command: $CMD_ESC"
kor_retry uart-inject "$CMD_ESC" >/dev/null || true

echo "Running post-injection loops..."
for ((i = 1; i <= POST_LOOPS; i++)); do
  kor_retry start >/dev/null || true
  sleep "$STEP_SLEEP"
  kor_retry stop >/dev/null || true
  out="$(kor_retry uart-read 200000 || true)"
  if [[ -n "$out" ]]; then
    printf '%s' "$out" >>"$UART_LOG"
  fi
  st="$(kor_retry dump || true)"
  if [[ -n "$st" ]]; then
    printf '%s\n' "$st" >>"$STATE_LOG"
  fi
done

echo "---- UART tail ----"
tail -n 120 "$UART_LOG" || true
echo "---- STATE tail ----"
tail -n 20 "$STATE_LOG" || true
echo "Logs:"
echo "  $UART_LOG"
echo "  $STATE_LOG"
echo "  $DAEMON_LOG"
