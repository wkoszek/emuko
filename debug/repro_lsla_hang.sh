#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EMU_BIN="${EMU_BIN:-target/release/emuko}"
EMUKO_ADDR="${EMUKO_ADDR:-127.0.0.1:7788}"
LOG_DIR="${LOG_DIR:-/tmp/emuko-debug}"
READ_CHUNK="${READ_CHUNK:-200000}"
SLICE_SLEEP="${SLICE_SLEEP:-0.20}"
MAX_SLICES="${MAX_SLICES:-90}"

mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
UART_LOG="$LOG_DIR/repro-lsla-uart-$TS.log"
STATE_LOG="$LOG_DIR/repro-lsla-state-$TS.log"

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

stamp() {
  date "+%Y-%m-%d %H:%M:%S"
}

drain_uart() {
  local tag="$1"
  local out
  out="$(kor_retry uart-read "$READ_CHUNK" || true)"
  if [[ -n "$out" ]]; then
    {
      echo "=== $tag @ $(stamp) ==="
      printf '%s' "$out"
      echo
    } >>"$UART_LOG"
  fi
}

sample_state() {
  local tag="$1"
  {
    echo "=== $tag @ $(stamp) ==="
    kor_retry dump || echo "dump_failed"
    kor_retry disas || echo "disas_failed"
    echo
  } >>"$STATE_LOG"
}

wait_for_marker() {
  local marker="$1"
  local tag="$2"
  local i
  for i in $(seq 1 "$MAX_SLICES"); do
    sleep "$SLICE_SLEEP"
    drain_uart "$tag/slice_$i"
    if grep -q "$marker" "$UART_LOG"; then
      return 0
    fi
  done
  return 1
}

prompt_count() {
  if [[ ! -f "$UART_LOG" ]]; then
    echo 0
    return
  fi
  # Count only standalone prompt lines, not echoed command text like "~ # ls ...".
  rg -n "^~ #[[:space:]]*$" "$UART_LOG" 2>/dev/null | wc -l | tr -d ' '
}

wait_for_prompt_advance() {
  local before="$1"
  local tag="$2"
  local i
  for i in $(seq 1 "$MAX_SLICES"); do
    sleep "$SLICE_SLEEP"
    drain_uart "$tag/slice_$i"
    local now
    now="$(prompt_count)"
    if [[ "$now" -gt "$before" ]]; then
      return 0
    fi
  done
  return 1
}

run_cmd() {
  local name="$1"
  local cmd="$2"
  echo "Running: $cmd"
  local before
  before="$(prompt_count)"
  kor_retry uart-inject "${cmd}\\n" >/dev/null || true
  if ! wait_for_prompt_advance "$before" "$name"; then
    echo "Command did not return prompt: $name"
    sample_state "$name/hang_state"
    drain_uart "$name/hang_uart"
    return 1
  fi
  sample_state "$name/done"
  return 0
}

if ! kor_retry dump >/dev/null; then
  echo "Daemon not reachable at $EMUKO_ADDR" >&2
  exit 1
fi

# Ensure CPU is executing (restore leaves daemon paused).
kor_retry con >/dev/null || true
sleep 0.05

# Try to recover prompt first.
kor_retry uart-inject "\\x03\\n" >/dev/null || true
sleep 0.1
drain_uart "recover"

RC=0
run_cmd "ls_ld_core" "ls -ld /init /initrd /media /proc /run /sys /usr" || RC=1
run_cmd "ls_lan" "ls -lan" || RC=1
run_cmd "ls_la_root" "ls -la /" || RC=1
run_cmd "ls_la_initrd" "ls -la initrd" || RC=1
run_cmd "ls_la" "ls -la" || RC=1

echo "UART log:  $UART_LOG"
echo "State log: $STATE_LOG"
exit "$RC"
