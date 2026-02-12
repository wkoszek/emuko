#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

KOR_BIN="${KOR_BIN:-target/release/kor}"
KOR_ADDR="${KOR_ADDR:-127.0.0.1:7789}"
LOG_DIR="${LOG_DIR:-/tmp/korisc5-debug}"
READ_CHUNK="${READ_CHUNK:-120000}"
SLICE_SLEEP="${SLICE_SLEEP:-0.20}"
MAX_BIN_SLICES="${MAX_BIN_SLICES:-120}"
MAX_ETC_SLICES="${MAX_ETC_SLICES:-260}"

mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
UART_LOG="$LOG_DIR/repro-lsl-bin-etc-uart-$TS.log"
UART_RAW="$LOG_DIR/repro-lsl-bin-etc-uart-raw-$TS.log"
STATE_LOG="$LOG_DIR/repro-lsl-bin-etc-state-$TS.log"

kor() {
  KOR_ADDR="$KOR_ADDR" "$KOR_BIN" "$@"
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
    printf '%s' "$out" >>"$UART_RAW"
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

wait_for_token() {
  local token="$1"
  local tag="$2"
  local max_slices="$3"
  local i
  for i in $(seq 1 "$max_slices"); do
    sleep "$SLICE_SLEEP"
    drain_uart "$tag/slice_$i"
    sample_state "$tag/slice_$i"
    if rg -q "$token" "$UART_RAW"; then
      return 0
    fi
  done
  return 1
}

if ! kor_retry dump >/dev/null; then
  echo "Daemon not reachable at $KOR_ADDR" >&2
  exit 1
fi

kor_retry con >/dev/null || true
sleep 0.05
kor_retry uart-inject "\\x03\\n" >/dev/null || true
sleep 0.15
drain_uart "recover"
sample_state "recover"

echo "Running: ls -l bin"
kor_retry uart-inject "echo __LSL_BIN_BEGIN__\\nls -l bin\\necho __LSL_BIN_END__\\n" >/dev/null
if ! wait_for_token "__LSL_BIN_END__" "bin" "$MAX_BIN_SLICES"; then
  echo "Timeout waiting for __LSL_BIN_END__"
fi

echo "Running: ls -l etc"
kor_retry uart-inject "echo __LSL_ETC_BEGIN__\\nls -l etc\\necho __LSL_ETC_END__\\n" >/dev/null
if ! wait_for_token "__LSL_ETC_END__" "etc" "$MAX_ETC_SLICES"; then
  echo "Timeout waiting for __LSL_ETC_END__"
fi

echo "UART log:      $UART_LOG"
echo "UART raw log:  $UART_RAW"
echo "State log:     $STATE_LOG"
