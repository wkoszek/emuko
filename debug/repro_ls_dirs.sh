#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EMU_BIN="${EMU_BIN:-target/release/emuko}"
EMUKO_ADDR="${EMUKO_ADDR:-127.0.0.1:7789}"
LOG_DIR="${LOG_DIR:-/tmp/emuko-debug}"
READ_CHUNK="${READ_CHUNK:-120000}"
SLICE_SLEEP="${SLICE_SLEEP:-0.20}"
MAX_SLICES="${MAX_SLICES:-140}"

mkdir -p "$LOG_DIR"
TS="$(date +%Y%m%d-%H%M%S)"
UART_LOG="$LOG_DIR/repro-ls-dirs-uart-$TS.log"
STATE_LOG="$LOG_DIR/repro-ls-dirs-state-$TS.log"

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

wait_for_marker() {
  local marker="$1"
  local tag="$2"
  local i
  for i in $(seq 1 "$MAX_SLICES"); do
    sleep "$SLICE_SLEEP"
    drain_uart "$tag/slice_$i"
    if rg -q "$marker" "$UART_LOG"; then
      return 0
    fi
  done
  return 1
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

run_ls_dir() {
  local dir="$1"
  local safe
  safe="$(echo "$dir" | sed 's#[^A-Za-z0-9]#_#g')"
  local start="__LS_BEGIN_${safe}__"
  local end="__LS_END_${safe}__"
  echo "Running: ls $dir"
  kor_retry uart-inject "echo ${start}\\nls ${dir}\\necho ${end}\\n" >/dev/null
  if ! wait_for_marker "$end" "ls_${safe}"; then
    echo "Timeout waiting for $end"
    sample_state "ls_${safe}/timeout"
    return 1
  fi
  return 0
}

if ! kor_retry dump >/dev/null; then
  echo "Daemon not reachable at $EMUKO_ADDR" >&2
  exit 1
fi

kor_retry con >/dev/null || true
sleep 0.05
kor_retry uart-inject "\\x03\\n" >/dev/null || true
sleep 0.15
drain_uart "recover"

DIRS=(/ bin dev etc init initrd lib media mnt proc root run sbin sys tmp usr var)

rc=0
for d in "${DIRS[@]}"; do
  run_ls_dir "$d" || rc=1
done

echo "UART log:  $UART_LOG"
echo "State log: $STATE_LOG"
exit "$rc"
