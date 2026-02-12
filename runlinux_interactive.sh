#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEBIAN_NETBOOT_DIR="${DEBIAN_NETBOOT_DIR:-$ROOT_DIR/artifacts/debian-netboot}"
DQIB_DIR="${DQIB_DIR:-/Users/wkoszek/Downloads/koriscv/dqib_riscv64-virt}"

DEFAULT_KERNEL="$DQIB_DIR/kernel"
DEFAULT_INITRD="$DQIB_DIR/initrd"
if [[ -f "$DEBIAN_NETBOOT_DIR/linux" ]]; then
  DEFAULT_KERNEL="$DEBIAN_NETBOOT_DIR/linux"
fi
if [[ -f "$DEBIAN_NETBOOT_DIR/initrd.gz" ]]; then
  DEFAULT_INITRD="$DEBIAN_NETBOOT_DIR/initrd.gz"
fi

ARGS=("$@")
KERNEL="${DEFAULT_KERNEL}"
INITRD="${DEFAULT_INITRD}"
if [[ ${#ARGS[@]} -ge 1 ]]; then
  KERNEL="${ARGS[0]}"
fi
if [[ ${#ARGS[@]} -ge 2 ]]; then
  INITRD="${ARGS[1]}"
fi
EXTRA_SIM_ARGS=()
if [[ ${#ARGS[@]} -ge 3 ]]; then
  EXTRA_SIM_ARGS=("${ARGS[@]:2}")
fi

if [[ ! -f "$KERNEL" ]]; then
  echo "Missing kernel: $KERNEL" >&2
  exit 1
fi

if [[ ! -f "$INITRD" ]]; then
  echo "Missing initrd: $INITRD" >&2
  exit 1
fi

if [[ ! -t 0 ]]; then
  echo "Warning: stdin is not a TTY; UART RX may not receive interactive input." >&2
fi

echo "Kernel: $KERNEL" >&2
echo "Initrd: $INITRD" >&2

LOAD_ADDR="${LOAD_ADDR:-0x80200000}"
ENTRY_ADDR="${ENTRY_ADDR:-0x80200000}"
BOOTARGS="${BOOTARGS:-console=ttyS0,115200 earlycon=uart8250,mmio,0x10000000 ignore_loglevel rdinit=/bin/sh}"
RAM_MB="${RAM_MB:-1024}"
RAM_SIZE="${RAM_SIZE:-}"
if [[ -z "$RAM_SIZE" ]]; then
  RAM_SIZE="$((RAM_MB * 1024 * 1024))"
fi
STEPS="${STEPS:-}"
TIMEOUT_SECS="${TIMEOUT_SECS:-0}"
TRACE_TRAPS="${TRACE_TRAPS:-0}"
TRACE_INSTR="${TRACE_INSTR:-0}"
NO_DUMP="${NO_DUMP:-1}"
SNAPSHOT_LOAD="${SNAPSHOT_LOAD:-}"
SNAPSHOT_SAVE="${SNAPSHOT_SAVE:-}"
AUTOSNAPSHOT_EVERY="${AUTOSNAPSHOT_EVERY:-0}"
AUTOSNAPSHOT_DIR="${AUTOSNAPSHOT_DIR:-/tmp/korisc5}"

LOAD_ARGS=()
if command -v file >/dev/null 2>&1; then
  if file "$KERNEL" | grep -q "PE32"; then
    echo "Note: kernel is a PE/EFI image; using PE loader with minimal EFI services." >&2
  else
    LOAD_ARGS+=(--load-addr "$LOAD_ADDR" --entry-addr "$ENTRY_ADDR")
  fi
else
  LOAD_ARGS+=(--load-addr "$LOAD_ADDR" --entry-addr "$ENTRY_ADDR")
fi

cd "$ROOT_DIR"

KOR_ADDR="${KOR_ADDR:-127.0.0.1:7788}"
CHUNK_STEPS="${CHUNK_STEPS:-50000}"
AUTOSTART="${AUTOSTART:-1}"
STARTUP_WAIT_SECS="${STARTUP_WAIT_SECS:-10}"

if [[ -n "$STEPS" ]]; then
  echo "Warning: STEPS is ignored in daemon mode (use: kor step <n>)." >&2
fi
if [[ "$TIMEOUT_SECS" != "0" ]]; then
  echo "Warning: TIMEOUT_SECS is ignored in daemon mode." >&2
fi
if [[ "$TRACE_TRAPS" != "0" || "$TRACE_INSTR" != "0" ]]; then
  echo "Warning: TRACE_TRAPS/TRACE_INSTR are ignored by runlinux_interactive daemon path." >&2
fi
if [[ "$AUTOSNAPSHOT_EVERY" != "0" ]]; then
  echo "Warning: AUTOSNAPSHOT_EVERY is ignored in daemon mode (use: kor snap)." >&2
fi
if [[ -n "$SNAPSHOT_SAVE" ]]; then
  echo "Warning: SNAPSHOT_SAVE is ignored in daemon mode (use: kor snap)." >&2
fi
if [[ ${#LOAD_ARGS[@]} -gt 0 ]]; then
  echo "Warning: --load-addr/--entry-addr are not passed via daemon mode; PE kernel path is recommended." >&2
fi
if [[ ${#EXTRA_SIM_ARGS[@]} -gt 0 ]]; then
  echo "Warning: extra simulator args are ignored by daemon launcher: ${EXTRA_SIM_ARGS[*]}" >&2
fi

DAEMON_ARGS=(--addr "$KOR_ADDR" --snapshot-dir "$AUTOSNAPSHOT_DIR" --chunk-steps "$CHUNK_STEPS")
if [[ -n "$SNAPSHOT_LOAD" ]]; then
  DAEMON_ARGS+=(--snapshot "$SNAPSHOT_LOAD")
else
  DAEMON_ARGS+=("$KERNEL" "$INITRD" --ram-size "$RAM_SIZE" --bootargs "$BOOTARGS")
fi

echo "KoRISCV API: http://$KOR_ADDR/v1/api/{start,stop,dump,step,continue,set,uart}" >&2
echo "Chunk steps: $CHUNK_STEPS" >&2

cargo run --release --bin koriscvd -- "${DAEMON_ARGS[@]}" &
daemon_pid=$!
cleanup() {
  if kill -0 "$daemon_pid" >/dev/null 2>&1; then
    kill "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

startup_deadline=$((SECONDS + STARTUP_WAIT_SECS))
ready=0
while [[ "$SECONDS" -lt "$startup_deadline" ]]; do
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS "http://$KOR_ADDR/v1/api/dump" >/dev/null 2>&1; then
      ready=1
      break
    fi
  elif KOR_ADDR="$KOR_ADDR" target/release/kor dump >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.05
done
if [[ "$ready" != "1" ]]; then
  echo "Failed to reach daemon HTTP API at $KOR_ADDR" >&2
  exit 1
fi

if [[ "$AUTOSTART" == "1" ]]; then
  if command -v curl >/dev/null 2>&1; then
    curl -fsS "http://$KOR_ADDR/v1/api/continue" >/dev/null
  else
    KOR_ADDR="$KOR_ADDR" target/release/kor con >/dev/null
  fi
  echo "Execution started. Use 'kor stop' to pause and 'kor dump' to inspect state." >&2
else
  echo "Execution is paused. Start with: KOR_ADDR=$KOR_ADDR kor con" >&2
fi

wait "$daemon_pid"
