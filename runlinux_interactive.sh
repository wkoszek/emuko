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

TIMEOUT_CMD=()
if [[ -n "$TIMEOUT_SECS" && "$TIMEOUT_SECS" != "0" ]]; then
  if command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD=(gtimeout "$TIMEOUT_SECS")
  elif command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD=(timeout "$TIMEOUT_SECS")
  else
    echo "Warning: timeout not available; running without wall-clock limit." >&2
  fi
fi

STEP_ARGS=()
if [[ -n "$STEPS" ]]; then
  STEP_ARGS+=(--steps "$STEPS")
fi
if [[ "$NO_DUMP" == "1" ]]; then
  STEP_ARGS+=(--no-dump)
fi

SNAPSHOT_ARGS=()
if [[ -n "$SNAPSHOT_LOAD" ]]; then
  SNAPSHOT_ARGS+=(--load-snapshot "$SNAPSHOT_LOAD")
fi
if [[ -n "$SNAPSHOT_SAVE" ]]; then
  SNAPSHOT_ARGS+=(--save-snapshot "$SNAPSHOT_SAVE")
fi
if [[ "$AUTOSNAPSHOT_EVERY" != "0" ]]; then
  mkdir -p "$AUTOSNAPSHOT_DIR"
  SNAPSHOT_ARGS+=(--autosnapshot-every "$AUTOSNAPSHOT_EVERY" --autosnapshot-dir "$AUTOSNAPSHOT_DIR")
fi

exec ${TIMEOUT_CMD[@]+"${TIMEOUT_CMD[@]}"} cargo run --release -- "$KERNEL" \
  ${LOAD_ARGS[@]+"${LOAD_ARGS[@]}"} \
  --ram-size "$RAM_SIZE" \
  --initrd "$INITRD" \
  --linux \
  --bootargs "$BOOTARGS" \
  ${STEP_ARGS[@]+"${STEP_ARGS[@]}"} \
  ${SNAPSHOT_ARGS[@]+"${SNAPSHOT_ARGS[@]}"} \
  --trace-traps "$TRACE_TRAPS" \
  --trace-instr "$TRACE_INSTR" \
  ${EXTRA_SIM_ARGS[@]+"${EXTRA_SIM_ARGS[@]}"}
