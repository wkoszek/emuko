#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="$ROOT_DIR/smoke/build"

ASM="$ROOT_DIR/smoke/mmu_sv39_smoke.S"
LDS="$ROOT_DIR/smoke/link.ld"
ELF="$BUILD_DIR/mmu_sv39_smoke.elf"
BIN="$BUILD_DIR/mmu_sv39_smoke.bin"
MAP="$BUILD_DIR/mmu_sv39_smoke.map"

CC="${CC:-riscv64-elf-gcc}"
OBJCOPY="${OBJCOPY:-riscv64-elf-objcopy}"

STEPS="${STEPS:-300000}"
TIMEOUT_SECS="${TIMEOUT_SECS:-10}"
TRACE_TRAPS="${TRACE_TRAPS:-0}"
TRACE_INSTR="${TRACE_INSTR:-0}"

mkdir -p "$BUILD_DIR"

"$CC" \
  -nostdlib \
  -nostartfiles \
  -march=rv64imac_zicsr \
  -mabi=lp64 \
  -T "$LDS" \
  -Wl,-Map="$MAP" \
  -o "$ELF" \
  "$ASM"

"$OBJCOPY" -O binary "$ELF" "$BIN"

TIMEOUT_CMD=()
if [[ -n "$TIMEOUT_SECS" && "$TIMEOUT_SECS" != "0" ]]; then
  if command -v gtimeout >/dev/null 2>&1; then
    TIMEOUT_CMD=(gtimeout "$TIMEOUT_SECS")
  elif command -v timeout >/dev/null 2>&1; then
    TIMEOUT_CMD=(timeout "$TIMEOUT_SECS")
  fi
fi

cd "$ROOT_DIR"
exec ${TIMEOUT_CMD[@]+"${TIMEOUT_CMD[@]}"} cargo run --release -- \
  "$BIN" \
  --load-addr 0x80000000 \
  --entry-addr 0x80000000 \
  --steps "$STEPS" \
  --no-dump \
  --trace-traps "$TRACE_TRAPS" \
  --trace-instr "$TRACE_INSTR"
