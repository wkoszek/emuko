#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build --release
target/release/emuko dow debian-netboot
K=~/.emuko/riscv64/debian-netboot/linux
I=~/.emuko/riscv64/debian-netboot/initrd.gz
target/release/emuko start "$K" "$I" --autostart &
sleep 3
target/release/emuko dump | head -5
target/release/emuko stop
echo "PASS: smoke test complete"
