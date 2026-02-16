# emuko

Fast RISC-V emulator written in Rust. Boots Linux.

[emuko.dev](https://emuko.dev)

## Features

- **RV64IMAFDC** with M/S/U privilege levels and Sv39 virtual memory
- **JIT compilation** for ARM64 and x86_64 hosts (adaptive selection)
- **Full Linux boot** with BusyBox userland and interactive shell
- **Snapshot/restore** for saving and resuming full machine state
- **Daemon mode** with HTTP API and live UART command injection
- **Differential checker** to validate JIT against interpreter
- Peripherals: UART 16550, CLINT, PLIC, SBI 1.0, FDT generation
- Single dependency (`zstd`), pure Rust

## Build

```
cargo build --release
```

Binaries are placed in `target/release/`:
- `emuko` — standalone emulator
- `emukod` — daemon with HTTP API
- `emu` — client for the daemon
- `emuko-jitdiff` — JIT correctness checker

## Quick Start

### Boot Linux (standalone)

```
./runlinux.sh <kernel> <initrd>
```

### Boot Linux (interactive daemon)

```
./runlinux_interactive.sh --kernel <kernel> --initrd <initrd>
```

The daemon exposes an HTTP API at `http://127.0.0.1:7788/v1/api/` with endpoints: `start`, `stop`, `dump`, `step`, `continue`, `set`, `uart`.

Use `emu` to interact:

```
emu con          # continue execution
emu stop         # pause
emu dump         # print CPU state
emu step 1000    # step N instructions
emu uart "ls"    # inject command into guest shell
```

### Run a bare-metal binary

```
cargo run --release --bin emuko -- program.bin --steps 10000
```

### Snapshots

```
# Save
cargo run --release --bin emuko -- <kernel> --linux --initrd <initrd> \
  --save-snapshot state.emuko.zst --steps 5000000

# Restore
cargo run --release --bin emuko -- <kernel> --linux --initrd <initrd> \
  --load-snapshot state.emuko.zst
```

## Configuration

Options can be set via CLI flags, environment variables, or `emuko.yml`:

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `--ram-size` | `RAM_SIZE` | 1 GB | RAM in bytes |
| `--steps` | `STEPS` | unlimited | Max instructions to execute |
| `--backend` | `EMUKO_BACKEND` | `adaptive` | `adaptive`, `arm64_jit`, `amd64_jit`, `arm64`, `x86_64` |
| `--bootargs` | `BOOTARGS` | serial console | Kernel command line |
| `--trace-traps N` | `TRACE_TRAPS` | 0 | Print trap details |
| `--trace-instr N` | `TRACE_INSTR` | 0 | Print executed instructions |

## Getting a Kernel

Use [DQIB (Debian Quick Image Baker)](https://people.debian.org/~gio/dqib/) pre-built RISC-V images, or the Debian netboot installer:

```
mkdir -p artifacts/debian-netboot && cd artifacts/debian-netboot
wget http://ftp.debian.org/debian/dists/sid/main/installer-riscv64/current/images/netboot/vmlinuz
wget http://ftp.debian.org/debian/dists/sid/main/installer-riscv64/current/images/netboot/initrd.gz
mv vmlinuz linux
```

## License

Apache 2.0. See [LICENSE](LICENSE).
