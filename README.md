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
- `emuko` — CLI: download, daemon control (`start`, `stop`, `dump`, `step`, `con`, `uart`, etc.)
- `emukod` — daemon with HTTP API + standalone emulator (debug mode)
- `emuko-debug-jitdiff` — JIT correctness checker

## Quick Start

### Download a kernel

```
emuko dow
```

This downloads the Debian RISC-V netboot kernel and initrd to `~/.emuko/riscv64/debian-netboot/` with SHA256 verification.

### Boot Linux (interactive daemon)

```
./runlinux_interactive.sh --kernel <kernel> --initrd <initrd>
```

Or start the daemon directly and control it with `emuko`:

```
emukod --kernel <kernel> --initrd <initrd> --autostart &
emuko dump             # print CPU state
emuko con              # continue execution
emuko stop             # pause
emuko step 1000        # step N instructions
emuko uart-inject "ls" # inject command into guest UART
emuko snap             # take a snapshot
emuko ls               # list snapshots
```

The daemon exposes an HTTP API at `http://127.0.0.1:7788/v1/api/` with endpoints: `start`, `stop`, `dump`, `step`, `continue`, `set`, `snap`, `ls`, `restore`, `uart`.

### Run a bare-metal binary

```
emukod program.bin --steps 10000
```

### Snapshots

```
# Save
emukod <kernel> --linux --initrd <initrd> \
  --save-snapshot state.emuko.zst --steps 5000000

# Restore
emukod <kernel> --linux --initrd <initrd> \
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

Use `emuko dow` (see Quick Start above) or grab pre-built images from [DQIB (Debian Quick Image Baker)](https://people.debian.org/~gio/dqib/). To download a specific set:

```
emuko dow debian-netboot
```

## License

Apache 2.0. See [LICENSE](LICENSE).
