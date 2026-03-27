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

## Note on speed

Full disclosure: in interpreter mode this emulator is ~3 times slower than Qemu.
In the JIT mode, it's ~29 times slower.
We will get better performance once we implement code block chaining.

## RISC-V Emulator Comparison (emuko vs others)

This is a direct comparison with commonly used RISC-V emulators/simulators: **QEMU**, **Spike**, and **Renode**.

Legend: `✅` = built in / directly documented, `—` = not built in (or not documented in the referenced source).

| Feature | emuko | QEMU (RISC-V `virt`) | Spike (`riscv-isa-sim`) | Renode |
|---------|-------|----------------------|--------------------------|--------|
| JIT / dynamic translation backend | ✅ | ✅ | — | — |
| Snapshot save + restore | ✅ | ✅ | — | ✅ |
| Autosnapshot (periodic) | ✅ | — | — | ✅ |
| HTTP API for machine control | ✅ | — | — | — |
| WebSocket UART console endpoint | ✅ | — | — | — |
| Scriptable UART host bridge primitives | ✅ | — | — | ✅ |
| One-command Debian kernel/initrd download with SHA256 verification | ✅ | — | — | — |
| Built-in JIT-vs-interpreter differential checker | ✅ | — | — | — |
| GDB debugging workflow | — | ✅ | ✅ | ✅ |
| Large RISC-V board/device ecosystem (PCIe/virtio on `virt`) | — | ✅ | — | — |
| Multi-node simulation focus | — | — | — | ✅ |
| Broad ISA extension coverage (incl. RVV, crypto, etc.) | — | — | ✅ | — |

Sources:
- QEMU RISC-V `virt` machine docs: <https://www.qemu.org/docs/master/system/riscv/virt.html>
- QEMU RISC-V system overview: <https://www.qemu.org/docs/master/system/target-riscv.html>
- QEMU GDB usage: <https://www.qemu.org/docs/master/system/gdb.html>
- QMP reference: <https://www.qemu.org/docs/master/interop/qmp-spec.html>
- QEMU monitor (`savevm`, `loadvm`): <https://www.qemu.org/docs/master/system/monitor.html>
- QEMU VM snapshots: <https://www.qemu.org/docs/master/system/images.html>
- Spike README: <https://github.com/riscv-software-src/riscv-isa-sim>
- Renode README: <https://github.com/renode/renode>
- Renode state save/load + autosave: <https://renode.readthedocs.io/en/latest/basic/saving.html>
- Renode GDB integration: <https://renode.readthedocs.io/en/latest/debugging/gdb.html>
- Renode UART host integration: <https://renode.readthedocs.io/en/latest/host-integration/uart.html>

## Build

```
cargo build --release
```

The main binary is `target/release/emuko`.

## Quick Start

### 1. Download a kernel

```
alias emuko=target/release/emuko
emuko dow
```

Downloads the Debian RISC-V netboot kernel and initrd to `~/.emuko/` with SHA256 verification.

### 2. Boot Linux

```
emuko start
```

This starts the emulator daemon and attaches an interactive console. You'll see the kernel boot and get a shell prompt. Keyboard shortcuts:

| Key | Action |
|-----|--------|
| Ctrl+] | Detach from console (daemon keeps running) |
| Ctrl+C | Sent to guest (interrupt running command) |
| Ctrl+D | Sent to guest (EOF) |

### 3. Reattach or control

```
emuko start            # reattach console to running daemon
emuko dump             # print CPU state
emuko stop             # pause execution
emuko con              # continue execution
emuko step 1000        # step N instructions
emuko snap             # take a snapshot
emuko kill             # shut down daemon
```

The daemon exposes an HTTP API at `http://127.0.0.1:7788/v1/api/` and a WebSocket console at `ws://127.0.0.1:7788/v1/ws/uart`.

### Snapshots

```
emuko snap                 # take a snapshot now
emuko snap 5000000         # auto-snapshot every 5M steps
emuko snap stop            # disable auto-snapshots
emuko ls                   # list snapshots
emuko restore <snapshot>   # restore a snapshot
```

## Memory Map

The emuko virtual machine uses a fixed MMIO layout compatible with the QEMU RISC-V `virt` platform.

### Physical address space

| Region | Base | Size | Description |
|--------|------|------|-------------|
| CLINT | `0x0200_0000` | 64 KiB | Core-local interruptor (timer + software IRQ) |
| PLIC | `0x0C00_0000` | 4 MiB | Platform-level interrupt controller (32 sources) |
| UART | `0x1000_0000` | 256 B | NS16550A serial console, IRQ 10 |
| RAM | `0x8000_0000` | 1 GiB | General-purpose RAM (default, configurable) |

For bare-metal programs: write a byte to `0x1000_0000` to emit a character on the UART console.

### RAM layout (Linux boot)

RAM is laid out dynamically at boot. With default settings (`load_addr=0x80200000`, 1 GiB RAM):

```
0x8000_0000  ──── RAM start
                  (unused gap — available for bare-metal use)
0x8020_0000  ──── Kernel image  (default load address)
                  │  .text / .rodata / .data / .bss
                  └─ kernel end (varies by image)
                  (free space)
             ──── initrd        (placed just below DTB)
             ──── DTB           (placed just below EFI / RAM top)
             ──── EFI region    (128 KiB, PE/UEFI kernels only)
0xBFFF_FFFF  ──── RAM end
```

DTB, initrd, and EFI are placed from the top of RAM downward and must not overlap the kernel image. emukod checks for overlaps at boot and aborts with a clear error if RAM is too small.

### RAM layout (bare-metal ELF)

When you `emuko run ./my.elf` the ELF PT_LOAD segments are mapped at their `p_vaddr` addresses. The `examples/bare_printf` example links at `0x8000_0000`:

```
0x8000_0000  ──── .text  (_start → main)
             ──── .rodata
             ──── .data
             ──── .bss   (zeroed by start.S)
             ──── stack  (16 KiB, set up by start.S above BSS)
```

No DTB, initrd, or kernel is loaded. All registers start at zero except `sp` (set to `ram_base + 0x100000` by the emulator reset, overwritten by `start.S`).

## Configuration

Pass options after `emuko start`, or set via environment variables or `emuko.yml`:

| Option | Env Var | Default | Description |
|--------|---------|---------|-------------|
| `--ram-size` | `RAM_SIZE` | 1 GB | RAM in bytes |
| `--backend` | `EMUKO_BACKEND` | `adaptive` | `adaptive`, `arm64_jit`, `amd64_jit`, `arm64`, `x86_64` |
| `--bootargs` | `BOOTARGS` | serial console | Kernel command line |

## Getting a Kernel

Use `emuko dow` (see Quick Start above) or grab pre-built images from [DQIB (Debian Quick Image Baker)](https://people.debian.org/~gio/dqib/). To download a specific set:

```
emuko dow debian-netboot
```

## License

Apache 2.0. See [LICENSE](LICENSE).
