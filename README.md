# emuko

A RISC-V emulator in Rust. It boots Linux.

[emuko.dev](https://emuko.dev)

---

The machine implements RV64IMAFDC with M/S/U privilege levels and Sv39 virtual memory.
It runs a JIT on ARM64 and x86\_64 hosts, falling back to an interpreter when needed.
The peripherals are UART 16550, CLINT, PLIC, and SBI 1.0. There is one external dependency: `zstd`.

It is not the fastest emulator. In interpreter mode it runs about three times slower than QEMU.
In JIT mode, about twenty-nine times slower. Code block chaining is not yet implemented;
that will help. We say this plainly because you should know what you are getting.

What it does well: it is simple to operate, it exposes an HTTP API for machine control,
it can execute a bare-metal ELF without a kernel, and it can save and restore the full
machine state. These are useful things for systems work and for testing.

---

## Build

```
cargo build --release
```

The binary is `target/release/emuko`. Make an alias.

```
alias emuko=target/release/emuko
```

---

## Quick Start

### Get a kernel

```
emuko dow
```

Downloads a Debian RISC-V netboot kernel and initrd to `~/.emuko/`.
SHA256 is verified. No kernel of your own is required.

### Boot Linux

```
emuko start
```

The emulator runs as a daemon. You are attached to its console.
You will see the kernel boot. You will get a shell.

| Key | Effect |
|-----|--------|
| Ctrl+] | Detach (daemon continues) |
| Ctrl+C | Interrupt in guest |
| Ctrl+D | EOF in guest |

### Control a running machine

```
emuko start            # reattach console
emuko dump             # print CPU state
emuko stop             # pause execution
emuko con              # continue
emuko step 1000        # single-step N instructions
emuko snap             # take a snapshot
emuko kill             # shut down
```

The daemon listens on `http://127.0.0.1:7788/v1/api/` and accepts WebSocket console
connections at `ws://127.0.0.1:7788/v1/ws/uart`. Both are usable from scripts.

---

## Bare-Metal ELF Execution

Sometimes you do not want an operating system. You want the machine,
a binary, and nothing else between them.

```
emuko run ./my_program.elf
```

The daemon resets the machine, loads the ELF segments at their physical addresses,
and begins execution. Output arrives over the UART console. The daemon must already
be running.

To write to the console from bare metal: store a byte at `0x1000_0000`.

### Examples

The `examples/` directory contains programs that run this way.

| Example | What it does |
|---------|-------------|
| [`bare_printf`](examples/bare_printf/) | Prints a message every 10 million iterations. No libc. Direct UART write. |

A RISC-V cross-compiler is required to build them.
On macOS: `brew install riscv64-elf-gcc`.
On Linux: `apt install gcc-riscv64-linux-gnu`.

```
emuko start
cd examples/bare_printf
make run
```

---

## Snapshots

The machine state — registers, memory, everything — can be saved and restored.

```
emuko snap                  # snapshot now
emuko snap 5000000          # auto-snapshot every 5M steps
emuko snap stop             # stop auto-snapshots
emuko ls                    # list snapshots
emuko restore <snapshot>    # restore
```

---

## Memory Map

The virtual machine uses a fixed MMIO layout compatible with the QEMU RISC-V `virt` platform.

| Region | Base | Size | Notes |
|--------|------|------|-------|
| CLINT  | `0x0200_0000` | 64 KiB | Timer and software IRQ |
| PLIC   | `0x0C00_0000` | 4 MiB  | 32 interrupt sources |
| UART   | `0x1000_0000` | 256 B  | NS16550A, IRQ 10 |
| RAM    | `0x8000_0000` | 1 GiB  | Configurable |

### RAM layout at Linux boot

With default settings (`load_addr=0x80200000`, 1 GiB RAM):

```
0x8000_0000  ── RAM base
                (gap — usable by bare-metal programs)
0x8020_0000  ── Kernel image
                │  .text / .rodata / .data / .bss
                └─ kernel end
                (free)
             ── initrd
             ── DTB
             ── EFI region    (128 KiB, PE/UEFI kernels only)
0xBFFF_FFFF  ── RAM end
```

DTB, initrd, and EFI are placed downward from the top of RAM. The emulator checks
for overlap with the kernel at boot and stops with a clear error if RAM is too small.

### RAM layout for bare-metal ELF

ELF `PT_LOAD` segments are placed at their `p_vaddr` addresses.
`bare_printf` links at `0x8000_0000`:

```
0x8000_0000  ── .text
             ── .rodata
             ── .data
             ── .bss   (zeroed by start.S)
             ── stack  (16 KiB above BSS)
```

No kernel. No initrd. No DTB. Registers start at zero except `sp`,
which the emulator sets to `ram_base + 0x100000` before `start.S` takes over.

---

## Configuration

Options may be passed on the command line, set as environment variables, or placed in `emuko.yml`.

| Option | Env Var | Default | Notes |
|--------|---------|---------|-------|
| `--ram-size` | `RAM_SIZE` | 1 GB | RAM in bytes |
| `--backend` | `EMUKO_BACKEND` | `adaptive` | `adaptive`, `arm64_jit`, `amd64_jit`, `arm64`, `x86_64` |
| `--bootargs` | `BOOTARGS` | serial console | Kernel command line |

---

## Comparison

Direct comparison with commonly-used RISC-V emulators.
`✅` = supported and documented. `—` = not built in.

| Feature | emuko | QEMU | Spike | Renode |
|---------|-------|------|-------|--------|
| JIT / dynamic translation | ✅ | ✅ | — | — |
| Snapshot save and restore | ✅ | ✅ | — | ✅ |
| Periodic auto-snapshot | ✅ | — | — | ✅ |
| HTTP API for machine control | ✅ | — | — | — |
| WebSocket UART console | ✅ | — | — | — |
| Scriptable UART host bridge | ✅ | — | — | ✅ |
| Bare-metal ELF upload (no OS) | ✅ | — | — | — |
| One-command kernel download + SHA256 | ✅ | — | — | — |
| JIT-vs-interpreter differential checker | ✅ | — | — | — |
| GDB debugging | — | ✅ | ✅ | ✅ |
| Large device ecosystem (PCIe, virtio) | — | ✅ | — | — |
| Multi-node simulation | — | — | — | ✅ |
| Broad ISA coverage (RVV, crypto, etc.) | — | — | ✅ | — |

Sources: [QEMU virt](https://www.qemu.org/docs/master/system/riscv/virt.html) ·
[Spike](https://github.com/riscv-software-src/riscv-isa-sim) ·
[Renode](https://github.com/renode/renode)

---

## License

Apache 2.0. See [LICENSE](LICENSE).
