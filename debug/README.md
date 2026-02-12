# KoRISCV Debug Scripts

These scripts are for repeatable `kor`/`koriscvd` probing.

## Prerequisites

1. Build binaries:
   - `cargo build --release`
2. Ensure snapshot exists (default used by scripts):
   - `/tmp/korisc5-rd/snap-00000000002600400005.kriscv.zst`

## Scripts

- `debug/probe_lsla.sh`
  - Starts a daemon from snapshot.
  - Runs to shell prompt.
  - Injects UART command (`ls -la\n` by default).
  - Captures UART output and state snapshots into `/tmp/korisc5-debug/`.

- `debug/poll_state.sh`
  - Polls `kor dump` repeatedly.
  - Useful for seeing a stuck PC/instruction loop in real time.

- `debug/proba_all_basic.sh`
  - Fast, fixed command batch (no long prompt wait):
    - `ls`
    - `ls -la`
    - `time uname -a`
    - `uname -a`
    - `echo sample`
    - `echo sample > file`
  - Captures UART and state logs into `/tmp/korisc5-debug/`.

## Typical usage

```bash
debug/probe_lsla.sh
```

```bash
debug/proba_all_basic.sh
```

```bash
KOR_ADDR=127.0.0.1:7788 debug/poll_state.sh
```

## Useful env vars

- `SNAPSHOT`
- `KOR_ADDR`
- `CHUNK_STEPS`
- `BOOT_LOOPS`
- `POST_LOOPS`
- `STEP_SLEEP`
- `CMD_ESC` (default: `ls -la\\n`)
- `KEEP_DAEMON=1` (do not stop daemon at script exit)
