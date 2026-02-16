#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'USAGE' >&2
Usage: runlinux_interactive.sh [options] [kernel] [initrd] [extra_sim_args...]

Options (all are optional):
  --config FILE
  --kernel FILE
  --initrd FILE
  --debian-netboot-dir DIR
  --dqib-dir DIR
  --load-addr ADDR
  --entry-addr ADDR
  --bootargs STR
  --ram-mb N
  --ram-size BYTES
  --steps N
  --timeout-secs N
  --trace-traps N
  --trace-instr N
  --no-dump N
  --snapshot-load FILE
  --snapshot-save FILE
  --autosnapshot-every N
  --autosnapshot-dir DIR
  --kor-addr HOST:PORT
  --chunk-steps N
  --autostart N
  --startup-wait-secs N
  --reuse-daemon N
  --use-release-bin N
  --uart-flush-every N
  --daemon-foreground N
  --backend adaptive|arm64_jit|amd64_jit|arm64|x86_64
  -h, --help

Precedence for values:
  1) config file (emuko.yml)
  2) command switch
  3) environment variable
USAGE
}

trim_ws() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

normalize_bool() {
  local v lower
  v="$(trim_ws "$1")"
  lower="$(printf '%s' "$v" | tr '[:upper:]' '[:lower:]')"
  case "$lower" in
    1|true|yes|on) printf '1' ;;
    0|false|no|off) printf '0' ;;
    *) printf '%s' "$v" ;;
  esac
}

unquote_yaml() {
  local v="$1"
  if [[ ${#v} -ge 2 && "${v:0:1}" == '"' && "${v: -1}" == '"' ]]; then
    v="${v:1:${#v}-2}"
    v="${v//\\\"/\"}"
  elif [[ ${#v} -ge 2 && "${v:0:1}" == "'" && "${v: -1}" == "'" ]]; then
    v="${v:1:${#v}-2}"
  fi
  printf '%s' "$v"
}

CFG_KERNEL=""
CFG_INITRD=""
CFG_DEBIAN_NETBOOT_DIR=""
CFG_DQIB_DIR=""
CFG_LOAD_ADDR=""
CFG_ENTRY_ADDR=""
CFG_BOOTARGS=""
CFG_RAM_MB=""
CFG_RAM_SIZE=""
CFG_STEPS=""
CFG_TIMEOUT_SECS=""
CFG_TRACE_TRAPS=""
CFG_TRACE_INSTR=""
CFG_NO_DUMP=""
CFG_SNAPSHOT_LOAD=""
CFG_SNAPSHOT_SAVE=""
CFG_AUTOSNAPSHOT_EVERY=""
CFG_AUTOSNAPSHOT_DIR=""
CFG_EMUKO_ADDR=""
CFG_CHUNK_STEPS=""
CFG_AUTOSTART=""
CFG_STARTUP_WAIT_SECS=""
CFG_REUSE_DAEMON=""
CFG_USE_RELEASE_BIN=""
CFG_UART_FLUSH_EVERY=""
CFG_DAEMON_FOREGROUND=""
CFG_BACKEND=""

set_cfg_value() {
  local key="$1"
  local val="$2"
  key="$(printf '%s' "$key" | tr '[:upper:]' '[:lower:]')"
  case "$key" in
    kernel) CFG_KERNEL="$val" ;;
    initrd) CFG_INITRD="$val" ;;
    debian_netboot_dir) CFG_DEBIAN_NETBOOT_DIR="$val" ;;
    dqib_dir) CFG_DQIB_DIR="$val" ;;
    load_addr) CFG_LOAD_ADDR="$val" ;;
    entry_addr) CFG_ENTRY_ADDR="$val" ;;
    bootargs) CFG_BOOTARGS="$val" ;;
    ram_mb) CFG_RAM_MB="$val" ;;
    ram_size) CFG_RAM_SIZE="$val" ;;
    steps) CFG_STEPS="$val" ;;
    timeout_secs) CFG_TIMEOUT_SECS="$val" ;;
    trace_traps) CFG_TRACE_TRAPS="$val" ;;
    trace_instr) CFG_TRACE_INSTR="$val" ;;
    no_dump) CFG_NO_DUMP="$(normalize_bool "$val")" ;;
    snapshot_load) CFG_SNAPSHOT_LOAD="$val" ;;
    snapshot_save) CFG_SNAPSHOT_SAVE="$val" ;;
    autosnapshot_every) CFG_AUTOSNAPSHOT_EVERY="$val" ;;
    autosnapshot_dir) CFG_AUTOSNAPSHOT_DIR="$val" ;;
    emuko_addr|kor_addr) CFG_EMUKO_ADDR="$val" ;;
    chunk_steps) CFG_CHUNK_STEPS="$val" ;;
    autostart) CFG_AUTOSTART="$(normalize_bool "$val")" ;;
    startup_wait_secs) CFG_STARTUP_WAIT_SECS="$val" ;;
    reuse_daemon) CFG_REUSE_DAEMON="$(normalize_bool "$val")" ;;
    use_release_bin) CFG_USE_RELEASE_BIN="$(normalize_bool "$val")" ;;
    uart_flush_every) CFG_UART_FLUSH_EVERY="$val" ;;
    daemon_foreground) CFG_DAEMON_FOREGROUND="$(normalize_bool "$val")" ;;
    backend) CFG_BACKEND="$val" ;;
    *) ;;
  esac
}

load_config_file() {
  local file="$1"
  local raw line key val
  while IFS= read -r raw || [[ -n "$raw" ]]; do
    line="${raw%%#*}"
    line="$(trim_ws "$line")"
    [[ -z "$line" ]] && continue
    if [[ "$line" =~ ^([A-Za-z0-9_]+)[[:space:]]*:[[:space:]]*(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      val="${BASH_REMATCH[2]}"
      val="$(trim_ws "$val")"
      val="$(unquote_yaml "$val")"
      set_cfg_value "$key" "$val"
    fi
  done < "$file"
}

pick_value() {
  local __out="$1"
  local env_name="$2"
  local cli_val="$3"
  local cfg_val="$4"
  local def_val="$5"
  local env_val="${!env_name:-}"
  local val="$def_val"

  if [[ -n "$cfg_val" ]]; then
    val="$cfg_val"
  fi
  if [[ -n "$cli_val" ]]; then
    val="$cli_val"
  fi
  if [[ -n "$env_val" ]]; then
    val="$env_val"
  fi
  printf -v "$__out" '%s' "$val"
}

CLI_CONFIG=""
CLI_KERNEL=""
CLI_INITRD=""
CLI_DEBIAN_NETBOOT_DIR=""
CLI_DQIB_DIR=""
CLI_LOAD_ADDR=""
CLI_ENTRY_ADDR=""
CLI_BOOTARGS=""
CLI_RAM_MB=""
CLI_RAM_SIZE=""
CLI_STEPS=""
CLI_TIMEOUT_SECS=""
CLI_TRACE_TRAPS=""
CLI_TRACE_INSTR=""
CLI_NO_DUMP=""
CLI_SNAPSHOT_LOAD=""
CLI_SNAPSHOT_SAVE=""
CLI_AUTOSNAPSHOT_EVERY=""
CLI_AUTOSNAPSHOT_DIR=""
CLI_EMUKO_ADDR=""
CLI_CHUNK_STEPS=""
CLI_AUTOSTART=""
CLI_STARTUP_WAIT_SECS=""
CLI_REUSE_DAEMON=""
CLI_USE_RELEASE_BIN=""
CLI_UART_FLUSH_EVERY=""
CLI_DAEMON_FOREGROUND=""
CLI_BACKEND=""
POSITIONAL_ARGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --config)
      [[ $# -ge 2 ]] || { echo "Missing value for --config" >&2; exit 1; }
      CLI_CONFIG="$2"
      shift 2
      ;;
    --kernel)
      [[ $# -ge 2 ]] || { echo "Missing value for --kernel" >&2; exit 1; }
      CLI_KERNEL="$2"
      shift 2
      ;;
    --initrd)
      [[ $# -ge 2 ]] || { echo "Missing value for --initrd" >&2; exit 1; }
      CLI_INITRD="$2"
      shift 2
      ;;
    --debian-netboot-dir)
      [[ $# -ge 2 ]] || { echo "Missing value for --debian-netboot-dir" >&2; exit 1; }
      CLI_DEBIAN_NETBOOT_DIR="$2"
      shift 2
      ;;
    --dqib-dir)
      [[ $# -ge 2 ]] || { echo "Missing value for --dqib-dir" >&2; exit 1; }
      CLI_DQIB_DIR="$2"
      shift 2
      ;;
    --load-addr)
      [[ $# -ge 2 ]] || { echo "Missing value for --load-addr" >&2; exit 1; }
      CLI_LOAD_ADDR="$2"
      shift 2
      ;;
    --entry-addr)
      [[ $# -ge 2 ]] || { echo "Missing value for --entry-addr" >&2; exit 1; }
      CLI_ENTRY_ADDR="$2"
      shift 2
      ;;
    --bootargs)
      [[ $# -ge 2 ]] || { echo "Missing value for --bootargs" >&2; exit 1; }
      CLI_BOOTARGS="$2"
      shift 2
      ;;
    --ram-mb)
      [[ $# -ge 2 ]] || { echo "Missing value for --ram-mb" >&2; exit 1; }
      CLI_RAM_MB="$2"
      shift 2
      ;;
    --ram-size)
      [[ $# -ge 2 ]] || { echo "Missing value for --ram-size" >&2; exit 1; }
      CLI_RAM_SIZE="$2"
      shift 2
      ;;
    --steps)
      [[ $# -ge 2 ]] || { echo "Missing value for --steps" >&2; exit 1; }
      CLI_STEPS="$2"
      shift 2
      ;;
    --timeout-secs)
      [[ $# -ge 2 ]] || { echo "Missing value for --timeout-secs" >&2; exit 1; }
      CLI_TIMEOUT_SECS="$2"
      shift 2
      ;;
    --trace-traps)
      [[ $# -ge 2 ]] || { echo "Missing value for --trace-traps" >&2; exit 1; }
      CLI_TRACE_TRAPS="$2"
      shift 2
      ;;
    --trace-instr)
      [[ $# -ge 2 ]] || { echo "Missing value for --trace-instr" >&2; exit 1; }
      CLI_TRACE_INSTR="$2"
      shift 2
      ;;
    --no-dump)
      [[ $# -ge 2 ]] || { echo "Missing value for --no-dump" >&2; exit 1; }
      CLI_NO_DUMP="$(normalize_bool "$2")"
      shift 2
      ;;
    --snapshot-load)
      [[ $# -ge 2 ]] || { echo "Missing value for --snapshot-load" >&2; exit 1; }
      CLI_SNAPSHOT_LOAD="$2"
      shift 2
      ;;
    --snapshot-save)
      [[ $# -ge 2 ]] || { echo "Missing value for --snapshot-save" >&2; exit 1; }
      CLI_SNAPSHOT_SAVE="$2"
      shift 2
      ;;
    --autosnapshot-every)
      [[ $# -ge 2 ]] || { echo "Missing value for --autosnapshot-every" >&2; exit 1; }
      CLI_AUTOSNAPSHOT_EVERY="$2"
      shift 2
      ;;
    --autosnapshot-dir)
      [[ $# -ge 2 ]] || { echo "Missing value for --autosnapshot-dir" >&2; exit 1; }
      CLI_AUTOSNAPSHOT_DIR="$2"
      shift 2
      ;;
    --kor-addr)
      [[ $# -ge 2 ]] || { echo "Missing value for --kor-addr" >&2; exit 1; }
      CLI_EMUKO_ADDR="$2"
      shift 2
      ;;
    --chunk-steps)
      [[ $# -ge 2 ]] || { echo "Missing value for --chunk-steps" >&2; exit 1; }
      CLI_CHUNK_STEPS="$2"
      shift 2
      ;;
    --autostart)
      [[ $# -ge 2 ]] || { echo "Missing value for --autostart" >&2; exit 1; }
      CLI_AUTOSTART="$(normalize_bool "$2")"
      shift 2
      ;;
    --startup-wait-secs)
      [[ $# -ge 2 ]] || { echo "Missing value for --startup-wait-secs" >&2; exit 1; }
      CLI_STARTUP_WAIT_SECS="$2"
      shift 2
      ;;
    --reuse-daemon)
      [[ $# -ge 2 ]] || { echo "Missing value for --reuse-daemon" >&2; exit 1; }
      CLI_REUSE_DAEMON="$(normalize_bool "$2")"
      shift 2
      ;;
    --use-release-bin)
      [[ $# -ge 2 ]] || { echo "Missing value for --use-release-bin" >&2; exit 1; }
      CLI_USE_RELEASE_BIN="$(normalize_bool "$2")"
      shift 2
      ;;
    --uart-flush-every)
      [[ $# -ge 2 ]] || { echo "Missing value for --uart-flush-every" >&2; exit 1; }
      CLI_UART_FLUSH_EVERY="$2"
      shift 2
      ;;
    --daemon-foreground)
      [[ $# -ge 2 ]] || { echo "Missing value for --daemon-foreground" >&2; exit 1; }
      CLI_DAEMON_FOREGROUND="$(normalize_bool "$2")"
      shift 2
      ;;
    --backend)
      [[ $# -ge 2 ]] || { echo "Missing value for --backend" >&2; exit 1; }
      CLI_BACKEND="$2"
      shift 2
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        POSITIONAL_ARGS+=("$1")
        shift
      done
      ;;
    -*)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
    *)
      POSITIONAL_ARGS+=("$1")
      shift
      ;;
  esac
done

DEFAULT_CONFIG_FILE="$ROOT_DIR/emuko.yml"
CONFIG_FILE="$DEFAULT_CONFIG_FILE"
if [[ -n "$CLI_CONFIG" ]]; then
  CONFIG_FILE="$CLI_CONFIG"
fi
if [[ -n "${EMUKO_CONFIG:-}" ]]; then
  CONFIG_FILE="$EMUKO_CONFIG"
fi

if [[ -f "$CONFIG_FILE" ]]; then
  load_config_file "$CONFIG_FILE"
elif [[ -n "$CLI_CONFIG" || -n "${EMUKO_CONFIG:-}" ]]; then
  echo "Missing config file: $CONFIG_FILE" >&2
  exit 1
fi

pick_value DEBIAN_NETBOOT_DIR DEBIAN_NETBOOT_DIR "$CLI_DEBIAN_NETBOOT_DIR" "$CFG_DEBIAN_NETBOOT_DIR" "$ROOT_DIR/artifacts/debian-netboot"
pick_value DQIB_DIR DQIB_DIR "$CLI_DQIB_DIR" "$CFG_DQIB_DIR" "/Users/wkoszek/Downloads/emuko/dqib_riscv64-virt"

DEFAULT_KERNEL="$DQIB_DIR/kernel"
DEFAULT_INITRD="$DQIB_DIR/initrd"
if [[ -f "$DEBIAN_NETBOOT_DIR/linux" ]]; then
  DEFAULT_KERNEL="$DEBIAN_NETBOOT_DIR/linux"
fi
if [[ -f "$DEBIAN_NETBOOT_DIR/initrd.gz" ]]; then
  DEFAULT_INITRD="$DEBIAN_NETBOOT_DIR/initrd.gz"
fi

if [[ -z "$CLI_KERNEL" && ${#POSITIONAL_ARGS[@]} -ge 1 ]]; then
  CLI_KERNEL="${POSITIONAL_ARGS[0]}"
fi
if [[ -z "$CLI_INITRD" && ${#POSITIONAL_ARGS[@]} -ge 2 ]]; then
  CLI_INITRD="${POSITIONAL_ARGS[1]}"
fi

EXTRA_SIM_ARGS=()
if [[ ${#POSITIONAL_ARGS[@]} -ge 3 ]]; then
  EXTRA_SIM_ARGS=("${POSITIONAL_ARGS[@]:2}")
fi

pick_value KERNEL KERNEL "$CLI_KERNEL" "$CFG_KERNEL" "$DEFAULT_KERNEL"
pick_value INITRD INITRD "$CLI_INITRD" "$CFG_INITRD" "$DEFAULT_INITRD"

pick_value LOAD_ADDR LOAD_ADDR "$CLI_LOAD_ADDR" "$CFG_LOAD_ADDR" "0x80200000"
pick_value ENTRY_ADDR ENTRY_ADDR "$CLI_ENTRY_ADDR" "$CFG_ENTRY_ADDR" "0x80200000"
pick_value BOOTARGS BOOTARGS "$CLI_BOOTARGS" "$CFG_BOOTARGS" "console=ttyS0,115200 earlycon=uart8250,mmio,0x10000000 rdinit=/bin/sh"
pick_value RAM_MB RAM_MB "$CLI_RAM_MB" "$CFG_RAM_MB" "1024"
pick_value RAM_SIZE RAM_SIZE "$CLI_RAM_SIZE" "$CFG_RAM_SIZE" ""
pick_value STEPS STEPS "$CLI_STEPS" "$CFG_STEPS" ""
pick_value TIMEOUT_SECS TIMEOUT_SECS "$CLI_TIMEOUT_SECS" "$CFG_TIMEOUT_SECS" "0"
pick_value TRACE_TRAPS TRACE_TRAPS "$CLI_TRACE_TRAPS" "$CFG_TRACE_TRAPS" "0"
pick_value TRACE_INSTR TRACE_INSTR "$CLI_TRACE_INSTR" "$CFG_TRACE_INSTR" "0"
pick_value NO_DUMP NO_DUMP "$CLI_NO_DUMP" "$CFG_NO_DUMP" "1"
pick_value SNAPSHOT_LOAD SNAPSHOT_LOAD "$CLI_SNAPSHOT_LOAD" "$CFG_SNAPSHOT_LOAD" ""
pick_value SNAPSHOT_SAVE SNAPSHOT_SAVE "$CLI_SNAPSHOT_SAVE" "$CFG_SNAPSHOT_SAVE" ""
pick_value AUTOSNAPSHOT_EVERY AUTOSNAPSHOT_EVERY "$CLI_AUTOSNAPSHOT_EVERY" "$CFG_AUTOSNAPSHOT_EVERY" "0"
pick_value AUTOSNAPSHOT_DIR AUTOSNAPSHOT_DIR "$CLI_AUTOSNAPSHOT_DIR" "$CFG_AUTOSNAPSHOT_DIR" "/tmp/emuko"
pick_value EMUKO_ADDR EMUKO_ADDR "$CLI_EMUKO_ADDR" "$CFG_EMUKO_ADDR" "127.0.0.1:7788"
pick_value CHUNK_STEPS CHUNK_STEPS "$CLI_CHUNK_STEPS" "$CFG_CHUNK_STEPS" "4000000"
pick_value AUTOSTART AUTOSTART "$CLI_AUTOSTART" "$CFG_AUTOSTART" "1"
pick_value STARTUP_WAIT_SECS STARTUP_WAIT_SECS "$CLI_STARTUP_WAIT_SECS" "$CFG_STARTUP_WAIT_SECS" "10"
pick_value REUSE_DAEMON REUSE_DAEMON "$CLI_REUSE_DAEMON" "$CFG_REUSE_DAEMON" "0"
pick_value USE_RELEASE_BIN USE_RELEASE_BIN "$CLI_USE_RELEASE_BIN" "$CFG_USE_RELEASE_BIN" "0"
pick_value UART_FLUSH_EVERY UART_FLUSH_EVERY "$CLI_UART_FLUSH_EVERY" "$CFG_UART_FLUSH_EVERY" "1024"
pick_value DAEMON_FOREGROUND DAEMON_FOREGROUND "$CLI_DAEMON_FOREGROUND" "$CFG_DAEMON_FOREGROUND" "1"
pick_value BACKEND BACKEND "$CLI_BACKEND" "$CFG_BACKEND" "adaptive"
if [[ -n "${EMUKO_BACKEND:-}" ]]; then
  BACKEND="$EMUKO_BACKEND"
fi
BACKEND="$(printf '%s' "$BACKEND" | tr '[:upper:]' '[:lower:]')"
if [[ "$BOOTARGS" == *"rdinit=/bin/sh"* ]]; then
  echo "Note: bootargs use rdinit=/bin/sh, so init scripts are skipped." >&2
  echo "      In guest, mount pseudo-fs before tools like reopen-console:" >&2
  echo "      mount -t proc proc /proc; mount -t sysfs sysfs /sys; mount -t devtmpfs devtmpfs /dev" >&2
fi

if [[ -z "$RAM_SIZE" ]]; then
  RAM_SIZE="$((RAM_MB * 1024 * 1024))"
fi

HOST_ARCH_RAW="$(uname -m 2>/dev/null || echo unknown)"
case "$HOST_ARCH_RAW" in
  aarch64|arm64)
    HOST_ARCH="arm64"
    ;;
  x86_64|amd64)
    HOST_ARCH="x86_64"
    ;;
  *)
    HOST_ARCH="unknown"
    ;;
esac

BACKEND_EFFECTIVE="$BACKEND"
BACKEND_JIT_DEFAULT="0"
case "$BACKEND" in
  adaptive)
    if [[ "$HOST_ARCH" == "arm64" ]]; then
      BACKEND_EFFECTIVE="arm64_jit"
      BACKEND_JIT_DEFAULT="1"
    elif [[ "$HOST_ARCH" == "x86_64" ]]; then
      BACKEND_EFFECTIVE="amd64_jit"
      BACKEND_JIT_DEFAULT="1"
    else
      BACKEND_EFFECTIVE="x86_64"
      BACKEND_JIT_DEFAULT="0"
      echo "Warning: unknown host arch '$HOST_ARCH_RAW'; adaptive backend fell back to interpreter." >&2
    fi
    ;;
  arm64_jit)
    if [[ "$HOST_ARCH" != "arm64" ]]; then
      echo "Warning: backend arm64_jit requested on host '$HOST_ARCH_RAW'; falling back to interpreter." >&2
      BACKEND_EFFECTIVE="arm64"
      BACKEND_JIT_DEFAULT="0"
    else
      BACKEND_JIT_DEFAULT="1"
    fi
    ;;
  amd64_jit)
    if [[ "$HOST_ARCH" != "x86_64" ]]; then
      echo "Warning: backend amd64_jit requested on host '$HOST_ARCH_RAW'; falling back to interpreter." >&2
      BACKEND_EFFECTIVE="x86_64"
      BACKEND_JIT_DEFAULT="0"
    else
      BACKEND_JIT_DEFAULT="1"
    fi
    ;;
  arm64|x86_64)
    BACKEND_JIT_DEFAULT="0"
    ;;
  *)
    echo "Warning: unknown backend '$BACKEND'; using adaptive." >&2
    if [[ "$HOST_ARCH" == "arm64" ]]; then
      BACKEND_EFFECTIVE="arm64_jit"
      BACKEND_JIT_DEFAULT="1"
    elif [[ "$HOST_ARCH" == "x86_64" ]]; then
      BACKEND_EFFECTIVE="amd64_jit"
      BACKEND_JIT_DEFAULT="1"
    else
      BACKEND_EFFECTIVE="x86_64"
      BACKEND_JIT_DEFAULT="0"
    fi
    ;;
esac

EMUKO_JIT_NATIVE_EFFECTIVE="$BACKEND_JIT_DEFAULT"
if [[ -n "${EMUKO_JIT_NATIVE:-}" ]]; then
  EMUKO_JIT_NATIVE_EFFECTIVE="$EMUKO_JIT_NATIVE"
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
echo "Backend: $BACKEND_EFFECTIVE (host=$HOST_ARCH_RAW, EMUKO_JIT_NATIVE=$EMUKO_JIT_NATIVE_EFFECTIVE)" >&2
if [[ -f "$CONFIG_FILE" ]]; then
  echo "Config: $CONFIG_FILE" >&2
fi

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

if [[ ! -t 0 && "$DAEMON_FOREGROUND" == "1" ]]; then
  echo "Warning: forcing DAEMON_FOREGROUND=0 because stdin is not a TTY." >&2
  DAEMON_FOREGROUND=0
fi

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

DAEMON_ARGS=(--addr "$EMUKO_ADDR" --snapshot-dir "$AUTOSNAPSHOT_DIR" --chunk-steps "$CHUNK_STEPS")
if [[ -n "$SNAPSHOT_LOAD" ]]; then
  DAEMON_ARGS+=(--snapshot "$SNAPSHOT_LOAD")
else
  DAEMON_ARGS+=("$KERNEL" "$INITRD" --ram-size "$RAM_SIZE" --bootargs "$BOOTARGS")
fi

api_ready() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS "http://$EMUKO_ADDR/v1/api/dump" >/dev/null 2>&1
  else
    EMUKO_ADDR="$EMUKO_ADDR" target/release/emu dump >/dev/null 2>&1
  fi
}

daemon_pid=""
existing_daemon=0
if api_ready; then
  if [[ "$REUSE_DAEMON" == "1" ]]; then
    existing_daemon=1
    echo "Reusing existing daemon at $EMUKO_ADDR" >&2
  else
    echo "Error: daemon already listening at $EMUKO_ADDR." >&2
    echo "Use a different EMUKO_ADDR, stop the old daemon, or set REUSE_DAEMON=1." >&2
    exit 1
  fi
fi

echo "emuko API: http://$EMUKO_ADDR/v1/api/{start,stop,dump,step,continue,set,uart}" >&2
echo "Chunk steps: $CHUNK_STEPS" >&2

# Foreground mode keeps daemon attached to this TTY, so host stdin -> UART works.
if [[ "$existing_daemon" != "1" && "$DAEMON_FOREGROUND" == "1" ]]; then
  if [[ "$AUTOSTART" == "1" ]]; then
    DAEMON_ARGS+=(--autostart)
    echo "Execution started (daemon foreground mode)." >&2
  else
    echo "Execution is paused. Start with: EMUKO_ADDR=$EMUKO_ADDR emu con" >&2
  fi
  if [[ "$USE_RELEASE_BIN" == "1" && -x target/release/emukod ]]; then
    echo "Launch mode: release binary foreground (USE_RELEASE_BIN=1)" >&2
    exec env UART_FLUSH_EVERY="$UART_FLUSH_EVERY" EMUKO_JIT_NATIVE="$EMUKO_JIT_NATIVE_EFFECTIVE" target/release/emukod "${DAEMON_ARGS[@]}"
  else
    echo "Launch mode: cargo run --release --bin emukod foreground" >&2
    exec env UART_FLUSH_EVERY="$UART_FLUSH_EVERY" EMUKO_JIT_NATIVE="$EMUKO_JIT_NATIVE_EFFECTIVE" cargo run --release --bin emukod -- "${DAEMON_ARGS[@]}"
  fi
fi

if [[ "$existing_daemon" != "1" ]]; then
  if [[ "$USE_RELEASE_BIN" == "1" && -x target/release/emukod ]]; then
    echo "Launch mode: release binary (USE_RELEASE_BIN=1)" >&2
    UART_FLUSH_EVERY="$UART_FLUSH_EVERY" EMUKO_JIT_NATIVE="$EMUKO_JIT_NATIVE_EFFECTIVE" target/release/emukod "${DAEMON_ARGS[@]}" &
  else
    echo "Launch mode: cargo run --release --bin emukod" >&2
    UART_FLUSH_EVERY="$UART_FLUSH_EVERY" EMUKO_JIT_NATIVE="$EMUKO_JIT_NATIVE_EFFECTIVE" cargo run --release --bin emukod -- "${DAEMON_ARGS[@]}" &
  fi
  daemon_pid=$!
fi

cleanup() {
  if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" >/dev/null 2>&1; then
    kill "$daemon_pid" >/dev/null 2>&1 || true
    wait "$daemon_pid" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

startup_deadline=$((SECONDS + STARTUP_WAIT_SECS))
ready=0
while [[ "$SECONDS" -lt "$startup_deadline" ]]; do
  if [[ -n "$daemon_pid" ]] && ! kill -0 "$daemon_pid" >/dev/null 2>&1; then
    wait "$daemon_pid" || true
    echo "Daemon exited before API became ready." >&2
    exit 1
  fi
  if api_ready; then
    ready=1
    break
  fi
  sleep 0.05
done
if [[ "$ready" != "1" ]]; then
  echo "Failed to reach daemon HTTP API at $EMUKO_ADDR" >&2
  exit 1
fi

if [[ "$AUTOSTART" == "1" ]]; then
  if command -v curl >/dev/null 2>&1; then
    curl -fsS "http://$EMUKO_ADDR/v1/api/continue" >/dev/null
  else
    EMUKO_ADDR="$EMUKO_ADDR" target/release/emu con >/dev/null
  fi
  echo "Execution started. Use 'emu stop' to pause and 'emu dump' to inspect state." >&2
else
  echo "Execution is paused. Start with: EMUKO_ADDR=$EMUKO_ADDR emu con" >&2
fi

if [[ -n "$daemon_pid" ]]; then
  wait "$daemon_pid"
else
  echo "Reused existing daemon at $EMUKO_ADDR; leaving script now." >&2
  if [[ "$DAEMON_FOREGROUND" == "1" ]]; then
    echo "Note: foreground stdin bridging is unavailable when reusing an existing daemon." >&2
  fi
fi
