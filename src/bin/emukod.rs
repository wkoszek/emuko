#![allow(dead_code)]

#[path = "../bus.rs"]
mod bus;
#[path = "../clint.rs"]
mod clint;
#[path = "../csr.rs"]
mod csr;
#[path = "../dev.rs"]
mod dev;
#[path = "../disas.rs"]
mod disas;
#[path = "../efi.rs"]
mod efi;
#[path = "../fdt.rs"]
mod fdt;
#[path = "../hart.rs"]
mod hart;
#[path = "../isa.rs"]
mod isa;
#[path = "../pe.rs"]
mod pe;
#[path = "../plic.rs"]
mod plic;
#[path = "../sbi.rs"]
mod sbi;
#[path = "../snapshot.rs"]
mod snapshot;
#[path = "../system.rs"]
mod system;
#[path = "../trap.rs"]
mod trap;

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use bus::Bus;
use system::{System, DEFAULT_RAM_BASE, DEFAULT_RAM_SIZE};
use trap::Trap;

const NAME: &str = "emuko";

// ---------------------------------------------------------------------------
// Minimal WebSocket (RFC 6455) — SHA-1, base64, frame encode/decode
// ---------------------------------------------------------------------------

fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h0: u32 = 0x67452301;
    let mut h1: u32 = 0xEFCDAB89;
    let mut h2: u32 = 0x98BADCFE;
    let mut h3: u32 = 0x10325476;
    let mut h4: u32 = 0xC3D2E1F0;
    let bit_len = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h0, h1, h2, h3, h4);
        for i in 0..80 {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1u32),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDCu32),
                _ => (b ^ c ^ d, 0xCA62C1D6u32),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(w[i]);
            e = d; d = c; c = b.rotate_left(30); b = a; a = temp;
        }
        h0 = h0.wrapping_add(a); h1 = h1.wrapping_add(b); h2 = h2.wrapping_add(c);
        h3 = h3.wrapping_add(d); h4 = h4.wrapping_add(e);
    }
    let mut out = [0u8; 20];
    out[0..4].copy_from_slice(&h0.to_be_bytes());
    out[4..8].copy_from_slice(&h1.to_be_bytes());
    out[8..12].copy_from_slice(&h2.to_be_bytes());
    out[12..16].copy_from_slice(&h3.to_be_bytes());
    out[16..20].copy_from_slice(&h4.to_be_bytes());
    out
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 { out.push(T[((n >> 6) & 63) as usize] as char); } else { out.push('='); }
        if chunk.len() > 2 { out.push(T[(n & 63) as usize] as char); } else { out.push('='); }
    }
    out
}

fn ws_accept_key(client_key: &str) -> String {
    let mut input = client_key.trim().to_string();
    input.push_str("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    base64_encode(&sha1(input.as_bytes()))
}

fn ws_encode_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(2 + 8 + payload.len());
    frame.push(0x80 | opcode); // FIN + opcode
    if payload.len() < 126 {
        frame.push(payload.len() as u8);
    } else if payload.len() <= 65535 {
        frame.push(126);
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    } else {
        frame.push(127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }
    frame.extend_from_slice(payload);
    frame
}

/// Returns (opcode, payload) or None on incomplete/error.
fn ws_decode_frame(buf: &[u8]) -> Option<(u8, Vec<u8>, usize)> {
    if buf.len() < 2 { return None; }
    let opcode = buf[0] & 0x0F;
    let masked = (buf[1] & 0x80) != 0;
    let len1 = (buf[1] & 0x7F) as usize;
    let (payload_len, mut offset) = if len1 < 126 {
        (len1, 2)
    } else if len1 == 126 {
        if buf.len() < 4 { return None; }
        (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)
    } else {
        if buf.len() < 10 { return None; }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&buf[2..10]);
        (u64::from_be_bytes(arr) as usize, 10)
    };
    let mask_key = if masked {
        if buf.len() < offset + 4 { return None; }
        let k = [buf[offset], buf[offset + 1], buf[offset + 2], buf[offset + 3]];
        offset += 4;
        Some(k)
    } else {
        None
    };
    if buf.len() < offset + payload_len { return None; }
    let mut payload = buf[offset..offset + payload_len].to_vec();
    if let Some(k) = mask_key {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= k[i % 4];
        }
    }
    Some((opcode, payload, offset + payload_len))
}

#[derive(Clone, Debug)]
struct DaemonOpts {
    snapshot: Option<String>,
    kernel: Option<String>,
    initrd: Option<String>,
    ram_size: u64,
    bootargs: String,
    addr: String,
    snapshot_dir: String,
    chunk_steps: u64,
    autostart: bool,
    backend: String,
    host_arch: String,
    jit_native: bool,
    config_path: Option<String>,
}

#[derive(Default, Clone, Debug)]
struct DaemonConfigFile {
    snapshot: Option<String>,
    kernel: Option<String>,
    initrd: Option<String>,
    debian_netboot_dir: Option<String>,
    dqib_dir: Option<String>,
    ram_size: Option<u64>,
    bootargs: Option<String>,
    addr: Option<String>,
    snapshot_dir: Option<String>,
    chunk_steps: Option<u64>,
    autostart: Option<bool>,
    backend: Option<String>,
}

#[derive(Default, Clone, Debug)]
struct CliOverrides {
    config: Option<String>,
    snapshot: Option<String>,
    kernel: Option<String>,
    initrd: Option<String>,
    ram_size: Option<u64>,
    bootargs: Option<String>,
    addr: Option<String>,
    snapshot_dir: Option<String>,
    chunk_steps: Option<u64>,
    autostart: Option<bool>,
    backend: Option<String>,
}

struct DaemonState {
    system: System,
    running: bool,
    shutdown_requested: bool,
    boot_snapshot: String,
    snapshot_dir: String,
    chunk_steps: u64,
    last_error: Option<String>,
    autosnapshot_every: u64,
    autosnapshot_last: u64,
}

enum RegTarget {
    Pc,
    X(usize),
}

fn print_usage_and_exit() -> ! {
    eprintln!(
        "Usage: emukod [--config FILE] [--snapshot FILE] [--kernel FILE] [--initrd FILE] [<kernel> <initrd>] [--ram-size BYTES] [--bootargs STR] [--addr HOST:PORT] [--snapshot-dir DIR] [--chunk-steps N] [--autostart] [--backend adaptive|arm64_jit|amd64_jit|arm64|x86_64]\n\
Precedence: config file < command switch < environment variable"
    );
    std::process::exit(1);
}

fn parse_u64(arg: &str) -> Option<u64> {
    if let Some(hex) = arg.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        arg.parse::<u64>().ok()
    }
}

fn parse_bool_text(arg: &str) -> Option<bool> {
    match arg.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn clean_opt(v: Option<String>) -> Option<String> {
    v.and_then(|s| {
        let t = s.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    })
}

fn unquote_yaml(v: &str) -> String {
    let s = v.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].replace("\\\"", "\"")
    } else if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn parse_emuko_yaml(path: &Path) -> Result<DaemonConfigFile, String> {
    let content = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut cfg = DaemonConfigFile::default();
    for raw in content.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let Some((k, v)) = line.split_once(':') else {
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = unquote_yaml(v);
        match key.as_str() {
            "snapshot" | "snapshot_load" => cfg.snapshot = clean_opt(Some(val)),
            "kernel" => cfg.kernel = clean_opt(Some(val)),
            "initrd" => cfg.initrd = clean_opt(Some(val)),
            "debian_netboot_dir" => cfg.debian_netboot_dir = clean_opt(Some(val)),
            "dqib_dir" => cfg.dqib_dir = clean_opt(Some(val)),
            "ram_size" => cfg.ram_size = parse_u64(&val),
            "bootargs" => cfg.bootargs = clean_opt(Some(val)),
            "emuko_addr" | "kor_addr" | "addr" => cfg.addr = clean_opt(Some(val)),
            "autosnapshot_dir" | "snapshot_dir" => cfg.snapshot_dir = clean_opt(Some(val)),
            "chunk_steps" => cfg.chunk_steps = parse_u64(&val),
            "autostart" => cfg.autostart = parse_bool_text(&val),
            "backend" => cfg.backend = clean_opt(Some(val)),
            _ => {}
        }
    }
    Ok(cfg)
}

fn resolve_backend(requested: &str, host_arch: &str) -> (String, bool) {
    match requested {
        "adaptive" => match host_arch {
            "aarch64" => ("arm64_jit".to_string(), true),
            "x86_64" => ("amd64_jit".to_string(), true),
            _ => ("x86_64".to_string(), false),
        },
        "arm64_jit" => {
            if host_arch == "aarch64" {
                ("arm64_jit".to_string(), true)
            } else {
                ("arm64".to_string(), false)
            }
        }
        "amd64_jit" => {
            if host_arch == "x86_64" {
                ("amd64_jit".to_string(), true)
            } else {
                ("x86_64".to_string(), false)
            }
        }
        "arm64" => ("arm64".to_string(), false),
        "x86_64" => ("x86_64".to_string(), false),
        _ => resolve_backend("adaptive", host_arch),
    }
}

fn parse_opts() -> DaemonOpts {
    let mut args = env::args().skip(1);
    let mut cli = CliOverrides::default();
    let mut positionals = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print_usage_and_exit();
            }
            "--config" => {
                cli.config = args.next();
                if cli.config.is_none() {
                    print_usage_and_exit();
                }
            }
            "--snapshot" => {
                cli.snapshot = args.next();
                if cli.snapshot.is_none() {
                    print_usage_and_exit();
                }
            }
            "--kernel" => {
                cli.kernel = args.next();
                if cli.kernel.is_none() {
                    print_usage_and_exit();
                }
            }
            "--initrd" => {
                cli.initrd = args.next();
                if cli.initrd.is_none() {
                    print_usage_and_exit();
                }
            }
            "--ram-size" => {
                let Some(v) = args.next() else {
                    print_usage_and_exit();
                };
                cli.ram_size = Some(parse_u64(&v).unwrap_or_else(|| {
                    eprintln!("Invalid --ram-size value: {v}");
                    std::process::exit(1);
                }));
            }
            "--bootargs" => {
                cli.bootargs = Some(args.next().unwrap_or_else(|| {
                    eprintln!("Missing --bootargs value");
                    std::process::exit(1);
                }));
            }
            "--addr" => {
                cli.addr = Some(args.next().unwrap_or_else(|| {
                    eprintln!("Missing --addr value");
                    std::process::exit(1);
                }));
            }
            "--snapshot-dir" => {
                cli.snapshot_dir = Some(args.next().unwrap_or_else(|| {
                    eprintln!("Missing --snapshot-dir value");
                    std::process::exit(1);
                }));
            }
            "--chunk-steps" => {
                let Some(v) = args.next() else {
                    print_usage_and_exit();
                };
                cli.chunk_steps = Some(parse_u64(&v).unwrap_or_else(|| {
                    eprintln!("Invalid --chunk-steps value: {v}");
                    std::process::exit(1);
                }));
            }
            "--autostart" => {
                cli.autostart = Some(true);
            }
            "--backend" => {
                cli.backend = args.next();
                if cli.backend.is_none() {
                    print_usage_and_exit();
                }
            }
            _ if arg.starts_with("--") => {
                eprintln!("Unknown argument: {arg}");
                print_usage_and_exit();
            }
            _ => positionals.push(arg),
        }
    }

    if cli.kernel.is_none() && !positionals.is_empty() {
        cli.kernel = Some(positionals[0].clone());
    }
    if cli.initrd.is_none() && positionals.len() > 1 {
        cli.initrd = Some(positionals[1].clone());
    }

    let mut cfg_path = "emuko.yml".to_string();
    if let Some(v) = clean_opt(cli.config.clone()) {
        cfg_path = v;
    }
    if let Ok(v) = env::var("EMUKO_CONFIG") {
        if !v.trim().is_empty() {
            cfg_path = v;
        }
    }
    let cfg_requested = cli.config.is_some() || env::var("EMUKO_CONFIG").is_ok();
    let cfg = if Path::new(&cfg_path).exists() {
        match parse_emuko_yaml(Path::new(&cfg_path)) {
            Ok(v) => Some(v),
            Err(e) => {
                eprintln!("Failed to parse config {}: {}", cfg_path, e);
                std::process::exit(1);
            }
        }
    } else {
        if cfg_requested {
            eprintln!("Missing config file: {}", cfg_path);
            print_usage_and_exit();
        }
        None
    };

    let cfg_kernel = cfg.as_ref().and_then(|c| c.kernel.clone());
    let cfg_initrd = cfg.as_ref().and_then(|c| c.initrd.clone());
    let cfg_snapshot = cfg.as_ref().and_then(|c| c.snapshot.clone());
    let cfg_bootargs = cfg.as_ref().and_then(|c| c.bootargs.clone());
    let cfg_addr = cfg.as_ref().and_then(|c| c.addr.clone());
    let cfg_snapshot_dir = cfg.as_ref().and_then(|c| c.snapshot_dir.clone());
    let cfg_backend = cfg.as_ref().and_then(|c| c.backend.clone());
    let cfg_ram_size = cfg.as_ref().and_then(|c| c.ram_size);
    let cfg_chunk_steps = cfg.as_ref().and_then(|c| c.chunk_steps);
    let cfg_autostart = cfg.as_ref().and_then(|c| c.autostart);

    let debian_netboot_dir = env::var("DEBIAN_NETBOOT_DIR")
        .ok()
        .or_else(|| cfg.as_ref().and_then(|c| c.debian_netboot_dir.clone()))
        .unwrap_or_else(|| {
            let home = env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
            format!("{}/.emuko/riscv64/debian-netboot", home)
        });
    let dqib_dir = env::var("DQIB_DIR")
        .ok()
        .or_else(|| cfg.as_ref().and_then(|c| c.dqib_dir.clone()))
        .unwrap_or_else(|| "/Users/wkoszek/Downloads/emuko/dqib_riscv64-virt".to_string());

    let mut default_kernel = format!("{}/kernel", dqib_dir);
    let mut default_initrd = format!("{}/initrd", dqib_dir);
    let debian_kernel = format!("{}/linux", debian_netboot_dir);
    let debian_initrd = format!("{}/initrd.gz", debian_netboot_dir);
    if Path::new(&debian_kernel).exists() {
        default_kernel = debian_kernel;
    }
    if Path::new(&debian_initrd).exists() {
        default_initrd = debian_initrd;
    }

    let snapshot = clean_opt(env::var("SNAPSHOT_LOAD").ok())
        .or_else(|| clean_opt(env::var("KOR_SNAPSHOT").ok()))
        .or_else(|| clean_opt(cli.snapshot))
        .or_else(|| clean_opt(cfg_snapshot));
    let kernel = clean_opt(env::var("KERNEL").ok())
        .or_else(|| clean_opt(cli.kernel))
        .or_else(|| clean_opt(cfg_kernel))
        .or_else(|| Some(default_kernel));
    let initrd = clean_opt(env::var("INITRD").ok())
        .or_else(|| clean_opt(cli.initrd))
        .or_else(|| clean_opt(cfg_initrd))
        .or_else(|| Some(default_initrd));

    let ram_size = env::var("RAM_SIZE")
        .ok()
        .and_then(|v| parse_u64(&v))
        .or(cli.ram_size)
        .or(cfg_ram_size)
        .unwrap_or(1024 * 1024 * 1024u64);
    let bootargs = clean_opt(env::var("BOOTARGS").ok())
        .or_else(|| clean_opt(cli.bootargs))
        .or_else(|| clean_opt(cfg_bootargs))
        .unwrap_or_else(|| {
            "console=ttyS0,115200 earlycon=uart8250,mmio,0x10000000 rdinit=/bin/sh".to_string()
        });
    let addr = clean_opt(env::var("EMUKO_ADDR").ok())
        .or_else(|| clean_opt(cli.addr))
        .or_else(|| clean_opt(cfg_addr))
        .unwrap_or_else(|| "127.0.0.1:7788".to_string());
    let snapshot_dir = clean_opt(env::var("AUTOSNAPSHOT_DIR").ok())
        .or_else(|| clean_opt(cli.snapshot_dir))
        .or_else(|| clean_opt(cfg_snapshot_dir))
        .unwrap_or_else(|| "/tmp/emuko".to_string());
    let chunk_steps = env::var("CHUNK_STEPS")
        .ok()
        .and_then(|v| parse_u64(&v))
        .or(cli.chunk_steps)
        .or(cfg_chunk_steps)
        .unwrap_or(4_000_000u64);
    let autostart = env::var("AUTOSTART")
        .ok()
        .and_then(|v| parse_bool_text(&v))
        .or(cli.autostart)
        .or(cfg_autostart)
        .unwrap_or(false);

    let backend_requested = clean_opt(env::var("KOR_BACKEND").ok())
        .or_else(|| clean_opt(env::var("BACKEND").ok()))
        .or_else(|| clean_opt(cli.backend))
        .or_else(|| clean_opt(cfg_backend))
        .unwrap_or_else(|| "adaptive".to_string())
        .to_ascii_lowercase();
    let host_arch = std::env::consts::ARCH.to_string();
    let (backend, mut jit_native) = resolve_backend(&backend_requested, &host_arch);
    if backend_requested != backend && backend_requested != "adaptive" {
        eprintln!(
            "Warning: backend '{}' not compatible with host '{}'; using '{}'",
            backend_requested, host_arch, backend
        );
    }
    if let Ok(v) = env::var("KOR_JIT_NATIVE") {
        if let Some(b) = parse_bool_text(&v) {
            jit_native = b;
        }
    }

    if snapshot.is_none() {
        if kernel.is_none() || initrd.is_none() {
            eprintln!("Need either --snapshot FILE or kernel/initrd (from args or emuko.yml)");
            print_usage_and_exit();
        }
        if let Some(k) = &kernel {
            if !Path::new(k).exists() {
                eprintln!("Missing kernel: {}", k);
                std::process::exit(1);
            }
        }
        if let Some(i) = &initrd {
            if !Path::new(i).exists() {
                eprintln!("Missing initrd: {}", i);
                std::process::exit(1);
            }
        }
    }

    DaemonOpts {
        snapshot,
        kernel,
        initrd,
        ram_size,
        bootargs,
        addr,
        snapshot_dir,
        chunk_steps,
        autostart,
        backend,
        host_arch,
        jit_native,
        config_path: if Path::new(&cfg_path).exists() {
            Some(cfg_path)
        } else {
            None
        },
    }
}

fn current_sim_bin() -> Option<PathBuf> {
    if let Ok(v) = env::var("EMUKO_SIM_BIN") {
        return Some(PathBuf::from(v));
    }
    env::current_exe().ok()
}

fn materialize_boot_snapshot(opts: &DaemonOpts) -> Result<String, String> {
    let kernel = opts
        .kernel
        .as_ref()
        .ok_or_else(|| "kernel path missing".to_string())?;
    let initrd = opts
        .initrd
        .as_ref()
        .ok_or_else(|| "initrd path missing".to_string())?;
    let dir = Path::new(&opts.snapshot_dir);
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let out = dir.join("boot-initial.emuko.zst");

    let sim_args = vec![
        kernel.clone(),
        "--ram-size".to_string(),
        opts.ram_size.to_string(),
        "--initrd".to_string(),
        initrd.clone(),
        "--linux".to_string(),
        "--bootargs".to_string(),
        opts.bootargs.clone(),
        "--steps".to_string(),
        "0".to_string(),
        "--no-dump".to_string(),
        "--save-snapshot".to_string(),
        out.display().to_string(),
    ];

    let run_via_cargo = |sim_args: &Vec<String>| -> Result<std::process::ExitStatus, String> {
        let mut cargo_args = vec![
            "run".to_string(),
            "--release".to_string(),
            "--bin".to_string(),
            "emukod".to_string(),
            "--".to_string(),
        ];
        cargo_args.extend(sim_args.iter().cloned());
        Command::new("cargo")
            .args(&cargo_args)
            .status()
            .map_err(|e| format!("failed to run cargo: {e}"))
    };

    let status = if let Some(bin) = current_sim_bin() {
        match Command::new(&bin).args(&sim_args).status() {
            Ok(st) => st,
            Err(e) if e.raw_os_error() == Some(8) => {
                eprintln!(
                    "warning: {} is not executable on this host ({}), falling back to cargo",
                    bin.display(),
                    e
                );
                run_via_cargo(&sim_args)?
            }
            Err(e) => return Err(format!("failed to run emukod: {e}")),
        }
    } else {
        run_via_cargo(&sim_args)?
    };
    if !status.success() {
        return Err("failed to build boot snapshot via emukod".to_string());
    }
    Ok(out.display().to_string())
}

fn parse_register(name: &str) -> Option<RegTarget> {
    let lower = name.to_ascii_lowercase();
    if lower == "pc" {
        return Some(RegTarget::Pc);
    }
    if let Some(n) = lower
        .strip_prefix('x')
        .and_then(|v| v.parse::<usize>().ok())
    {
        if n < 32 {
            return Some(RegTarget::X(n));
        }
    }
    let idx = match lower.as_str() {
        "zero" => 0,
        "ra" => 1,
        "sp" => 2,
        "gp" => 3,
        "tp" => 4,
        "t0" => 5,
        "t1" => 6,
        "t2" => 7,
        "s0" | "fp" => 8,
        "s1" => 9,
        "a0" => 10,
        "a1" => 11,
        "a2" => 12,
        "a3" => 13,
        "a4" => 14,
        "a5" => 15,
        "a6" => 16,
        "a7" => 17,
        "s2" => 18,
        "s3" => 19,
        "s4" => 20,
        "s5" => 21,
        "s6" => 22,
        "s7" => 23,
        "s8" => 24,
        "s9" => 25,
        "s10" => 26,
        "s11" => 27,
        "t3" => 28,
        "t4" => 29,
        "t5" => 30,
        "t6" => 31,
        _ => return None,
    };
    Some(RegTarget::X(idx))
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

fn decode_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if s.len() % 2 != 0 {
        return Err("hex payload must have even length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = (bytes[i] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex digit".to_string())?;
        let lo = (bytes[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| "invalid hex digit".to_string())?;
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    Ok(out)
}

fn state_json(st: &DaemonState) -> String {
    let hart = &st.system.harts[0];
    let stats = st.system.bus.stats();
    let satp = hart.csrs.read(csr::CSR_SATP);
    let sstatus = hart.csrs.read(csr::CSR_SSTATUS);
    let last_instr = hart
        .recent_instrs()
        .last()
        .map(|(pc, instr, len)| {
            if *len == 2 {
                let raw = (*instr & 0xffff) as u16;
                format!(
                    "{{\"pc\":\"0x{:016x}\",\"raw\":\"0x{:04x}\",\"len\":2,\"mnemonic\":\"{}\"}}",
                    pc,
                    raw,
                    disas::disas16(raw)
                )
            } else {
                format!(
                    "{{\"pc\":\"0x{:016x}\",\"raw\":\"0x{:08x}\",\"len\":4,\"mnemonic\":\"{}\"}}",
                    pc,
                    instr,
                    disas::disas32(*instr)
                )
            }
        })
        .unwrap_or_else(|| "null".to_string());
    let last_error = st
        .last_error
        .as_ref()
        .map(|e| format!("\"{}\"", json_escape(e)))
        .unwrap_or_else(|| "null".to_string());
    format!(
        "{{\"name\":\"{}\",\"running\":{},\"steps\":{},\"pc\":\"0x{:016x}\",\"sp\":\"0x{:016x}\",\"ra\":\"0x{:016x}\",\"a0\":\"0x{:016x}\",\"a1\":\"0x{:016x}\",\"satp\":\"0x{:016x}\",\"sstatus\":\"0x{:016x}\",\"bus_bytes\":{},\"last_instr\":{},\"last_error\":{}}}",
        NAME,
        if st.running { "true" } else { "false" },
        st.system.total_steps(),
        hart.pc,
        hart.regs[2],
        hart.regs[1],
        hart.regs[10],
        hart.regs[11],
        satp,
        sstatus,
        stats.total.bytes,
        last_instr,
        last_error
    )
}

fn disas_json(st: &mut DaemonState) -> String {
    let pc = st.system.harts[0].pc;
    let h16 = {
        let hart = &mut st.system.harts[0];
        hart.debug_read_u16_virt(&mut st.system.bus, pc)
    };
    let mut raw = String::new();
    let mut name = String::from("unmapped");
    if let Ok(v16) = h16 {
        if (v16 & 0x3) != 0x3 {
            raw = format!("0x{:04x}", v16);
            name = disas::disas16(v16);
        } else if let Ok(v32) = {
            let hart = &mut st.system.harts[0];
            hart.debug_read_u32_virt(&mut st.system.bus, pc)
        } {
            raw = format!("0x{:08x}", v32);
            name = disas::disas32(v32);
        }
    }
    format!(
        "{{\"pc\":\"0x{:016x}\",\"raw\":\"{}\",\"mnemonic\":\"{}\"}}",
        pc, raw, name
    )
}

fn run_steps(st: &mut DaemonState, n: u64) -> Result<u64, String> {
    match st.system.run(Some(n)) {
        Ok(done) => Ok(done),
        Err(trap) => {
            let msg = format!("trap: {:?}", trap);
            st.last_error = Some(msg.clone());
            Err(msg)
        }
    }
}

fn write_http(mut stream: TcpStream, code: u16, body: &str, content_type: &str) {
    let status = match code {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        409 => "Conflict",
        _ => "Internal Server Error",
    };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        code,
        status,
        content_type,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn list_snapshots(dir: &str) -> Result<String, String> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let name = name.to_string_lossy().to_string();
        if name.contains(".emuko") {
            out.push(name);
        }
    }
    out.sort();
    Ok(out.join("\n"))
}

fn handle_path(path: &str, st: &mut DaemonState) -> (u16, String, &'static str) {
    if path == "/v1/api/start" || path == "/v1/api/continue" {
        st.running = true;
        return (200, state_json(st), "application/json");
    }
    if path == "/v1/api/stop" {
        st.running = false;
        return (200, state_json(st), "application/json");
    }
    if path == "/v1/api/shutdown" {
        st.running = false;
        st.shutdown_requested = true;
        return (200, "{\"shutdown\":true}".to_string(), "application/json");
    }
    if path == "/v1/api/dump" || path == "/v1/api/state" {
        return (200, state_json(st), "application/json");
    }
    if path == "/v1/api/disas" {
        return (200, disas_json(st), "application/json");
    }
    if let Some(hex) = path.strip_prefix("/v1/api/uart/inject-hex/") {
        let bytes = match decode_hex_bytes(hex) {
            Ok(v) => v,
            Err(e) => {
                return (
                    400,
                    format!("{{\"error\":\"{}\"}}", json_escape(&e)),
                    "application/json",
                );
            }
        };
        let Some(uart) = st.system.bus.device_by_name_mut::<dev::Uart16550>("uart") else {
            return (
                500,
                "{\"error\":\"uart device not found\"}".to_string(),
                "application/json",
            );
        };
        uart.inject_bytes(&bytes);
        return (
            200,
            format!("{{\"injected\":{}}}", bytes.len()),
            "application/json",
        );
    }
    if path == "/v1/api/uart/read" || path.starts_with("/v1/api/uart/read/") {
        let max = if path == "/v1/api/uart/read" {
            4096usize
        } else {
            let tail = path.trim_start_matches("/v1/api/uart/read/");
            let Some(v) = parse_u64(tail) else {
                return (
                    400,
                    "{\"error\":\"invalid read size\"}".to_string(),
                    "application/json",
                );
            };
            v as usize
        };
        let Some(uart) = st.system.bus.device_by_name_mut::<dev::Uart16550>("uart") else {
            return (
                500,
                "{\"error\":\"uart device not found\"}".to_string(),
                "application/json",
            );
        };
        let bytes = uart.drain_tx_bytes(max);
        let text = String::from_utf8_lossy(&bytes).to_string();
        return (200, text, "text/plain");
    }
    if path == "/v1/api/step" || path.starts_with("/v1/api/step/") {
        if st.running {
            return (
                409,
                "{\"error\":\"running\"}".to_string(),
                "application/json",
            );
        }
        let n = if path == "/v1/api/step" {
            1
        } else {
            let tail = path.trim_start_matches("/v1/api/step/");
            parse_u64(tail).unwrap_or(0)
        };
        if n == 0 {
            return (
                400,
                "{\"error\":\"invalid step count\"}".to_string(),
                "application/json",
            );
        }
        match run_steps(st, n) {
            Ok(done) => {
                return (
                    200,
                    format!("{{\"stepped\":{},\"state\":{}}}", done, state_json(st)),
                    "application/json",
                );
            }
            Err(e) => {
                return (
                    500,
                    format!("{{\"error\":\"{}\"}}", json_escape(&e)),
                    "application/json",
                );
            }
        }
    }
    if let Some(rest) = path.strip_prefix("/v1/api/set/") {
        let mut it = rest.split('/');
        let Some(reg) = it.next() else {
            return (
                400,
                "{\"error\":\"missing register\"}".to_string(),
                "application/json",
            );
        };
        let Some(part2) = it.next() else {
            return (
                400,
                "{\"error\":\"missing value\"}".to_string(),
                "application/json",
            );
        };
        let value_s = if part2 == "value" {
            let Some(v) = it.next() else {
                return (
                    400,
                    "{\"error\":\"missing value\"}".to_string(),
                    "application/json",
                );
            };
            v
        } else {
            part2
        };
        let Some(target) = parse_register(reg) else {
            return (
                400,
                format!("{{\"error\":\"unknown register {}\"}}", json_escape(reg)),
                "application/json",
            );
        };
        let Some(value) = parse_u64(value_s) else {
            return (
                400,
                format!("{{\"error\":\"invalid value {}\"}}", json_escape(value_s)),
                "application/json",
            );
        };
        let hart = &mut st.system.harts[0];
        match target {
            RegTarget::Pc => hart.pc = value,
            RegTarget::X(0) => {}
            RegTarget::X(idx) => hart.regs[idx] = value,
        }
        return (200, state_json(st), "application/json");
    }
    if path == "/v1/api/snap/stop" {
        st.autosnapshot_every = 0;
        return (200, "{\"every\":0}".to_string(), "application/json");
    }
    if let Some(n_str) = path.strip_prefix("/v1/api/snap/every/") {
        if let Some(n) = parse_u64(n_str) {
            st.autosnapshot_every = n;
            st.autosnapshot_last = st.system.total_steps();
            return (200, format!("{{\"every\":{}}}", n), "application/json");
        } else {
            return (400, "{\"error\":\"invalid step count\"}".to_string(), "application/json");
        }
    }
    if path == "/v1/api/snap" {
        let _ = fs::create_dir_all(&st.snapshot_dir);
        let out = format!(
            "{}/snap-{:020}.emuko.zst",
            st.snapshot_dir,
            st.system.total_steps()
        );
        return match st.system.save_snapshot(&out) {
            Ok(_) => (
                200,
                format!("{{\"snapshot\":\"{}\"}}", json_escape(&out)),
                "application/json",
            ),
            Err(e) => (
                500,
                format!("{{\"error\":\"{}\"}}", json_escape(&e)),
                "application/json",
            ),
        };
    }
    if path == "/v1/api/ls" {
        return match list_snapshots(&st.snapshot_dir) {
            Ok(list) => (200, list, "text/plain"),
            Err(e) => (500, e, "text/plain"),
        };
    }
    if let Some(rest) = path.strip_prefix("/v1/api/restore/") {
        let path = if rest.starts_with('/') {
            rest.to_string()
        } else {
            format!("{}/{}", st.snapshot_dir, rest)
        };
        match System::load_snapshot(&path) {
            Ok(sys) => {
                st.system = sys;
                st.running = false;
                st.last_error = None;
                (200, state_json(st), "application/json")
            }
            Err(e) => (
                500,
                format!("{{\"error\":\"{}\"}}", json_escape(&e)),
                "application/json",
            ),
        }
    } else {
        (
            404,
            "{\"error\":\"unknown endpoint\"}".to_string(),
            "application/json",
        )
    }
}

/// Returns Some(stream) if this was a WebSocket upgrade for UART; None for normal HTTP.
fn handle_connection(mut stream: TcpStream, st: &mut DaemonState) -> Option<TcpStream> {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(25)));
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(0) => return None,
        Ok(n) => n,
        Err(_) => return None,
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let first = req.lines().next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");

    // Detect WebSocket upgrade for UART console.
    if method == "GET" && target == "/v1/ws/uart" {
        let mut ws_key = None;
        for line in req.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("sec-websocket-key:") {
                ws_key = Some(line.split_once(':').unwrap().1.trim().to_string());
            }
        }
        if let Some(key) = ws_key {
            let accept = ws_accept_key(&key);
            let resp = format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {}\r\n\r\n",
                accept
            );
            if stream.write_all(resp.as_bytes()).is_ok() {
                let _ = stream.set_nonblocking(true);
                return Some(stream);
            }
        }
        write_http(stream, 400, "{\"error\":\"missing Sec-WebSocket-Key\"}", "application/json");
        return None;
    }

    if method != "GET" {
        write_http(stream, 400, "{\"error\":\"GET only\"}", "application/json");
        return None;
    }
    let path = target.split('?').next().unwrap_or("/");
    let (code, body, ctype) = handle_path(path, st);
    write_http(stream, code, &body, ctype);
    None
}

fn spawn_stdin_reader() -> Receiver<u8> {
    let (tx, rx) = mpsc::channel::<u8>();
    thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut locked = stdin.lock();
        let mut buf = [0u8; 1];
        loop {
            match locked.read(&mut buf) {
                Ok(0) => break,
                Ok(_) => {
                    if tx.send(buf[0]).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
            }
        }
    });
    rx
}

fn pump_console_input(st: &mut DaemonState, stdin_rx: &Receiver<u8>) {
    let mut bytes = Vec::with_capacity(128);
    loop {
        match stdin_rx.try_recv() {
            Ok(b) => {
                // Normalize Enter key from host terminal for guest shells.
                bytes.push(if b == b'\r' { b'\n' } else { b });
                if bytes.len() >= 1024 {
                    break;
                }
            }
            Err(TryRecvError::Empty) => break,
            Err(TryRecvError::Disconnected) => break,
        }
    }
    if bytes.is_empty() {
        return;
    }
    if let Some(uart) = st.system.bus.device_by_name_mut::<dev::Uart16550>("uart") {
        uart.inject_host_bytes(&bytes);
    }
}

fn load_initial_state(opts: &DaemonOpts) -> Result<(System, String), String> {
    let boot_snapshot = if let Some(s) = &opts.snapshot {
        s.clone()
    } else {
        materialize_boot_snapshot(opts)?
    };
    let system = System::load_snapshot(&boot_snapshot)?;
    Ok((system, boot_snapshot))
}

struct WsClient {
    stream: TcpStream,
    read_buf: Vec<u8>,
}

fn pump_ws_uart(st: &mut DaemonState, client: &mut Option<WsClient>) {
    let Some(ref mut ws) = client else { return; };

    // Read WebSocket frames from client → inject into guest UART.
    let mut tmp = [0u8; 4096];
    let mut dead = false;
    match ws.stream.read(&mut tmp) {
        Ok(0) => dead = true,
        Ok(n) => ws.read_buf.extend_from_slice(&tmp[..n]),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(_) => dead = true,
    }
    // Process complete frames.
    while let Some((opcode, payload, consumed)) = ws_decode_frame(&ws.read_buf) {
        ws.read_buf.drain(..consumed);
        match opcode {
            // 0x01 text, 0x02 binary — both carry UART input bytes.
            1 | 2 => {
                if let Some(uart) = st.system.bus.device_by_name_mut::<dev::Uart16550>("uart") {
                    uart.inject_host_bytes(&payload);
                }
            }
            // 0x08 close
            8 => { dead = true; break; }
            // 0x09 ping → reply pong
            9 => {
                let pong = ws_encode_frame(0x0A, &payload);
                if ws.stream.write_all(&pong).is_err() { dead = true; break; }
            }
            _ => {}
        }
    }
    if dead { *client = None; return; }

    // Drain guest UART TX → send as WebSocket binary frames.
    let Some(ref mut ws) = client else { return; };
    if let Some(uart) = st.system.bus.device_by_name_mut::<dev::Uart16550>("uart") {
        let bytes = uart.drain_tx_bytes(8192);
        if !bytes.is_empty() {
            let frame = ws_encode_frame(0x02, &bytes);
            if ws.stream.write_all(&frame).is_err() || ws.stream.flush().is_err() {
                *client = None;
            }
        }
    }
}

fn run_loop(mut st: DaemonState, addr: &str) -> Result<(), String> {
    let listener = TcpListener::bind(addr).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;

    let mut ws_uart: Option<WsClient> = None;
    let stdin_rx = spawn_stdin_reader();
    eprintln!(
        "{} daemon listening on http://{} ws://{}/v1/ws/uart (chunk_steps={}, boot_snapshot={})",
        NAME, addr, addr, st.chunk_steps, st.boot_snapshot
    );
    loop {
        pump_console_input(&mut st, &stdin_rx);
        if st.running {
            let chunk = st.chunk_steps;
            match run_steps(&mut st, chunk) {
                Ok(done) => {
                    if done < chunk {
                        st.running = false;
                    }
                }
                Err(_) => {
                    st.running = false;
                }
            }
            if st.autosnapshot_every > 0 {
                let total = st.system.total_steps();
                if total - st.autosnapshot_last >= st.autosnapshot_every {
                    let _ = fs::create_dir_all(&st.snapshot_dir);
                    let path = format!("{}/snap-{:020}.emuko.zst", st.snapshot_dir, total);
                    if let Err(e) = st.system.save_snapshot(&path) {
                        eprintln!("Autosnapshot failed: {}", e);
                    }
                    st.autosnapshot_last = total;
                }
            }
        }

        pump_ws_uart(&mut st, &mut ws_uart);

        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    if let Some(upgraded) = handle_connection(stream, &mut st) {
                        // WebSocket upgrade for UART console (latest client wins).
                        ws_uart = Some(WsClient { stream: upgraded, read_buf: Vec::new() });
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        pump_console_input(&mut st, &stdin_rx);
        if st.shutdown_requested {
            eprintln!("{} daemon shutting down", NAME);
            break;
        }
        if st.running {
            std::thread::yield_now();
        } else {
            std::thread::sleep(Duration::from_millis(3));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Standalone emulator path (debug / snapshot generation)
// ---------------------------------------------------------------------------

enum RunFailure {
    Trap(Trap),
    Snapshot(String),
}

fn print_trap(trap: Trap) {
    match trap {
        Trap::Ecall => println!("ECALL"),
        Trap::Ebreak => println!("EBREAK"),
        Trap::IllegalInstruction(instr) => {
            eprintln!("Illegal instruction 0x{:08x}", instr)
        }
        Trap::MisalignedAccess { addr, size } => {
            eprintln!("Misaligned access addr=0x{:016x} size={}", addr, size)
        }
        Trap::MemoryOutOfBounds { addr, size } => {
            eprintln!("Out of bounds addr=0x{:016x} size={}", addr, size)
        }
        Trap::PageFault { addr, .. } => {
            eprintln!("Page fault addr=0x{:016x}", addr)
        }
    }
}

fn run_with_autosnapshot(
    system: &mut System,
    max_steps: Option<u64>,
    autosnapshot_every: Option<u64>,
    autosnapshot_dir: &str,
) -> Result<u64, RunFailure> {
    let every = autosnapshot_every.unwrap_or(0);
    if every == 0 {
        return system.run(max_steps).map_err(RunFailure::Trap);
    }
    fs::create_dir_all(autosnapshot_dir).map_err(|e| {
        RunFailure::Snapshot(format!("failed to create {}: {}", autosnapshot_dir, e))
    })?;

    let mut completed = 0u64;
    loop {
        let remaining = max_steps.map(|limit| limit.saturating_sub(completed));
        if remaining == Some(0) {
            return Ok(completed);
        }
        let chunk = remaining.map_or(every, |left| left.min(every));
        if chunk == 0 {
            return Ok(completed);
        }
        let ran = system.run(Some(chunk)).map_err(RunFailure::Trap)?;
        completed = completed.saturating_add(ran);
        let snap_path = format!(
            "{}/snap-{:020}.emuko.zst",
            autosnapshot_dir,
            system.total_steps()
        );
        system
            .save_snapshot(&snap_path)
            .map_err(|e| RunFailure::Snapshot(format!("failed to save {}: {}", snap_path, e)))?;
        eprintln!("Autosaved snapshot {}", snap_path);
        if ran < chunk {
            return Ok(completed);
        }
    }
}

#[derive(Default)]
struct RuntimeTuning {
    perf_report_count: Option<u32>,
    perf_report_secs: Option<f64>,
    perf_check_ticks: Option<u32>,
    uart_poll_wall_ms: Option<u64>,
    uart_poll_calib_ms: Option<u64>,
    uart_poll_check_ticks: Option<u32>,
    uart_poll_ticks: Option<u32>,
    uart_flush_every: Option<usize>,
}

impl RuntimeTuning {
    fn apply(&self, system: &mut System) -> Result<(), String> {
        let perf_interval = self.perf_report_secs.map(Duration::from_secs_f64);
        system.configure_perf_reporting(
            self.perf_report_count,
            perf_interval,
            self.perf_check_ticks,
        );

        if let Some(ticks) = self.uart_poll_ticks {
            system.configure_uart_poll_fixed(ticks)?;
        } else if self.uart_poll_wall_ms.is_some()
            || self.uart_poll_calib_ms.is_some()
            || self.uart_poll_check_ticks.is_some()
        {
            let wall_ms = self.uart_poll_wall_ms.unwrap_or(100);
            let calib_ms = self.uart_poll_calib_ms.unwrap_or(250);
            let check_ticks = self.uart_poll_check_ticks.unwrap_or(2048).max(1);
            system.configure_uart_poll_auto(
                Duration::from_millis(wall_ms),
                Duration::from_millis(calib_ms),
                check_ticks,
            )?;
        }

        if let Some(every) = self.uart_flush_every {
            system.configure_uart_flush_every(every)?;
        }
        Ok(())
    }
}

fn ext_mask_from_str(arg: &str) -> Option<u64> {
    let mut mask = 0u64;
    for ch in arg.chars() {
        if ch == ',' || ch == ' ' {
            continue;
        }
        let bit = match ch.to_ascii_uppercase() {
            'A' => 0,
            'C' => 2,
            'D' => 3,
            'F' => 5,
            'I' => 8,
            'M' => 12,
            'S' => 18,
            'U' => 20,
            _ => return None,
        };
        mask |= 1u64 << bit;
    }
    if mask == 0 {
        None
    } else {
        Some(mask)
    }
}

fn isa_string_from_mask(mask: u64) -> String {
    let mut s = String::from("rv64i");
    let has = |bit: u64| (mask & (1u64 << bit)) != 0;
    if has(12) {
        s.push('m');
    }
    if has(0) {
        s.push('a');
    }
    if has(5) {
        s.push('f');
    }
    if has(3) {
        s.push('d');
    }
    if has(2) {
        s.push('c');
    }
    s
}

fn align_up(val: u64, align: u64) -> u64 {
    (val + align - 1) & !(align - 1)
}

fn align_down(val: u64, align: u64) -> u64 {
    val & !(align - 1)
}

fn parse_f64(arg: &str) -> Option<f64> {
    arg.parse::<f64>().ok()
}

fn print_standalone_usage() {
    eprintln!(
        "Usage: emukod <binary> [--steps N] [--load-addr ADDR] [--entry-addr ADDR] [--ram-base ADDR] [--ram-size BYTES] [--dtb FILE] [--dtb-addr ADDR] [--initrd FILE] [--initrd-addr ADDR] [--linux] [--ext EXT] [--bootargs STR] [--trace-traps N] [--trace-instr N] [--save-snapshot FILE] [--load-snapshot FILE] [--autosnapshot-every N] [--autosnapshot-dir DIR] [--perf-report-count N] [--perf-report-secs S] [--perf-check-ticks N] [--uart-poll-wall-ms N] [--uart-poll-calib-ms N] [--uart-poll-check-ticks N] [--uart-poll-ticks N] [--uart-flush-every N] [--no-dump]"
    );
}

fn is_standalone_invocation() -> bool {
    let standalone_flags = [
        "--steps",
        "--load-addr",
        "--entry-addr",
        "--dtb",
        "--dtb-addr",
        "--initrd-addr",
        "--linux",
        "--ext",
        "--trace-traps",
        "--trace-instr",
        "--save-snapshot",
        "--load-snapshot",
        "--autosnapshot-every",
        "--autosnapshot-dir",
        "--no-dump",
    ];
    let standalone_prefixes = ["--perf-", "--uart-"];
    for arg in env::args().skip(1) {
        for flag in &standalone_flags {
            if arg == *flag {
                return true;
            }
        }
        for prefix in &standalone_prefixes {
            if arg.starts_with(prefix) {
                return true;
            }
        }
    }
    false
}

fn run_standalone() {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        print_standalone_usage();
        std::process::exit(1);
    };

    let mut max_steps: Option<u64> = None;
    let mut load_addr: Option<u64> = None;
    let mut entry_addr: Option<u64> = None;
    let mut ram_base: u64 = DEFAULT_RAM_BASE;
    let mut ram_size: usize = DEFAULT_RAM_SIZE;
    let mut dtb_path: Option<String> = None;
    let mut dtb_addr: Option<u64> = None;
    let mut initrd_path: Option<String> = None;
    let mut initrd_addr: Option<u64> = None;
    let mut linux_boot = false;
    let mut ext_mask: Option<u64> = None;
    let mut bootargs: Option<String> = None;
    let mut trace_traps: Option<u64> = None;
    let mut trace_instr: Option<u64> = None;
    let mut save_snapshot: Option<String> = None;
    let mut load_snapshot: Option<String> = None;
    let mut autosnapshot_every: Option<u64> = None;
    let mut autosnapshot_dir: String = "/tmp/emuko".to_string();
    let mut dump_state = true;
    let mut tuning = RuntimeTuning::default();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--steps" => {
                let Some(n) = args.next() else {
                    eprintln!("Missing value for --steps");
                    std::process::exit(1);
                };
                max_steps = n.parse::<u64>().ok();
                if max_steps.is_none() {
                    eprintln!("Invalid --steps value: {n}");
                    std::process::exit(1);
                }
            }
            "--load-addr" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --load-addr");
                    std::process::exit(1);
                };
                load_addr = parse_u64(&val);
                if load_addr.is_none() {
                    eprintln!("Invalid --load-addr value: {val}");
                    std::process::exit(1);
                }
            }
            "--entry-addr" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --entry-addr");
                    std::process::exit(1);
                };
                entry_addr = parse_u64(&val);
                if entry_addr.is_none() {
                    eprintln!("Invalid --entry-addr value: {val}");
                    std::process::exit(1);
                }
            }
            "--ram-base" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --ram-base");
                    std::process::exit(1);
                };
                ram_base = match parse_u64(&val) {
                    Some(v) => v,
                    None => {
                        eprintln!("Invalid --ram-base value: {val}");
                        std::process::exit(1);
                    }
                };
            }
            "--ram-size" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --ram-size");
                    std::process::exit(1);
                };
                ram_size = match parse_u64(&val) {
                    Some(v) => v as usize,
                    None => {
                        eprintln!("Invalid --ram-size value: {val}");
                        std::process::exit(1);
                    }
                };
            }
            "--dtb" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --dtb");
                    std::process::exit(1);
                };
                dtb_path = Some(val);
            }
            "--dtb-addr" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --dtb-addr");
                    std::process::exit(1);
                };
                dtb_addr = parse_u64(&val);
                if dtb_addr.is_none() {
                    eprintln!("Invalid --dtb-addr value: {val}");
                    std::process::exit(1);
                }
            }
            "--initrd" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --initrd");
                    std::process::exit(1);
                };
                initrd_path = Some(val);
            }
            "--initrd-addr" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --initrd-addr");
                    std::process::exit(1);
                };
                initrd_addr = parse_u64(&val);
                if initrd_addr.is_none() {
                    eprintln!("Invalid --initrd-addr value: {val}");
                    std::process::exit(1);
                }
            }
            "--linux" => {
                linux_boot = true;
            }
            "--ext" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --ext");
                    std::process::exit(1);
                };
                ext_mask = ext_mask_from_str(&val);
                if ext_mask.is_none() {
                    eprintln!("Invalid --ext value: {val}");
                    std::process::exit(1);
                }
            }
            "--bootargs" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --bootargs");
                    std::process::exit(1);
                };
                bootargs = Some(val);
            }
            "--trace-traps" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --trace-traps");
                    std::process::exit(1);
                };
                trace_traps = parse_u64(&val);
                if trace_traps.is_none() {
                    eprintln!("Invalid --trace-traps value: {val}");
                    std::process::exit(1);
                }
            }
            "--trace-instr" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --trace-instr");
                    std::process::exit(1);
                };
                trace_instr = parse_u64(&val);
                if trace_instr.is_none() {
                    eprintln!("Invalid --trace-instr value: {val}");
                    std::process::exit(1);
                }
            }
            "--save-snapshot" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --save-snapshot");
                    std::process::exit(1);
                };
                save_snapshot = Some(val);
            }
            "--load-snapshot" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --load-snapshot");
                    std::process::exit(1);
                };
                load_snapshot = Some(val);
            }
            "--autosnapshot-every" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --autosnapshot-every");
                    std::process::exit(1);
                };
                autosnapshot_every = parse_u64(&val);
                if autosnapshot_every.is_none() {
                    eprintln!("Invalid --autosnapshot-every value: {val}");
                    std::process::exit(1);
                }
            }
            "--autosnapshot-dir" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --autosnapshot-dir");
                    std::process::exit(1);
                };
                autosnapshot_dir = val;
            }
            "--perf-report-count" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --perf-report-count");
                    std::process::exit(1);
                };
                tuning.perf_report_count = parse_u64(&val).and_then(|v| u32::try_from(v).ok());
                if tuning.perf_report_count.is_none() {
                    eprintln!("Invalid --perf-report-count value: {val}");
                    std::process::exit(1);
                }
            }
            "--perf-report-secs" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --perf-report-secs");
                    std::process::exit(1);
                };
                tuning.perf_report_secs = parse_f64(&val);
                if tuning.perf_report_secs.is_none()
                    || tuning.perf_report_secs.unwrap_or(0.0) <= 0.0
                {
                    eprintln!("Invalid --perf-report-secs value: {val}");
                    std::process::exit(1);
                }
            }
            "--perf-check-ticks" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --perf-check-ticks");
                    std::process::exit(1);
                };
                tuning.perf_check_ticks = parse_u64(&val).and_then(|v| u32::try_from(v).ok());
                if tuning.perf_check_ticks.unwrap_or(0) == 0 {
                    eprintln!("Invalid --perf-check-ticks value: {val}");
                    std::process::exit(1);
                }
            }
            "--uart-poll-wall-ms" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --uart-poll-wall-ms");
                    std::process::exit(1);
                };
                tuning.uart_poll_wall_ms = parse_u64(&val);
                if tuning.uart_poll_wall_ms.unwrap_or(0) == 0 {
                    eprintln!("Invalid --uart-poll-wall-ms value: {val}");
                    std::process::exit(1);
                }
            }
            "--uart-poll-calib-ms" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --uart-poll-calib-ms");
                    std::process::exit(1);
                };
                tuning.uart_poll_calib_ms = parse_u64(&val);
                if tuning.uart_poll_calib_ms.unwrap_or(0) == 0 {
                    eprintln!("Invalid --uart-poll-calib-ms value: {val}");
                    std::process::exit(1);
                }
            }
            "--uart-poll-check-ticks" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --uart-poll-check-ticks");
                    std::process::exit(1);
                };
                tuning.uart_poll_check_ticks = parse_u64(&val).and_then(|v| u32::try_from(v).ok());
                if tuning.uart_poll_check_ticks.unwrap_or(0) == 0 {
                    eprintln!("Invalid --uart-poll-check-ticks value: {val}");
                    std::process::exit(1);
                }
            }
            "--uart-poll-ticks" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --uart-poll-ticks");
                    std::process::exit(1);
                };
                tuning.uart_poll_ticks = parse_u64(&val).and_then(|v| u32::try_from(v).ok());
                if tuning.uart_poll_ticks.unwrap_or(0) == 0 {
                    eprintln!("Invalid --uart-poll-ticks value: {val}");
                    std::process::exit(1);
                }
            }
            "--uart-flush-every" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --uart-flush-every");
                    std::process::exit(1);
                };
                tuning.uart_flush_every = parse_u64(&val).and_then(|v| usize::try_from(v).ok());
                if tuning.uart_flush_every.unwrap_or(0) == 0 {
                    eprintln!("Invalid --uart-flush-every value: {val}");
                    std::process::exit(1);
                }
            }
            "--no-dump" => {
                dump_state = false;
            }
            _ => {
                eprintln!("Unknown argument: {arg}");
                print_standalone_usage();
                std::process::exit(1);
            }
        }
    }

    if !Path::new(&autosnapshot_dir).is_absolute() {
        eprintln!(
            "--autosnapshot-dir must be an absolute path: {}",
            autosnapshot_dir
        );
        std::process::exit(1);
    }

    if let Some(load_path) = load_snapshot.as_deref() {
        let mut system = match System::load_snapshot(load_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Failed to load snapshot {}: {}", load_path, e);
                std::process::exit(1);
            }
        };
        if trace_traps.is_some() {
            system.set_trace_traps(trace_traps);
        }
        if trace_instr.is_some() {
            system.set_trace_instr(trace_instr);
        }
        if let Err(e) = tuning.apply(&mut system) {
            eprintln!("Failed to apply runtime tuning: {}", e);
            std::process::exit(1);
        }
        let mut exit_code = 0;
        let result = run_with_autosnapshot(
            &mut system,
            max_steps,
            autosnapshot_every,
            &autosnapshot_dir,
        );
        match result {
            Ok(steps) => {
                println!("Completed {} steps (total {})", steps, system.total_steps());
            }
            Err(RunFailure::Trap(trap)) => {
                exit_code = 2;
                print_trap(trap);
            }
            Err(RunFailure::Snapshot(err)) => {
                exit_code = 1;
                eprintln!("{}", err);
            }
        }
        if let Some(save_path) = save_snapshot.as_deref() {
            if let Err(e) = system.save_snapshot(save_path) {
                eprintln!("Failed to save snapshot {}: {}", save_path, e);
                if exit_code == 0 {
                    exit_code = 1;
                }
            } else {
                println!("Saved snapshot {}", save_path);
            }
        }
        if dump_state {
            system.dump_state(0);
            system.dump_bus_stats();
            system.dump_sbi_stats();
            system.dump_hotpcs();
        } else {
            if let Some(hart0) = system.harts.get(0) {
                println!(
                    "final hart0: pc=0x{:016x} ra=0x{:016x} sp=0x{:016x} a0=0x{:016x} a1=0x{:016x} a2=0x{:016x} a6=0x{:016x} a7=0x{:016x}",
                    hart0.pc,
                    hart0.regs[1],
                    hart0.regs[2],
                    hart0.regs[10],
                    hart0.regs[11],
                    hart0.regs[12],
                    hart0.regs[16],
                    hart0.regs[17]
                );
            }
            system.dump_bus_stats();
            system.dump_sbi_stats();
            system.dump_hotpcs();
        }
        std::process::exit(exit_code);
    }

    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read {}: {e}", path);
            std::process::exit(1);
        }
    };

    let pe_image = pe::parse_pe(&data).ok();
    if pe_image.is_none() && data.len() > ram_size {
        eprintln!(
            "Program too large: {} bytes (ram {} bytes)",
            data.len(),
            ram_size
        );
        std::process::exit(1);
    }

    let default_ext = (1u64 << 8)
        | (1u64 << 12)
        | (1u64 << 0)
        | (1u64 << 2)
        | (1u64 << 5)
        | (1u64 << 3)
        | (1u64 << 18)
        | (1u64 << 20);
    let ext_mask = ext_mask.unwrap_or(default_ext);
    let mut system = System::new(1, ram_base, ram_size, ext_mask);
    system.set_trace_traps(trace_traps);
    system.set_trace_instr(trace_instr);
    if let Err(e) = tuning.apply(&mut system) {
        eprintln!("Failed to apply runtime tuning: {}", e);
        std::process::exit(1);
    }
    let load_addr_arg = load_addr;
    let mut load_addr = load_addr_arg.unwrap_or(ram_base);
    let mut image_size = data.len() as u64;
    let mut entry_addr_default = load_addr;
    if let Some(pe) = &pe_image {
        if std::env::var("PE_TRACE").ok().is_some() {
            eprintln!(
                "PE: image_base=0x{:x} entry_rva=0x{:x} size_of_image=0x{:x} sections={}",
                pe.image_base,
                pe.entry_rva,
                pe.size_of_image,
                pe.sections.len()
            );
        }
        let preferred = if pe.image_base == 0 {
            ram_base
        } else {
            pe.image_base
        };
        load_addr = load_addr_arg.unwrap_or(preferred);
        image_size = pe.size_of_image as u64;
        entry_addr_default = load_addr + pe.entry_rva as u64;
    }
    if load_addr < ram_base || load_addr + image_size > ram_base + ram_size as u64 {
        eprintln!(
            "Image does not fit in RAM at 0x{:016x} (size 0x{:x})",
            load_addr, image_size
        );
        std::process::exit(1);
    }
    let entry_addr = entry_addr.unwrap_or(entry_addr_default);
    system.set_reset_pc(entry_addr);
    system.reset();

    let mut exit_code = 0;
    let mut ran = false;

    let kernel_end = load_addr + image_size;
    let mut kernel_data_start: Option<u64> = None;
    if let Some(pe) = &pe_image {
        for sec in &pe.sections {
            if sec.vsize == 0 && sec.raw_size == 0 {
                continue;
            }
            if sec.is_executable() {
                continue;
            }
            let start = load_addr + sec.vaddr;
            kernel_data_start = Some(kernel_data_start.map_or(start, |cur| cur.min(start)));
        }
    }
    let mut load_ok = true;
    if let Some(pe) = &pe_image {
        if load_addr != pe.image_base && pe.base_reloc_size == 0 {
            eprintln!(
                "Warning: PE has no relocations; load_addr 0x{:x} differs from image base 0x{:x}",
                load_addr, pe.image_base
            );
        }
        for sec in &pe.sections {
            if sec.raw_size == 0 && sec.vsize == 0 {
                continue;
            }
            let vaddr = load_addr + sec.vaddr;
            if sec.raw_size > 0 {
                let start = sec.raw_ptr as usize;
                let end = start.saturating_add(sec.raw_size as usize).min(data.len());
                if let Err(e) = system.load(vaddr, &data[start..end]) {
                    eprintln!("PE load failed: {:?}", e);
                    load_ok = false;
                    break;
                }
            }
            if sec.vsize > sec.raw_size {
                let zero_len = (sec.vsize - sec.raw_size) as usize;
                let zeros = vec![0u8; zero_len.min(1024 * 1024)];
                let mut offset = 0usize;
                while offset < zero_len {
                    let chunk = (zero_len - offset).min(zeros.len());
                    if let Err(e) =
                        system.load(vaddr + sec.raw_size as u64 + offset as u64, &zeros[..chunk])
                    {
                        eprintln!("PE BSS load failed: {:?}", e);
                        load_ok = false;
                        break;
                    }
                    offset += chunk;
                }
                if !load_ok {
                    break;
                }
            }
        }
    } else {
        if let Err(e) = system.load(load_addr, &data) {
            eprintln!("Load failed: {:?}", e);
            load_ok = false;
        }
    }

    if load_ok {
        if let Some(pe) = &pe_image {
            if load_addr != pe.image_base && pe.base_reloc_size != 0 {
                let delta = load_addr.wrapping_sub(pe.image_base);
                let mut rva = pe.base_reloc_rva as u64;
                let end = pe.base_reloc_rva as u64 + pe.base_reloc_size as u64;
                while rva < end {
                    let file_off = match pe.rva_to_file_offset(rva as u32) {
                        Some(off) => off,
                        None => break,
                    };
                    if file_off + 8 > data.len() {
                        break;
                    }
                    let page_rva = u32::from_le_bytes([
                        data[file_off],
                        data[file_off + 1],
                        data[file_off + 2],
                        data[file_off + 3],
                    ]);
                    let block_size = u32::from_le_bytes([
                        data[file_off + 4],
                        data[file_off + 5],
                        data[file_off + 6],
                        data[file_off + 7],
                    ]);
                    if block_size < 8 {
                        break;
                    }
                    let entries = (block_size - 8) / 2;
                    for i in 0..entries {
                        let entry_off = file_off + 8 + (i as usize) * 2;
                        if entry_off + 2 > data.len() {
                            break;
                        }
                        let entry = u16::from_le_bytes([data[entry_off], data[entry_off + 1]]);
                        let rtype = entry >> 12;
                        let roff = (entry & 0x0fff) as u64;
                        if rtype == 0 {
                            continue;
                        }
                        let reloc_addr = load_addr + page_rva as u64 + roff;
                        match rtype {
                            0xA => {
                                if let Ok(val) = system.bus.read_u64(
                                    0,
                                    reloc_addr,
                                    bus::AccessType::Debug,
                                ) {
                                    let _ = system.bus.write_u64(
                                        0,
                                        reloc_addr,
                                        val.wrapping_add(delta),
                                        bus::AccessType::Debug,
                                    );
                                }
                            }
                            0x3 => {
                                if let Ok(val) = system.bus.read_u32(
                                    0,
                                    reloc_addr,
                                    bus::AccessType::Debug,
                                ) {
                                    let _ = system.bus.write_u32(
                                        0,
                                        reloc_addr,
                                        val.wrapping_add(delta as u32),
                                        bus::AccessType::Debug,
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                    rva = rva.wrapping_add(block_size as u64);
                }
            }
        }

        let initrd_data = if let Some(path) = initrd_path {
            match fs::read(&path) {
                Ok(d) => Some(d),
                Err(e) => {
                    eprintln!("Failed to read initrd {}: {e}", path);
                    std::process::exit(1);
                }
            }
        } else {
            None
        };

        let mut initrd_range: Option<(u64, u64)> = None;
        if let Some(initrd) = &initrd_data {
            let top = ram_base + ram_size as u64;
            let size = align_up(initrd.len() as u64, 0x1000);
            let desired =
                initrd_addr.unwrap_or_else(|| align_down(top.saturating_sub(size), 0x1000));
            let end = desired + initrd.len() as u64;
            if desired < ram_base || end > ram_base + ram_size as u64 {
                eprintln!("Initrd does not fit in RAM at 0x{:016x}", desired);
                std::process::exit(1);
            }
            if !(end <= load_addr || desired >= kernel_end) {
                eprintln!("Initrd overlaps kernel image");
                std::process::exit(1);
            }
            if let Err(e) = system.load(desired, initrd) {
                eprintln!("Initrd load failed: {:?}", e);
                std::process::exit(1);
            }
            initrd_range = Some((desired, desired + initrd.len() as u64));
        }

        let dtb_data = if let Some(path) = dtb_path {
            match fs::read(&path) {
                Ok(d) => Some(d),
                Err(e) => {
                    eprintln!("Failed to read dtb {}: {e}", path);
                    std::process::exit(1);
                }
            }
        } else if linux_boot {
            let isa = isa_string_from_mask(ext_mask);
            Some(fdt::build_virt_dtb(
                1,
                ram_base,
                ram_size as u64,
                &isa,
                bootargs.as_deref(),
                initrd_range,
            ))
        } else {
            None
        };
        if let Ok(path) = std::env::var("DUMP_DTB") {
            if let Some(dtb) = &dtb_data {
                if let Err(e) = fs::write(&path, dtb) {
                    eprintln!("Failed to write dtb {}: {e}", path);
                } else {
                    eprintln!("Wrote dtb to {}", path);
                }
            }
        }

        let mut dtb_load_addr = 0u64;
        if let Some(dtb) = &dtb_data {
            let desired = dtb_addr.unwrap_or_else(|| {
                let top = initrd_range
                    .map(|(start, _)| start)
                    .unwrap_or(ram_base + ram_size as u64);
                let size = align_up(dtb.len() as u64, 0x1000);
                align_down(top.saturating_sub(size), 0x1000)
            });
            let dtb_end = desired + dtb.len() as u64;
            let kernel_end = load_addr + image_size;
            if let Some((initrd_start, initrd_end)) = initrd_range {
                if !(dtb_end <= initrd_start || desired >= initrd_end) {
                    eprintln!("DTB overlaps initrd");
                    std::process::exit(1);
                }
            }
            if desired < ram_base || dtb_end > ram_base + ram_size as u64 {
                eprintln!("DTB does not fit in RAM at 0x{:016x}", desired);
                std::process::exit(1);
            }
            if !(dtb_end <= load_addr || desired >= kernel_end) {
                eprintln!("DTB overlaps kernel image");
                std::process::exit(1);
            }
            if let Err(e) = system.load(desired, dtb) {
                eprintln!("DTB load failed: {:?}", e);
                std::process::exit(1);
            }
            dtb_load_addr = desired;
        }

        if linux_boot {
            if dtb_load_addr == 0 {
                eprintln!("--linux requires --dtb or auto-generated DTB");
                std::process::exit(1);
            }
            if pe_image.is_some() {
                let dtb_len = dtb_data.as_ref().map(|d| d.len()).unwrap_or(0);
                let dtb_range = if dtb_len == 0 {
                    None
                } else {
                    Some((dtb_load_addr, dtb_load_addr + dtb_len as u64))
                };
                let mut top = ram_base + ram_size as u64;
                if let Some((initrd_start, _)) = initrd_range {
                    top = top.min(initrd_start);
                }
                if dtb_load_addr != 0 {
                    top = top.min(dtb_load_addr);
                }
                let efi_size = efi::EFI_REGION_SIZE;
                let efi_base = align_down(top.saturating_sub(efi_size), 0x1000);
                if efi_base < ram_base || efi_base + efi_size > top {
                    eprintln!("EFI tables do not fit in RAM");
                    std::process::exit(1);
                }
                if !(efi_base + efi_size <= load_addr || efi_base >= kernel_end) {
                    eprintln!("EFI tables overlap kernel image");
                    std::process::exit(1);
                }
                let alloc_bottom = align_up(kernel_end, 0x1000);
                let alloc_top = efi_base;
                if alloc_bottom >= alloc_top {
                    eprintln!("EFI allocator region is empty");
                    std::process::exit(1);
                }
                let kernel_data_start_efi = if std::env::var("EFI_SPLIT_KERNEL_MAP").is_ok() {
                    kernel_data_start
                } else {
                    None
                };
                let efi_build = efi::build_efi_blob(
                    efi_base,
                    ram_base,
                    ram_size as u64,
                    (load_addr, kernel_end),
                    kernel_data_start_efi,
                    bootargs.as_deref(),
                    initrd_range,
                    dtb_range,
                    alloc_bottom,
                    alloc_top,
                );
                if std::env::var("EFI_PROTO_TRACE").is_ok() {
                    let off = (efi_build.riscv_boot_proto - efi_base) as usize;
                    if off + 16 <= efi_build.blob.len() {
                        eprintln!(
                            "EFI boot proto bytes: {:02x?}",
                            &efi_build.blob[off..off + 16]
                        );
                    }
                    let off = (efi_build.riscv_fdt_proto - efi_base) as usize;
                    if off + 16 <= efi_build.blob.len() {
                        eprintln!(
                            "EFI fdt proto bytes: {:02x?}",
                            &efi_build.blob[off..off + 16]
                        );
                    }
                }
                eprintln!(
                    "EFI: base=0x{:016x} system_table=0x{:016x} image_handle=0x{:016x} alloc=[0x{:016x}..0x{:016x})",
                    efi_base,
                    efi_build.system_table,
                    efi_build.image_handle,
                    alloc_bottom,
                    alloc_top
                );
                if let Err(e) = system.load(efi_base, &efi_build.blob) {
                    eprintln!("EFI tables load failed: {:?}", e);
                    std::process::exit(1);
                }
                let system_table = efi_build.system_table;
                let image_handle = efi_build.image_handle;
                let efi_state = efi::EfiState::new(efi_build);
                system.configure_efi_boot(system_table, image_handle, efi_state);
            } else {
                system.configure_linux_boot(dtb_load_addr);
            }
        }
        let result = run_with_autosnapshot(
            &mut system,
            max_steps,
            autosnapshot_every,
            &autosnapshot_dir,
        );
        ran = true;
        match result {
            Ok(steps) => {
                println!("Completed {} steps (total {})", steps, system.total_steps());
            }
            Err(RunFailure::Trap(trap)) => {
                exit_code = 2;
                print_trap(trap);
            }
            Err(RunFailure::Snapshot(err)) => {
                exit_code = 1;
                eprintln!("{}", err);
            }
        }
    } else {
        exit_code = 1;
    }

    if let Some(save_path) = save_snapshot.as_deref() {
        if let Err(e) = system.save_snapshot(save_path) {
            eprintln!("Failed to save snapshot {}: {}", save_path, e);
            if exit_code == 0 {
                exit_code = 1;
            }
        } else {
            println!("Saved snapshot {}", save_path);
        }
    }

    if dump_state {
        if ran {
            system.dump_state(data.len());
            system.dump_bus_stats();
            system.dump_sbi_stats();
            system.dump_hotpcs();
        } else {
            system.dump_state(0);
            system.dump_bus_stats();
            system.dump_sbi_stats();
            system.dump_hotpcs();
        }
    } else if ran {
        if let Some(hart0) = system.harts.get(0) {
            println!(
                "final hart0: pc=0x{:016x} ra=0x{:016x} sp=0x{:016x} a0=0x{:016x} a1=0x{:016x} a2=0x{:016x} a6=0x{:016x} a7=0x{:016x}",
                hart0.pc,
                hart0.regs[1],
                hart0.regs[2],
                hart0.regs[10],
                hart0.regs[11],
                hart0.regs[12],
                hart0.regs[16],
                hart0.regs[17]
            );
        }
        system.dump_bus_stats();
        system.dump_sbi_stats();
        system.dump_hotpcs();
    }
    std::process::exit(exit_code);
}

fn main() {
    if is_standalone_invocation() {
        run_standalone();
        return;
    }
    // Daemon owns stdin-to-UART bridging; keep UART device stdin reader disabled to avoid races.
    std::env::set_var("UART_HOST_STDIN", "0");
    let opts = parse_opts();
    if std::env::var("KOR_JIT_NATIVE").is_err() {
        std::env::set_var("KOR_JIT_NATIVE", if opts.jit_native { "1" } else { "0" });
    }
    if let Some(cfg) = &opts.config_path {
        eprintln!("config: {}", cfg);
    }
    eprintln!(
        "backend: {} host_arch={} jit_native={}",
        opts.backend,
        opts.host_arch,
        std::env::var("KOR_JIT_NATIVE").unwrap_or_else(|_| "0".to_string())
    );
    if opts.bootargs.contains("rdinit=/bin/sh") {
        eprintln!(
            "note: bootargs include rdinit=/bin/sh, so init scripts are skipped; \
mount pseudo-fs in guest: \
mount -t proc proc /proc; mount -t sysfs sysfs /sys; mount -t devtmpfs devtmpfs /dev"
        );
    }
    let (system, boot_snapshot) = match load_initial_state(&opts) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("failed to initialize {} daemon: {}", NAME, e);
            std::process::exit(1);
        }
    };
    let st = DaemonState {
        system,
        running: opts.autostart,
        shutdown_requested: false,
        boot_snapshot,
        snapshot_dir: opts.snapshot_dir.clone(),
        chunk_steps: opts.chunk_steps.max(1),
        last_error: None,
        autosnapshot_every: 0,
        autosnapshot_last: 0,
    };
    if let Err(e) = run_loop(st, &opts.addr) {
        eprintln!("daemon error: {}", e);
        std::process::exit(1);
    }
}
