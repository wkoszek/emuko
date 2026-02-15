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

use system::System;

const NAME: &str = "KoRISCV";

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
}

struct DaemonState {
    system: System,
    running: bool,
    boot_snapshot: String,
    snapshot_dir: String,
    chunk_steps: u64,
    last_error: Option<String>,
}

enum RegTarget {
    Pc,
    X(usize),
}

fn print_usage_and_exit() -> ! {
    eprintln!(
        "Usage: koriscvd [--snapshot FILE] [<kernel> <initrd>] [--ram-size BYTES] [--bootargs STR] [--addr HOST:PORT] [--snapshot-dir DIR] [--chunk-steps N] [--autostart]"
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

fn parse_opts() -> DaemonOpts {
    let mut args = env::args().skip(1);
    let mut snapshot = None;
    let mut kernel = None;
    let mut initrd = None;
    let mut ram_size = 1024 * 1024 * 1024u64;
    let mut bootargs =
        "console=ttyS0,115200 earlycon=uart8250,mmio,0x10000000 rdinit=/bin/sh"
            .to_string();
    let mut addr = "127.0.0.1:7788".to_string();
    let mut snapshot_dir = "/tmp/korisc5".to_string();
    let mut chunk_steps = 4_000_000u64;
    let mut autostart = false;
    let mut positionals = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--snapshot" => {
                snapshot = args.next();
                if snapshot.is_none() {
                    print_usage_and_exit();
                }
            }
            "--ram-size" => {
                let Some(v) = args.next() else {
                    print_usage_and_exit();
                };
                ram_size = parse_u64(&v).unwrap_or_else(|| {
                    eprintln!("Invalid --ram-size value: {v}");
                    std::process::exit(1);
                });
            }
            "--bootargs" => {
                bootargs = args.next().unwrap_or_else(|| {
                    eprintln!("Missing --bootargs value");
                    std::process::exit(1);
                });
            }
            "--addr" => {
                addr = args.next().unwrap_or_else(|| {
                    eprintln!("Missing --addr value");
                    std::process::exit(1);
                });
            }
            "--snapshot-dir" => {
                snapshot_dir = args.next().unwrap_or_else(|| {
                    eprintln!("Missing --snapshot-dir value");
                    std::process::exit(1);
                });
            }
            "--chunk-steps" => {
                let Some(v) = args.next() else {
                    print_usage_and_exit();
                };
                chunk_steps = parse_u64(&v).unwrap_or_else(|| {
                    eprintln!("Invalid --chunk-steps value: {v}");
                    std::process::exit(1);
                });
            }
            "--autostart" => {
                autostart = true;
            }
            _ if arg.starts_with("--") => {
                eprintln!("Unknown argument: {arg}");
                print_usage_and_exit();
            }
            _ => positionals.push(arg),
        }
    }

    if snapshot.is_none() {
        if positionals.len() < 2 {
            eprintln!("Need either --snapshot FILE or <kernel> <initrd>");
            print_usage_and_exit();
        }
        kernel = Some(positionals[0].clone());
        initrd = Some(positionals[1].clone());
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
    }
}

fn current_sim_bin() -> Option<PathBuf> {
    if let Ok(v) = env::var("KORISCV_SIM_BIN") {
        return Some(PathBuf::from(v));
    }
    let exe = env::current_exe().ok()?;
    for name in ["koriscv", "riscv_sim"] {
        let mut p = exe.clone();
        p.set_file_name(name);
        if p.exists() {
            return Some(p);
        }
    }
    None
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
    let out = dir.join("boot-initial.kriscv.zst");

    let mut sim_args = vec![
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

    let status = if let Some(bin) = current_sim_bin() {
        Command::new(bin)
            .args(&sim_args)
            .status()
            .map_err(|e| format!("failed to run koriscv: {e}"))?
    } else {
        let mut cargo_args = vec![
            "run".to_string(),
            "--release".to_string(),
            "--bin".to_string(),
            "koriscv".to_string(),
            "--".to_string(),
        ];
        cargo_args.append(&mut sim_args);
        Command::new("cargo")
            .args(&cargo_args)
            .status()
            .map_err(|e| format!("failed to run cargo: {e}"))?
    };
    if !status.success() {
        return Err("failed to build boot snapshot via koriscv".to_string());
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
        if name.contains(".kriscv") {
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
    if path == "/v1/api/snap" {
        let _ = fs::create_dir_all(&st.snapshot_dir);
        let out = format!(
            "{}/snap-{:020}.kriscv.zst",
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

fn handle_connection(mut stream: TcpStream, st: &mut DaemonState) {
    let _ = stream.set_read_timeout(Some(Duration::from_millis(25)));
    let mut buf = [0u8; 8192];
    let n = match stream.read(&mut buf) {
        Ok(0) => return,
        Ok(n) => n,
        Err(_) => return,
    };
    let req = String::from_utf8_lossy(&buf[..n]);
    let first = req.lines().next().unwrap_or_default();
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("/");
    if method != "GET" {
        write_http(stream, 400, "{\"error\":\"GET only\"}", "application/json");
        return;
    }
    let path = target.split('?').next().unwrap_or("/");
    let (code, body, ctype) = handle_path(path, st);
    write_http(stream, code, &body, ctype);
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

fn run_loop(mut st: DaemonState, addr: &str) -> Result<(), String> {
    let listener = TcpListener::bind(addr).map_err(|e| e.to_string())?;
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    let stdin_rx = spawn_stdin_reader();
    eprintln!(
        "{} daemon listening on http://{} (chunk_steps={}, boot_snapshot={})",
        NAME, addr, st.chunk_steps, st.boot_snapshot
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
        }
        loop {
            match listener.accept() {
                Ok((stream, _)) => handle_connection(stream, &mut st),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
        pump_console_input(&mut st, &stdin_rx);
        if st.running {
            std::thread::yield_now();
        } else {
            std::thread::sleep(Duration::from_millis(3));
        }
    }
}

fn main() {
    // Daemon owns stdin-to-UART bridging; keep UART device stdin reader disabled to avoid races.
    std::env::set_var("UART_HOST_STDIN", "0");
    let opts = parse_opts();
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
        boot_snapshot,
        snapshot_dir: opts.snapshot_dir.clone(),
        chunk_steps: opts.chunk_steps.max(1),
        last_error: None,
    };
    if let Err(e) = run_loop(st, &opts.addr) {
        eprintln!("daemon error: {}", e);
        std::process::exit(1);
    }
}
