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

use crate::csr::{
    CSR_CYCLE, CSR_INSTRET, CSR_MCAUSE, CSR_MEPC, CSR_MSTATUS, CSR_SATP, CSR_SCAUSE, CSR_SEPC,
    CSR_SSTATUS, CSR_STVAL, CSR_TIME,
};
use crate::system::System;
use std::env;

#[derive(Clone, Debug)]
struct Opts {
    snapshot: String,
    max_steps: u64,
    report_every: u64,
    jit_hot_threshold: u64,
    chunk_steps: u64,
}

fn parse_u64(arg: &str) -> Option<u64> {
    if let Some(hex) = arg.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        arg.parse::<u64>().ok()
    }
}

fn print_usage_and_exit() -> ! {
    eprintln!(
        "Usage: emuko-debug-jitdiff --snapshot FILE [--max-steps N] [--report-every N] [--jit-hot-threshold N] [--chunk-steps N]"
    );
    std::process::exit(1);
}

fn parse_opts() -> Opts {
    let mut args = env::args().skip(1);
    let mut snapshot: Option<String> = None;
    let mut max_steps = 5_000_000u64;
    let mut report_every = 100_000u64;
    let mut jit_hot_threshold = 8u64;
    let mut chunk_steps = 2u64;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--snapshot" => {
                snapshot = args.next();
                if snapshot.is_none() {
                    eprintln!("Missing value for --snapshot");
                    print_usage_and_exit();
                }
            }
            "--max-steps" => {
                let Some(v) = args.next() else {
                    eprintln!("Missing value for --max-steps");
                    print_usage_and_exit();
                };
                max_steps = parse_u64(&v).unwrap_or_else(|| {
                    eprintln!("Invalid --max-steps value: {}", v);
                    std::process::exit(1);
                });
            }
            "--report-every" => {
                let Some(v) = args.next() else {
                    eprintln!("Missing value for --report-every");
                    print_usage_and_exit();
                };
                report_every = parse_u64(&v).unwrap_or_else(|| {
                    eprintln!("Invalid --report-every value: {}", v);
                    std::process::exit(1);
                });
            }
            "--jit-hot-threshold" => {
                let Some(v) = args.next() else {
                    eprintln!("Missing value for --jit-hot-threshold");
                    print_usage_and_exit();
                };
                jit_hot_threshold = parse_u64(&v).unwrap_or_else(|| {
                    eprintln!("Invalid --jit-hot-threshold value: {}", v);
                    std::process::exit(1);
                });
            }
            "--chunk-steps" => {
                let Some(v) = args.next() else {
                    eprintln!("Missing value for --chunk-steps");
                    print_usage_and_exit();
                };
                chunk_steps = parse_u64(&v).unwrap_or_else(|| {
                    eprintln!("Invalid --chunk-steps value: {}", v);
                    std::process::exit(1);
                });
            }
            _ => {
                eprintln!("Unknown argument: {}", arg);
                print_usage_and_exit();
            }
        }
    }

    let Some(snapshot) = snapshot else {
        eprintln!("--snapshot is required");
        print_usage_and_exit();
    };

    Opts {
        snapshot,
        max_steps,
        report_every,
        jit_hot_threshold: jit_hot_threshold.max(1),
        chunk_steps: chunk_steps.max(1),
    }
}

fn decode_at_pc(sys: &mut System, pc: u64) -> String {
    let h16 = {
        let hart = &mut sys.harts[0];
        hart.debug_read_u16_virt(&mut sys.bus, pc)
    };
    match h16 {
        Ok(v16) if (v16 & 0x3) != 0x3 => {
            format!("c16=0x{:04x} {}", v16, disas::disas16(v16))
        }
        Ok(_) => {
            let h32 = {
                let hart = &mut sys.harts[0];
                hart.debug_read_u32_virt(&mut sys.bus, pc)
            };
            match h32 {
                Ok(v32) => format!("i32=0x{:08x} {}", v32, disas::disas32(v32)),
                Err(e) => format!("i32=<fault {:?}>", e),
            }
        }
        Err(e) => format!("fetch=<fault {:?}>", e),
    }
}

#[cfg(unix)]
fn maybe_silence_stdout() {
    if env::var_os("KOR_JITDIFF_KEEP_STDOUT").is_some() {
        return;
    }
    unsafe extern "C" {
        fn dup2(oldfd: i32, newfd: i32) -> i32;
    }
    const STDOUT_FILENO: i32 = 1;
    use std::fs::OpenOptions;
    use std::os::fd::AsRawFd;
    if let Ok(devnull) = OpenOptions::new().write(true).open("/dev/null") {
        unsafe {
            dup2(devnull.as_raw_fd(), STDOUT_FILENO);
        }
    }
}

#[cfg(not(unix))]
fn maybe_silence_stdout() {}

fn print_hart_debug(label: &str, sys: &System) {
    if sys.harts.is_empty() {
        eprintln!("{label}: no harts");
        return;
    }
    let h = &sys.harts[0];
    let snap = h.snapshot();
    eprintln!(
        "{label}: pc=0x{:016x} priv={:?} x1=0x{:016x} x2=0x{:016x} x10=0x{:016x} x11=0x{:016x}",
        h.pc, h.priv_mode, h.regs[1], h.regs[2], h.regs[10], h.regs[11]
    );
    eprintln!(
        "{label}: satp=0x{:016x} sstatus=0x{:016x} sepc=0x{:016x} scause=0x{:016x} stval=0x{:016x}",
        h.csrs.read(CSR_SATP),
        h.csrs.read(CSR_SSTATUS),
        h.csrs.read(CSR_SEPC),
        h.csrs.read(CSR_SCAUSE),
        h.csrs.read(CSR_STVAL),
    );
    eprintln!(
        "{label}: time=0x{:016x} cycle=0x{:016x} instret=0x{:016x} instret_pending=0x{:016x} time_div_accum={}",
        h.csrs.read(CSR_TIME),
        h.csrs.read(CSR_CYCLE),
        h.csrs.read(CSR_INSTRET),
        snap.instret_pending,
        snap.time_div_accum
    );
}

fn first_diff(sys_ref: &System, sys_jit: &System) -> Option<String> {
    if sys_ref.harts.len() != sys_jit.harts.len() {
        return Some(format!(
            "hart-count ref={} jit={}",
            sys_ref.harts.len(),
            sys_jit.harts.len()
        ));
    }
    for i in 0..sys_ref.harts.len() {
        let hr = &sys_ref.harts[i];
        let hj = &sys_jit.harts[i];
        let sr = hr.snapshot();
        let sj = hj.snapshot();
        if hr.pc != hj.pc {
            return Some(format!(
                "hart{} pc ref=0x{:016x} jit=0x{:016x}",
                i, hr.pc, hj.pc
            ));
        }
        if hr.priv_mode != hj.priv_mode {
            return Some(format!(
                "hart{} priv ref={:?} jit={:?}",
                i, hr.priv_mode, hj.priv_mode
            ));
        }
        for r in 0..32usize {
            if hr.regs[r] != hj.regs[r] {
                return Some(format!(
                    "hart{} x{} ref=0x{:016x} jit=0x{:016x}",
                    i, r, hr.regs[r], hj.regs[r]
                ));
            }
        }
        if sr.instret_pending != sj.instret_pending {
            return Some(format!(
                "hart{} instret_pending ref=0x{:016x} jit=0x{:016x}",
                i, sr.instret_pending, sj.instret_pending
            ));
        }
        if sr.time_div_accum != sj.time_div_accum {
            return Some(format!(
                "hart{} time_div_accum ref={} jit={}",
                i, sr.time_div_accum, sj.time_div_accum
            ));
        }
        for &csr in &[
            CSR_TIME,
            CSR_CYCLE,
            CSR_INSTRET,
            CSR_SATP,
            CSR_SSTATUS,
            CSR_SEPC,
            CSR_SCAUSE,
            CSR_STVAL,
            CSR_MSTATUS,
            CSR_MEPC,
            CSR_MCAUSE,
        ] {
            let vr = hr.csrs.read(csr);
            let vj = hj.csrs.read(csr);
            if vr != vj {
                return Some(format!(
                    "hart{} csr[0x{:03x}] ref=0x{:016x} jit=0x{:016x}",
                    i, csr, vr, vj
                ));
            }
        }
    }
    None
}

fn refine_divergence(opts: &Opts, chunk_start: u64, chunk_len: u64) {
    eprintln!(
        "refining divergence window: start={} len={} (chunk_steps={})",
        chunk_start, chunk_len, opts.chunk_steps
    );
    let mut sys_ref = match load_system(&opts.snapshot, false, opts.jit_hot_threshold) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to reload interpreter system for refinement: {}", e);
            return;
        }
    };
    let mut sys_jit = match load_system(&opts.snapshot, true, opts.jit_hot_threshold) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to reload jit system for refinement: {}", e);
            return;
        }
    };

    let mut advanced = 0u64;
    while advanced < chunk_start {
        let step_chunk = opts.chunk_steps.min(chunk_start - advanced).max(1);
        let ran_ref = match sys_ref.run(Some(step_chunk)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "interpreter refinement fast-forward failed at {}: {:?}",
                    advanced, e
                );
                return;
            }
        };
        let ran_jit = match sys_jit.run(Some(step_chunk)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("jit refinement fast-forward failed at {}: {:?}", advanced, e);
                return;
            }
        };
        if ran_ref != ran_jit {
            eprintln!(
                "refinement failed: fast-forward run count mismatch at {} (ref={} jit={})",
                advanced, ran_ref, ran_jit
            );
            return;
        }
        if ran_ref == 0 {
            eprintln!(
                "refinement failed: systems halted during fast-forward at {}",
                advanced
            );
            return;
        }
        advanced = advanced.saturating_add(ran_ref);
        if let Some(diff) = first_diff(&sys_ref, &sys_jit) {
            eprintln!(
                "refinement found earlier divergence during fast-forward at {}: {}",
                advanced, diff
            );
            print_hart_debug("ref-fast", &sys_ref);
            print_hart_debug("jit-fast", &sys_jit);
            return;
        }
    }

    let mut local = 0u64;
    while local < chunk_len {
        let abs_before = chunk_start + local;
        let pc_ref_before = sys_ref.harts[0].pc;
        let pc_jit_before = sys_jit.harts[0].pc;
        let ins_ref = decode_at_pc(&mut sys_ref, pc_ref_before);
        let ins_jit = decode_at_pc(&mut sys_jit, pc_jit_before);

        let ran_ref = match sys_ref.run(Some(1)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!(
                    "interpreter refinement step failed at {}: {:?}",
                    abs_before, e
                );
                return;
            }
        };
        let ran_jit = match sys_jit.run(Some(1)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("jit refinement step failed at {}: {:?}", abs_before, e);
                return;
            }
        };
        if ran_ref != ran_jit {
            eprintln!(
                "first divergence run-count at step {}: ref={} jit={}",
                abs_before, ran_ref, ran_jit
            );
            eprintln!("ref before pc=0x{:016x} {}", pc_ref_before, ins_ref);
            eprintln!("jit before pc=0x{:016x} {}", pc_jit_before, ins_jit);
            print_hart_debug("ref-after", &sys_ref);
            print_hart_debug("jit-after", &sys_jit);
            return;
        }
        if ran_ref == 0 {
            eprintln!("refinement stopped: both halted at step {}", abs_before);
            return;
        }
        let abs_after = abs_before.saturating_add(ran_ref);
        if let Some(diff) = first_diff(&sys_ref, &sys_jit) {
            eprintln!("first divergence state at step {}: {}", abs_after, diff);
            eprintln!("ref before pc=0x{:016x} {}", pc_ref_before, ins_ref);
            eprintln!("jit before pc=0x{:016x} {}", pc_jit_before, ins_jit);
            eprintln!(
                "ref after  pc=0x{:016x} jit after pc=0x{:016x}",
                sys_ref.harts[0].pc, sys_jit.harts[0].pc
            );
            print_hart_debug("ref-after", &sys_ref);
            print_hart_debug("jit-after", &sys_jit);
            return;
        }
        local = local.saturating_add(ran_ref);
    }
    eprintln!(
        "refinement could not isolate within window start={} len={}",
        chunk_start, chunk_len
    );
}

fn load_system(snapshot: &str, jit: bool, hot_threshold: u64) -> Result<System, String> {
    env::set_var("KOR_JIT_NATIVE", if jit { "1" } else { "0" });
    env::set_var("KOR_JIT_NATIVE_HOT_THRESHOLD", hot_threshold.to_string());
    // Keep differential runs deterministic across replays.
    env::set_var("UART_HOST_STDIN", "0");
    env::set_var("UART_POLL_TICKS", "1024");
    System::load_snapshot(snapshot)
}

fn main() {
    maybe_silence_stdout();
    let opts = parse_opts();
    let mut sys_ref = match load_system(&opts.snapshot, false, opts.jit_hot_threshold) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to load interpreter system: {}", e);
            std::process::exit(1);
        }
    };
    let mut sys_jit = match load_system(&opts.snapshot, true, opts.jit_hot_threshold) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to load jit system: {}", e);
            std::process::exit(1);
        }
    };

    let mut checked = 0u64;
    let mut next_report = if opts.report_every == 0 {
        u64::MAX
    } else {
        opts.report_every
    };
    while checked < opts.max_steps {
        let remaining = opts.max_steps.saturating_sub(checked);
        let chunk = opts.chunk_steps.min(remaining).max(1);
        let pc_ref_before = sys_ref.harts[0].pc;
        let pc_jit_before = sys_jit.harts[0].pc;
        let ins_ref = decode_at_pc(&mut sys_ref, pc_ref_before);
        let ins_jit = decode_at_pc(&mut sys_jit, pc_jit_before);

        let ran_ref = match sys_ref.run(Some(chunk)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("interpreter run failed at step {}: {:?}", checked, e);
                std::process::exit(1);
            }
        };
        let ran_jit = match sys_jit.run(Some(chunk)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("jit run failed at step {}: {:?}", checked, e);
                std::process::exit(1);
            }
        };

        if ran_ref != ran_jit {
            eprintln!(
                "divergence at step {}: ran ref={} jit={} (chunk={})",
                checked, ran_ref, ran_jit, chunk
            );
            eprintln!("ref before pc=0x{:016x} {}", pc_ref_before, ins_ref);
            eprintln!("jit before pc=0x{:016x} {}", pc_jit_before, ins_jit);
            refine_divergence(&opts, checked, chunk);
            std::process::exit(2);
        }
        if ran_ref == 0 {
            eprintln!("both systems halted cleanly at step {}", checked);
            return;
        }
        checked = checked.saturating_add(ran_ref);

        if let Some(diff) = first_diff(&sys_ref, &sys_jit) {
            eprintln!("divergence at step {}: {}", checked, diff);
            eprintln!("ref before pc=0x{:016x} {}", pc_ref_before, ins_ref);
            eprintln!("jit before pc=0x{:016x} {}", pc_jit_before, ins_jit);
            eprintln!(
                "ref after  pc=0x{:016x} jit after pc=0x{:016x}",
                sys_ref.harts[0].pc, sys_jit.harts[0].pc
            );
            print_hart_debug("ref-after", &sys_ref);
            print_hart_debug("jit-after", &sys_jit);
            refine_divergence(&opts, checked.saturating_sub(ran_ref), ran_ref);
            std::process::exit(2);
        }

        while checked >= next_report {
            eprintln!(
                "checked {} steps: pc=0x{:016x}",
                checked,
                sys_ref.harts[0].pc
            );
            next_report = next_report.saturating_add(opts.report_every);
        }
    }

    eprintln!(
        "no divergence in {} steps (jit_hot_threshold={}, chunk_steps={})",
        opts.max_steps, opts.jit_hot_threshold, opts.chunk_steps
    );
}
