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

use crate::csr::{CSR_MCAUSE, CSR_MEPC, CSR_MSTATUS, CSR_SATP, CSR_SCAUSE, CSR_SEPC, CSR_SSTATUS};
use crate::system::System;
use std::env;

#[derive(Clone, Debug)]
struct Opts {
    snapshot: String,
    max_steps: u64,
    report_every: u64,
    jit_hot_threshold: u64,
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
        "Usage: korjitdiff --snapshot FILE [--max-steps N] [--report-every N] [--jit-hot-threshold N]"
    );
    std::process::exit(1);
}

fn parse_opts() -> Opts {
    let mut args = env::args().skip(1);
    let mut snapshot: Option<String> = None;
    let mut max_steps = 5_000_000u64;
    let mut report_every = 100_000u64;
    let mut jit_hot_threshold = 8u64;

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
        for &csr in &[
            CSR_SATP,
            CSR_SSTATUS,
            CSR_SEPC,
            CSR_SCAUSE,
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

fn load_system(snapshot: &str, jit: bool, hot_threshold: u64) -> Result<System, String> {
    env::set_var("KOR_JIT_NATIVE", if jit { "1" } else { "0" });
    env::set_var("KOR_JIT_NATIVE_HOT_THRESHOLD", hot_threshold.to_string());
    System::load_snapshot(snapshot)
}

fn main() {
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

    for step in 0..opts.max_steps {
        let pc_ref_before = sys_ref.harts[0].pc;
        let pc_jit_before = sys_jit.harts[0].pc;
        let ins_ref = decode_at_pc(&mut sys_ref, pc_ref_before);
        let ins_jit = decode_at_pc(&mut sys_jit, pc_jit_before);

        let ran_ref = match sys_ref.run(Some(1)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("interpreter run failed at step {}: {:?}", step, e);
                std::process::exit(1);
            }
        };
        let ran_jit = match sys_jit.run(Some(1)) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("jit run failed at step {}: {:?}", step, e);
                std::process::exit(1);
            }
        };

        if ran_ref != ran_jit {
            eprintln!(
                "divergence at step {}: ran ref={} jit={}",
                step, ran_ref, ran_jit
            );
            eprintln!("ref before pc=0x{:016x} {}", pc_ref_before, ins_ref);
            eprintln!("jit before pc=0x{:016x} {}", pc_jit_before, ins_jit);
            std::process::exit(2);
        }

        if let Some(diff) = first_diff(&sys_ref, &sys_jit) {
            eprintln!("divergence at step {}: {}", step, diff);
            eprintln!("ref before pc=0x{:016x} {}", pc_ref_before, ins_ref);
            eprintln!("jit before pc=0x{:016x} {}", pc_jit_before, ins_jit);
            eprintln!(
                "ref after  pc=0x{:016x} jit after pc=0x{:016x}",
                sys_ref.harts[0].pc, sys_jit.harts[0].pc
            );
            std::process::exit(2);
        }

        if opts.report_every != 0 && (step + 1) % opts.report_every == 0 {
            eprintln!(
                "checked {} steps: pc=0x{:016x}",
                step + 1,
                sys_ref.harts[0].pc
            );
        }
    }

    println!(
        "no divergence in {} steps (jit_hot_threshold={})",
        opts.max_steps, opts.jit_hot_threshold
    );
}
