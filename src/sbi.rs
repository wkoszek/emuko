use crate::clint::ClintState;
use crate::efi::{EfiState, EFI_EID};
use crate::hart::Hart;
use crate::trap::Trap;
use std::collections::BTreeMap;
use std::cell::RefCell;
use std::rc::Rc;

pub trait Sbi {
    fn handle_ecall(&mut self, hart: &mut Hart, bus: &mut dyn crate::bus::Bus) -> Result<bool, Trap>;
    fn tick(&mut self, cycles: u64);
    fn time(&self) -> u64;
    fn timer_due(&self, hart_id: usize) -> bool;
    fn shutdown_requested(&self) -> bool;
    fn dump_stats(&self);
}

pub struct VirtualSbi {
    clint: Rc<RefCell<ClintState>>,
    shutdown: bool,
    efi: Option<EfiState>,
    trace: bool,
    trace_efi_unsupported: bool,
    force_stip: bool,
    ecall_counts: BTreeMap<(u64, u64), u64>,
}

impl VirtualSbi {
    pub fn new(clint: Rc<RefCell<ClintState>>) -> Self {
        Self {
            clint,
            shutdown: false,
            efi: None,
            trace: std::env::var("SBI_TRACE").is_ok(),
            trace_efi_unsupported: std::env::var("SBI_TRACE_EFI_UNSUPPORTED").is_ok(),
            force_stip: std::env::var("FORCE_STIP").is_ok(),
            ecall_counts: BTreeMap::new(),
        }
    }

    pub fn configure_efi(&mut self, efi: EfiState) {
        self.efi = Some(efi);
    }
}

const SBI_EXT_BASE: u64 = 0x10;
const SBI_EXT_TIME: u64 = 0x5449_4D45; // "TIME"
const SBI_EXT_SRST: u64 = 0x5352_5354; // "SRST"
const SBI_EXT_IPI: u64 = 0x0073_5049; // "sPI"

const SBI_BASE_GET_SPEC_VERSION: u64 = 0;
const SBI_BASE_GET_IMPL_ID: u64 = 1;
const SBI_BASE_GET_IMPL_VERSION: u64 = 2;
const SBI_BASE_PROBE_EXT: u64 = 3;
const SBI_BASE_GET_MVENDORID: u64 = 4;
const SBI_BASE_GET_MARCHID: u64 = 5;
const SBI_BASE_GET_MIMPID: u64 = 6;

const SBI_LEGACY_SET_TIMER: u64 = 0;
const SBI_LEGACY_CONSOLE_PUTCHAR: u64 = 1;
const SBI_LEGACY_CONSOLE_GETCHAR: u64 = 2;
const SBI_LEGACY_SHUTDOWN: u64 = 8;
const SBI_LEGACY_SEND_IPI: u64 = 4;

impl Sbi for VirtualSbi {
    fn handle_ecall(&mut self, hart: &mut Hart, bus: &mut dyn crate::bus::Bus) -> Result<bool, Trap> {
        let a0 = hart.regs[10];
        let a1 = hart.regs[11];
        let a2 = hart.regs[12];
        let a6 = hart.regs[16];
        let a7 = hart.regs[17];
        let key = if a7 < SBI_EXT_BASE { (0, a7) } else { (a7, a6) };
        *self.ecall_counts.entry(key).or_insert(0) += 1;
        if self.trace || (self.trace_efi_unsupported && a7 == EFI_EID && a6 == 0x7ff) {
            eprintln!(
                "SBI ecall hart={} pc=0x{:016x} eid=0x{:x} fid=0x{:x} a0=0x{:016x} a1=0x{:016x} a2=0x{:016x}",
                hart.hart_id, hart.pc, a7, a6, a0, a1, a2
            );
        }

        // Legacy SBI: a7 is the call ID.
        if a7 < SBI_EXT_BASE {
            match a7 {
                SBI_LEGACY_SET_TIMER => {
                    if let Some(cmp) = self.clint.borrow_mut().mtimecmp.get_mut(hart.hart_id) {
                        *cmp = a0;
                    }
                    hart.regs[10] = 0;
                    return Ok(true);
                }
                SBI_LEGACY_CONSOLE_PUTCHAR => {
                    let ch = a0 as u8;
                    print!("{}", ch as char);
                    hart.regs[10] = 0;
                    return Ok(true);
                }
                SBI_LEGACY_CONSOLE_GETCHAR => {
                    hart.regs[10] = u64::MAX; // -1
                    return Ok(true);
                }
                SBI_LEGACY_SEND_IPI => {
                    let mask = a0;
                    for hart_id in 0..self.clint.borrow().msip.len() {
                        if (mask & (1u64 << hart_id)) != 0 {
                            self.clint.borrow_mut().set_msip(hart_id, true);
                        }
                    }
                    hart.regs[10] = 0;
                    return Ok(true);
                }
                SBI_LEGACY_SHUTDOWN => {
                    self.shutdown = true;
                    hart.regs[10] = 0;
                    return Ok(true);
                }
                _ => {
                    hart.regs[10] = u64::MAX;
                    return Ok(true);
                }
            }
        }

        let eid = a7;
        let fid = a6;

        let mut err = 0u64;
        let mut val = 0u64;

        match eid {
            EFI_EID => {
                if let Some(efi) = self.efi.as_mut() {
                    efi.handle_ecall(fid, hart, bus)?;
                    return Ok(true);
                } else {
                    err = u64::MAX;
                }
            }
            SBI_EXT_BASE => match fid {
                SBI_BASE_GET_SPEC_VERSION => {
                    val = 0x0000_0002; // v0.2
                }
                SBI_BASE_GET_IMPL_ID => {
                    val = 0;
                }
                SBI_BASE_GET_IMPL_VERSION => {
                    val = 0;
                }
                SBI_BASE_PROBE_EXT => {
                    val = match a0 {
                        SBI_EXT_BASE | SBI_EXT_TIME | SBI_EXT_IPI | SBI_EXT_SRST => 1,
                        _ => 0,
                    };
                }
                SBI_BASE_GET_MVENDORID => {
                    val = 0;
                }
                SBI_BASE_GET_MARCHID => {
                    val = 0;
                }
                SBI_BASE_GET_MIMPID => {
                    val = 0;
                }
                _ => {
                    err = u64::MAX;
                }
            },
            SBI_EXT_TIME => match fid {
                0 => {
                    if let Some(cmp) = self.clint.borrow_mut().mtimecmp.get_mut(hart.hart_id) {
                        *cmp = a0;
                    }
                }
                _ => {
                    err = u64::MAX;
                }
            },
            SBI_EXT_IPI => match fid {
                0 => {
                    let mask = a0;
                    for hart_id in 0..self.clint.borrow().msip.len() {
                        if (mask & (1u64 << hart_id)) != 0 {
                            self.clint.borrow_mut().set_msip(hart_id, true);
                        }
                    }
                }
                _ => {
                    err = u64::MAX;
                }
            },
            SBI_EXT_SRST => match fid {
                0 => {
                    let _reset_type = a0;
                    let _reset_reason = a1;
                    let _ = a2;
                    self.shutdown = true;
                }
                _ => {
                    err = u64::MAX;
                }
            },
            _ => {
                err = u64::MAX;
            }
        }

        hart.regs[10] = err;
        hart.regs[11] = val;
        Ok(true)
    }

    fn tick(&mut self, cycles: u64) {
        self.clint.borrow_mut().tick(cycles);
    }

    fn time(&self) -> u64 {
        self.clint.borrow().mtime
    }

    fn timer_due(&self, hart_id: usize) -> bool {
        self.force_stip || self.clint.borrow().timer_due(hart_id)
    }

    fn shutdown_requested(&self) -> bool {
        self.shutdown
    }

    fn dump_stats(&self) {
        if self.ecall_counts.is_empty() {
            println!("sbi calls: none");
            return;
        }
        println!("sbi calls:");
        for ((eid, fid), count) in &self.ecall_counts {
            if *eid == 0 {
                println!("  legacy id=0x{:x} count={}", fid, count);
            } else {
                println!("  eid=0x{:x} fid=0x{:x} count={}", eid, fid, count);
            }
        }
    }
}
