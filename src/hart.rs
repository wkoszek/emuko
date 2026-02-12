use crate::bus::{AccessType, Bus};
use crate::csr::{
    CsrFile, CsrSnapshot, PrivMode, CSR_MEPC, CSR_SATP, CSR_SCAUSE, CSR_SEPC, CSR_SIE, CSR_SIP,
    CSR_SSTATUS, CSR_STVAL, CSR_STVEC, SIP_SEIP, SIP_SSIP, SIP_STIP, SSTATUS_SIE, SSTATUS_SPIE,
    SSTATUS_SPP,
};
use crate::disas;
use crate::isa::*;
use crate::sbi::Sbi;
use crate::trap::Trap;
use std::collections::HashMap;

pub struct Hart {
    pub regs: [u64; 32],
    pub fregs: [u64; 32],
    pub pc: u64,
    pub hart_id: usize,
    pub priv_mode: PrivMode,
    pub csrs: CsrFile,
    misa_ext: u64,
    reservation: Option<u64>,
    last_access: Option<(AccessType, u64, u64)>,
    trace_instr: Option<u64>,
    trace_disas: bool,
    trace_pc: Option<u64>,
    trace_span: u64,
    trace_pc_left: Option<u64>,
    watch_pc: Option<u64>,
    watch_reg: Option<usize>,
    watch_left: u64,
    watch_pc2: Option<u64>,
    watch_reg2: Option<usize>,
    watch_left2: u64,
    watch_str: bool,
    hotpc_top: usize,
    hotpc_counts: HashMap<u64, u64>,
    trace_pc_zero: bool,
    trace_last: bool,
    trace_last_dumped: bool,
    last_instrs: Vec<(u64, u32, u8)>,
    trace_cjalr: bool,
    ignore_ebreak: bool,
    mmu_trace_addr: Option<u64>,
    mmu_trace_left: u64,
    mmu_idmap_fallback: bool,
}

#[derive(Clone, Debug)]
pub struct HartSnapshot {
    pub regs: [u64; 32],
    pub fregs: [u64; 32],
    pub pc: u64,
    pub hart_id: usize,
    pub priv_mode: PrivMode,
    pub csrs: CsrSnapshot,
    pub misa_ext: u64,
    pub reservation: Option<u64>,
    pub last_access: Option<(AccessType, u64, u64)>,
    pub trace_instr: Option<u64>,
    pub trace_pc_left: Option<u64>,
    pub watch_left: u64,
    pub watch_left2: u64,
    pub mmu_trace_left: u64,
}

impl Hart {
    pub fn new(hart_id: usize, misa_ext: u64) -> Self {
        fn parse_env_u64(name: &str) -> Option<u64> {
            std::env::var(name).ok().and_then(|v| {
                if let Some(hex) = v.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    v.parse::<u64>().ok()
                }
            })
        }
        fn parse_env_reg(name: &str) -> Option<usize> {
            std::env::var(name).ok().and_then(|v| {
                let vv = v.trim();
                let n = vv.strip_prefix('x').unwrap_or(vv);
                n.parse::<usize>().ok().filter(|r| *r < 32)
            })
        }

        let trace_pc = std::env::var("TRACE_PC").ok().and_then(|v| {
            if let Some(hex) = v.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).ok()
            } else {
                v.parse::<u64>().ok()
            }
        });
        let trace_span = std::env::var("TRACE_SPAN")
            .ok()
            .and_then(|v| {
                if let Some(hex) = v.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    v.parse::<u64>().ok()
                }
            })
            .unwrap_or(0x200);
        let trace_pc_left = parse_env_u64("TRACE_PC_LIMIT");
        let watch_pc = parse_env_u64("WATCH_PC");
        let watch_reg = parse_env_reg("WATCH_REG");
        let watch_left = if watch_pc.is_some() {
            parse_env_u64("WATCH_COUNT").unwrap_or(200)
        } else {
            0
        };
        let watch_pc2 = parse_env_u64("WATCH_PC2");
        let watch_reg2 = parse_env_reg("WATCH_REG2");
        let watch_left2 = if watch_pc2.is_some() {
            parse_env_u64("WATCH_COUNT2")
                .or_else(|| parse_env_u64("WATCH_COUNT"))
                .unwrap_or(200)
        } else {
            0
        };
        let watch_str = std::env::var("WATCH_STR").is_ok();
        let hotpc_top = parse_env_u64("TRACE_HOTPC_TOP").unwrap_or(0) as usize;
        let trace_pc_zero = std::env::var("TRACE_PC_ZERO").is_ok();
        let trace_last = std::env::var("TRACE_LAST").is_ok();
        let trace_cjalr = std::env::var("TRACE_CJALR").is_ok();
        let ignore_ebreak = std::env::var("IGNORE_EBREAK").is_ok();
        let mmu_trace_addr = parse_env_u64("TRACE_MMU_ADDR");
        let mmu_trace_left = if mmu_trace_addr.is_some() {
            parse_env_u64("TRACE_MMU_COUNT").unwrap_or(16)
        } else {
            0
        };
        let mmu_idmap_fallback = std::env::var("MMU_IDMAP_FALLBACK").is_ok();
        Self {
            regs: [0; 32],
            fregs: [0; 32],
            pc: 0,
            hart_id,
            priv_mode: PrivMode::Supervisor,
            csrs: CsrFile::new(hart_id, misa_ext),
            misa_ext,
            reservation: None,
            last_access: None,
            trace_instr: None,
            trace_disas: std::env::var("TRACE_DISAS").is_ok(),
            trace_pc,
            trace_span,
            trace_pc_left,
            watch_pc,
            watch_reg,
            watch_left,
            watch_pc2,
            watch_reg2,
            watch_left2,
            watch_str,
            hotpc_top,
            hotpc_counts: HashMap::new(),
            trace_pc_zero,
            trace_last,
            trace_last_dumped: false,
            last_instrs: Vec::new(),
            trace_cjalr,
            ignore_ebreak,
            mmu_trace_addr,
            mmu_trace_left,
            mmu_idmap_fallback,
        }
    }

    #[inline]
    fn watch_hit_slot(watch_pc: Option<u64>, watch_left: &mut u64, pc: u64) -> bool {
        if *watch_left == 0 {
            return false;
        }
        if watch_pc == Some(pc) {
            *watch_left -= 1;
            return true;
        }
        false
    }

    #[inline]
    fn watch_hit(&mut self, pc: u64) -> bool {
        Self::watch_hit_slot(self.watch_pc, &mut self.watch_left, pc)
    }

    #[inline]
    fn watch_hit2(&mut self, pc: u64) -> bool {
        Self::watch_hit_slot(self.watch_pc2, &mut self.watch_left2, pc)
    }

    #[inline]
    fn watch_field(reg: Option<usize>, before: Option<u64>, after: Option<u64>) -> String {
        if let Some(r) = reg {
            format!(
                " x{}:0x{:016x}->0x{:016x}",
                r,
                before.unwrap_or(0),
                after.unwrap_or(0)
            )
        } else {
            String::new()
        }
    }

    fn read_guest_cstr(&mut self, bus: &mut dyn Bus, addr: u64, max_len: usize) -> Option<String> {
        if addr == 0 {
            return None;
        }
        let mut bytes = Vec::new();
        for i in 0..max_len {
            let b = self
                .read_u8(bus, addr.wrapping_add(i as u64), AccessType::Debug)
                .ok()?;
            if b == 0 {
                break;
            }
            bytes.push(if (0x20..=0x7e).contains(&b) { b } else { b'.' });
        }
        if bytes.is_empty() {
            return Some(String::new());
        }
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn watch_cstr_field(
        &mut self,
        bus: &mut dyn Bus,
        reg: Option<usize>,
        ptr: Option<u64>,
    ) -> String {
        if !self.watch_str {
            return String::new();
        }
        let (Some(r), Some(addr)) = (reg, ptr) else {
            return String::new();
        };
        if let Some(s) = self.read_guest_cstr(bus, addr, 96) {
            if s.is_empty() {
                String::new()
            } else {
                format!(" x{}@0x{:016x}=\"{}\"", r, addr, s.escape_default())
            }
        } else {
            String::new()
        }
    }

    pub fn reset(&mut self, pc: u64, sp: u64, gp: u64) {
        self.regs = [0; 32];
        self.fregs = [0; 32];
        self.pc = pc;
        self.reservation = None;
        self.priv_mode = PrivMode::Supervisor;
        self.csrs.reset(self.hart_id, self.misa_ext);
        self.last_access = None;
        self.hotpc_counts.clear();
        self.regs[2] = sp;
        self.regs[3] = gp;
        self.regs[4] = 0;
    }

    pub fn snapshot(&self) -> HartSnapshot {
        HartSnapshot {
            regs: self.regs,
            fregs: self.fregs,
            pc: self.pc,
            hart_id: self.hart_id,
            priv_mode: self.priv_mode,
            csrs: self.csrs.snapshot(),
            misa_ext: self.misa_ext,
            reservation: self.reservation,
            last_access: self.last_access,
            trace_instr: self.trace_instr,
            trace_pc_left: self.trace_pc_left,
            watch_left: self.watch_left,
            watch_left2: self.watch_left2,
            mmu_trace_left: self.mmu_trace_left,
        }
    }

    pub fn from_snapshot(snap: &HartSnapshot) -> Result<Self, &'static str> {
        let mut hart = Self::new(snap.hart_id, snap.misa_ext);
        hart.restore_from_snapshot(snap)?;
        Ok(hart)
    }

    pub fn restore_from_snapshot(&mut self, snap: &HartSnapshot) -> Result<(), &'static str> {
        self.regs = snap.regs;
        self.fregs = snap.fregs;
        self.pc = snap.pc;
        self.hart_id = snap.hart_id;
        self.priv_mode = snap.priv_mode;
        self.csrs.restore(&snap.csrs)?;
        self.misa_ext = snap.misa_ext;
        self.reservation = snap.reservation;
        self.last_access = snap.last_access;
        self.trace_instr = snap.trace_instr;
        self.trace_pc_left = snap.trace_pc_left;
        self.watch_left = snap.watch_left;
        self.watch_left2 = snap.watch_left2;
        self.mmu_trace_left = snap.mmu_trace_left;
        self.hotpc_counts.clear();
        self.last_instrs.clear();
        self.trace_last_dumped = false;
        Ok(())
    }

    pub fn dump_hotpcs(&self) {
        if self.hotpc_top == 0 || self.hotpc_counts.is_empty() {
            return;
        }
        let mut entries: Vec<(u64, u64)> = self
            .hotpc_counts
            .iter()
            .map(|(pc, count)| (*pc, *count))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let top = self.hotpc_top.min(entries.len());
        println!("hotpc hart {} top {}:", self.hart_id, top);
        for (pc, count) in entries.into_iter().take(top) {
            println!("  pc=0x{:016x} count={}", pc, count);
        }
    }

    pub fn set_trace_instr(&mut self, limit: Option<u64>) {
        self.trace_instr = limit;
    }

    pub fn last_access(&self) -> Option<(AccessType, u64, u64)> {
        self.last_access
    }

    pub fn recent_instrs(&self) -> &[(u64, u32, u8)] {
        &self.last_instrs
    }

    fn record_instr(&mut self, pc: u64, instr: u32, len: u8) {
        const MAX: usize = 64;
        if self.last_instrs.len() >= MAX {
            self.last_instrs.remove(0);
        }
        self.last_instrs.push((pc, instr, len));
    }

    #[inline]
    fn check_align(&self, addr: u64, align: u64) -> Result<(), Trap> {
        if addr % align != 0 {
            return Err(Trap::MisalignedAccess { addr, size: align });
        }
        Ok(())
    }

    fn read_phys_u64(&mut self, bus: &mut dyn Bus, addr: u64) -> Result<u64, Trap> {
        bus.read_u64(self.hart_id, addr, AccessType::Debug)
    }

    fn write_phys_u64(&mut self, bus: &mut dyn Bus, addr: u64, value: u64) -> Result<(), Trap> {
        bus.write_u64(self.hart_id, addr, value, AccessType::Debug)
    }

    fn translate_addr(
        &mut self,
        bus: &mut dyn Bus,
        vaddr: u64,
        kind: AccessType,
    ) -> Result<u64, Trap> {
        let mmu_trace = if self.mmu_trace_left > 0 && self.mmu_trace_addr == Some(vaddr) {
            self.mmu_trace_left -= 1;
            true
        } else {
            false
        };
        if mmu_trace {
            eprintln!(
                "mmu: vaddr=0x{:016x} kind={:?} priv={:?} satp=0x{:016x}",
                vaddr,
                kind,
                self.priv_mode,
                self.csrs.read(CSR_SATP)
            );
        }
        if self.priv_mode == PrivMode::Machine {
            if mmu_trace {
                eprintln!("  bypass machine mode -> phys=0x{:016x}", vaddr);
            }
            return Ok(vaddr);
        }

        let satp = self.csrs.read(CSR_SATP);
        let mode = satp >> 60;
        let idmap_fallback =
            self.mmu_idmap_fallback && (0x8000_0000..0x1_0000_0000).contains(&vaddr);
        if mode == 0 {
            if mmu_trace {
                eprintln!("  bare mode -> phys=0x{:016x}", vaddr);
            }
            return Ok(vaddr);
        }

        // Sv39
        if mode != 8 {
            if mmu_trace {
                eprintln!("  unsupported satp mode {}", mode);
            }
            return Err(Trap::PageFault { addr: vaddr, kind });
        }

        let sign = (vaddr >> 38) & 1;
        let upper = vaddr >> 39;
        if (sign == 0 && upper != 0) || (sign == 1 && upper != ((1u64 << 25) - 1)) {
            if mmu_trace {
                eprintln!("  non-canonical address");
            }
            return Err(Trap::PageFault { addr: vaddr, kind });
        }

        let vpn = [
            (vaddr >> 12) & 0x1ff,
            (vaddr >> 21) & 0x1ff,
            (vaddr >> 30) & 0x1ff,
        ];
        let mut a = (satp & ((1u64 << 44) - 1)) << 12;

        for level in (0..=2).rev() {
            let pte_addr = a + vpn[level] * 8;
            let pte = match self.read_phys_u64(bus, pte_addr) {
                Ok(v) => v,
                Err(_) => {
                    if mmu_trace {
                        eprintln!("  l{} pte@0x{:016x} read failed", level, pte_addr);
                    }
                    if idmap_fallback {
                        if mmu_trace {
                            eprintln!("  fallback idmap -> phys=0x{:016x}", vaddr);
                        }
                        return Ok(vaddr);
                    }
                    return Err(Trap::PageFault { addr: vaddr, kind });
                }
            };
            let v = (pte & 0x1) != 0;
            let r = (pte & 0x2) != 0;
            let w = (pte & 0x4) != 0;
            let x = (pte & 0x8) != 0;
            if mmu_trace {
                eprintln!(
                    "  l{} pte@0x{:016x}=0x{:016x} v={} r={} w={} x={}",
                    level, pte_addr, pte, v, r, w, x
                );
            }

            if !v || (!r && w) {
                if mmu_trace {
                    eprintln!("  invalid leaf/non-leaf encoding");
                }
                if idmap_fallback {
                    if mmu_trace {
                        eprintln!("  fallback idmap -> phys=0x{:016x}", vaddr);
                    }
                    return Ok(vaddr);
                }
                return Err(Trap::PageFault { addr: vaddr, kind });
            }

            if r || x {
                // Leaf PTE.
                let allow = match kind {
                    AccessType::Fetch => x,
                    AccessType::Load => r,
                    AccessType::Store => w,
                    AccessType::Debug => true,
                };
                if !allow {
                    if mmu_trace {
                        eprintln!("  permission denied");
                    }
                    return Err(Trap::PageFault { addr: vaddr, kind });
                }

                // Set A/D bits on access.
                let mut new_pte = pte;
                if (pte & (1 << 6)) == 0 {
                    new_pte |= 1 << 6;
                }
                if kind == AccessType::Store && (pte & (1 << 7)) == 0 {
                    new_pte |= 1 << 7;
                }
                if new_pte != pte {
                    let _ = self.write_phys_u64(bus, pte_addr, new_pte);
                }

                let ppn = pte >> 10;
                let page_offset = vaddr & 0xfff;
                let phys = match level {
                    2 => {
                        // 1 GiB superpage: ppn1/ppn0 must be zero.
                        if (ppn & ((1u64 << 18) - 1)) != 0 {
                            if mmu_trace {
                                eprintln!("  bad 1GiB superpage alignment");
                            }
                            return Err(Trap::PageFault { addr: vaddr, kind });
                        }
                        (ppn >> 18) << 30 | (vpn[1] << 21) | (vpn[0] << 12) | page_offset
                    }
                    1 => {
                        // 2 MiB superpage: ppn0 must be zero.
                        if (ppn & ((1u64 << 9) - 1)) != 0 {
                            if mmu_trace {
                                eprintln!("  bad 2MiB superpage alignment");
                            }
                            return Err(Trap::PageFault { addr: vaddr, kind });
                        }
                        (ppn >> 9) << 21 | (vpn[0] << 12) | page_offset
                    }
                    _ => (ppn << 12) | page_offset,
                };
                if mmu_trace {
                    eprintln!("  -> phys=0x{:016x}", phys);
                }
                return Ok(phys);
            }

            a = (pte >> 10) << 12;
        }

        if mmu_trace {
            eprintln!("  walk ended without leaf");
        }
        if idmap_fallback {
            if mmu_trace {
                eprintln!("  fallback idmap -> phys=0x{:016x}", vaddr);
            }
            return Ok(vaddr);
        }
        Err(Trap::PageFault { addr: vaddr, kind })
    }

    #[inline]
    fn read_u8(&mut self, bus: &mut dyn Bus, addr: u64, kind: AccessType) -> Result<u8, Trap> {
        self.last_access = Some((kind, addr, 1));
        let paddr = self.translate_addr(bus, addr, kind)?;
        let res = bus.read_u8(self.hart_id, paddr, kind);
        if res.is_ok() {
            self.last_access = None;
        }
        res
    }

    #[inline]
    fn read_u16(&mut self, bus: &mut dyn Bus, addr: u64, kind: AccessType) -> Result<u16, Trap> {
        self.last_access = Some((kind, addr, 2));
        self.check_align(addr, 2)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        let res = bus.read_u16(self.hart_id, paddr, kind);
        if res.is_ok() {
            self.last_access = None;
        }
        res
    }

    #[inline]
    fn read_u32(&mut self, bus: &mut dyn Bus, addr: u64, kind: AccessType) -> Result<u32, Trap> {
        self.last_access = Some((kind, addr, 4));
        self.check_align(addr, 4)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        let res = bus.read_u32(self.hart_id, paddr, kind);
        if res.is_ok() {
            self.last_access = None;
        }
        res
    }

    #[inline]
    #[allow(dead_code)]
    fn read_u64(&mut self, bus: &mut dyn Bus, addr: u64, kind: AccessType) -> Result<u64, Trap> {
        self.last_access = Some((kind, addr, 8));
        self.check_align(addr, 8)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        let res = bus.read_u64(self.hart_id, paddr, kind);
        if res.is_ok() {
            self.last_access = None;
        }
        res
    }

    #[inline]
    fn write_u8(
        &mut self,
        bus: &mut dyn Bus,
        addr: u64,
        val: u8,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.last_access = Some((kind, addr, 1));
        let paddr = self.translate_addr(bus, addr, kind)?;
        let res = bus.write_u8(self.hart_id, paddr, val, kind);
        if res.is_ok() {
            self.last_access = None;
        }
        res
    }

    #[inline]
    fn write_u16(
        &mut self,
        bus: &mut dyn Bus,
        addr: u64,
        val: u16,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.last_access = Some((kind, addr, 2));
        self.check_align(addr, 2)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        let res = bus.write_u16(self.hart_id, paddr, val, kind);
        if res.is_ok() {
            self.last_access = None;
        }
        res
    }

    #[inline]
    fn write_u32(
        &mut self,
        bus: &mut dyn Bus,
        addr: u64,
        val: u32,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.last_access = Some((kind, addr, 4));
        self.check_align(addr, 4)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        let res = bus.write_u32(self.hart_id, paddr, val, kind);
        if res.is_ok() {
            self.last_access = None;
        }
        res
    }

    #[inline]
    #[allow(dead_code)]
    fn write_u64(
        &mut self,
        bus: &mut dyn Bus,
        addr: u64,
        val: u64,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.last_access = Some((kind, addr, 8));
        self.check_align(addr, 8)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        let res = bus.write_u64(self.hart_id, paddr, val, kind);
        if res.is_ok() {
            self.last_access = None;
        }
        res
    }

    #[inline]
    fn sign_extend(val: u64, bits: u32) -> i64 {
        let shift = 64 - bits;
        ((val << shift) as i64) >> shift
    }

    #[inline]
    fn imm_i(instr: u32) -> i64 {
        Self::sign_extend((instr >> 20) as u64, 12)
    }

    #[inline]
    fn imm_s(instr: u32) -> i64 {
        let imm = ((instr >> 25) << 5) | ((instr >> 7) & 0x1f);
        Self::sign_extend(imm as u64, 12)
    }

    #[inline]
    fn imm_b(instr: u32) -> i64 {
        let bit12 = (instr >> 31) & 0x1;
        let bit11 = (instr >> 7) & 0x1;
        let bits10_5 = (instr >> 25) & 0x3f;
        let bits4_1 = (instr >> 8) & 0x0f;
        let imm = (bit12 << 12) | (bit11 << 11) | (bits10_5 << 5) | (bits4_1 << 1);
        Self::sign_extend(imm as u64, 13)
    }

    #[inline]
    fn imm_u(instr: u32) -> i64 {
        Self::sign_extend((instr & 0xfffff000) as u64, 32)
    }

    #[inline]
    fn imm_j(instr: u32) -> i64 {
        let bit20 = (instr >> 31) & 0x1;
        let bits19_12 = (instr >> 12) & 0xff;
        let bit11 = (instr >> 20) & 0x1;
        let bits10_1 = (instr >> 21) & 0x3ff;
        let imm = (bit20 << 20) | (bits19_12 << 12) | (bit11 << 11) | (bits10_1 << 1);
        Self::sign_extend(imm as u64, 21)
    }

    fn pending_interrupt(&self) -> Option<u64> {
        let sstatus = self.csrs.read(CSR_SSTATUS);
        if (sstatus & SSTATUS_SIE) == 0 {
            return None;
        }
        let sie = self.csrs.read(CSR_SIE);
        let sip = self.csrs.read(CSR_SIP);
        let pending = sip & sie & (SIP_SSIP | SIP_STIP | SIP_SEIP);
        if (pending & SIP_SSIP) != 0 {
            return Some(1);
        }
        if (pending & SIP_STIP) != 0 {
            return Some(5);
        }
        if (pending & SIP_SEIP) != 0 {
            return Some(9);
        }
        None
    }

    fn take_trap(&mut self, cause: u64, tval: u64) {
        let stvec = self.csrs.read(CSR_STVEC);
        let mode = stvec & 0x3;
        let base = stvec & !0x3;

        let mut sstatus = self.csrs.read(CSR_SSTATUS);
        let sie = sstatus & SSTATUS_SIE;
        if sie != 0 {
            sstatus |= SSTATUS_SPIE;
        } else {
            sstatus &= !SSTATUS_SPIE;
        }
        sstatus &= !SSTATUS_SIE;
        sstatus = (sstatus & !SSTATUS_SPP) | ((self.priv_mode as u64) << 8);
        self.csrs.write(CSR_SSTATUS, sstatus);

        self.csrs.write(CSR_SEPC, self.pc);
        self.csrs.write(CSR_SCAUSE, cause);
        self.csrs.write(CSR_STVAL, tval);
        self.priv_mode = PrivMode::Supervisor;

        let next_pc = if mode == 1 {
            base.wrapping_add(4 * (cause & 0xfff))
        } else {
            base
        };
        if self.trace_pc_zero && next_pc == 0 {
            eprintln!(
                "pc->0 via trap: pc=0x{:016x} cause=0x{:x} tval=0x{:016x} stvec=0x{:016x}",
                self.pc, cause, tval, stvec
            );
        }
        self.pc = next_pc;
        self.last_access = None;
    }

    pub fn handle_trap(&mut self, trap: Trap) {
        if self.trace_last && !self.trace_last_dumped {
            eprintln!("last instrs:");
            for (pc, instr, len) in &self.last_instrs {
                if *len == 2 {
                    eprintln!("  pc=0x{:016x} c16=0x{:04x}", pc, instr & 0xffff);
                } else {
                    eprintln!("  pc=0x{:016x} i32=0x{:08x}", pc, instr);
                }
            }
            self.trace_last_dumped = true;
        }
        let (kind, _addr, _size) = self.last_access.unwrap_or((AccessType::Fetch, self.pc, 4));
        match trap {
            Trap::IllegalInstruction(instr) => {
                self.take_trap(2, instr as u64);
            }
            Trap::Ebreak => {
                self.take_trap(3, self.pc);
            }
            Trap::Ecall => {
                let cause = match self.priv_mode {
                    PrivMode::User => 8,
                    PrivMode::Supervisor => 9,
                    PrivMode::Machine => 11,
                };
                self.take_trap(cause, 0);
            }
            Trap::PageFault { addr, kind } => {
                let cause = match kind {
                    AccessType::Fetch => 12,
                    AccessType::Load => 13,
                    AccessType::Store => 15,
                    AccessType::Debug => 13,
                };
                self.take_trap(cause, addr);
            }
            Trap::MisalignedAccess { addr, .. } => {
                let cause = match kind {
                    AccessType::Fetch => 0,
                    AccessType::Load => 4,
                    AccessType::Store => 6,
                    AccessType::Debug => 0,
                };
                self.take_trap(cause, addr);
            }
            Trap::MemoryOutOfBounds { addr, .. } => {
                let cause = match kind {
                    AccessType::Fetch => 1,
                    AccessType::Load => 5,
                    AccessType::Store => 7,
                    AccessType::Debug => 1,
                };
                self.take_trap(cause, addr);
            }
        }
    }

    pub fn step(&mut self, bus: &mut dyn Bus, sbi: &mut dyn Sbi) -> Result<(), Trap> {
        if self.hotpc_top != 0 {
            *self.hotpc_counts.entry(self.pc).or_insert(0) += 1;
        }
        if let Some(code) = self.pending_interrupt() {
            let cause = (1u64 << 63) | code;
            self.take_trap(cause, 0);
            return Ok(());
        }

        self.check_align(self.pc, 2)?;
        let instr16 = self.read_u16(bus, self.pc, AccessType::Fetch)?;
        if (instr16 & 0x3) != 0x3 {
            self.record_instr(self.pc, instr16 as u32, 2);
            let pc_before = self.pc;
            let watch_hit = self.watch_hit(self.pc);
            let watch_reg = self.watch_reg;
            let watch_before = watch_reg.map(|r| self.regs[r]);
            let watch_hit2 = self.watch_hit2(self.pc);
            let watch_reg2 = self.watch_reg2;
            let watch_before2 = watch_reg2.map(|r| self.regs[r]);
            let trace_window = self.trace_pc.map_or(false, |start| {
                self.pc >= start && self.pc < start.saturating_add(self.trace_span)
            });
            if trace_window {
                let should_print = match self.trace_pc_left.as_mut() {
                    Some(left) => {
                        if *left == 0 {
                            false
                        } else {
                            *left -= 1;
                            true
                        }
                    }
                    None => true,
                };
                if should_print {
                    if self.trace_disas {
                        eprintln!(
                            "instr pc=0x{:016x} c16=0x{:04x} {}",
                            self.pc,
                            instr16,
                            disas::disas16(instr16)
                        );
                    } else {
                        eprintln!("instr pc=0x{:016x} c16=0x{:04x}", self.pc, instr16);
                    }
                }
            } else if let Some(left) = self.trace_instr.as_mut() {
                if *left > 0 {
                    if self.trace_disas {
                        eprintln!(
                            "instr pc=0x{:016x} c16=0x{:04x} {}",
                            self.pc,
                            instr16,
                            disas::disas16(instr16)
                        );
                    } else {
                        eprintln!("instr pc=0x{:016x} c16=0x{:04x}", self.pc, instr16);
                    }
                    *left -= 1;
                }
            }
            let res = self.exec_compressed(bus, instr16);
            if watch_hit {
                let watch_after = watch_reg.map(|r| self.regs[r]);
                let watch_field = Self::watch_field(watch_reg, watch_before, watch_after);
                let watch_cstr = self.watch_cstr_field(bus, watch_reg, watch_after);
                match res {
                    Ok(()) => {
                        eprintln!(
                            "watch1 pc=0x{:016x} c16=0x{:04x} {} ra=0x{:016x} sp=0x{:016x} -> next_pc=0x{:016x}{}{}",
                            pc_before,
                            instr16,
                            disas::disas16(instr16),
                            self.regs[1],
                            self.regs[2],
                            self.pc,
                            watch_field,
                            watch_cstr
                        );
                    }
                    Err(ref trap) => {
                        eprintln!(
                            "watch1 pc=0x{:016x} c16=0x{:04x} {} trap={:?}{}{}",
                            pc_before,
                            instr16,
                            disas::disas16(instr16),
                            trap,
                            watch_field,
                            watch_cstr
                        );
                    }
                }
            }
            if watch_hit2 {
                let watch_after2 = watch_reg2.map(|r| self.regs[r]);
                let watch_field2 = Self::watch_field(watch_reg2, watch_before2, watch_after2);
                let watch_cstr2 = self.watch_cstr_field(bus, watch_reg2, watch_after2);
                match res {
                    Ok(()) => {
                        eprintln!(
                            "watch2 pc=0x{:016x} c16=0x{:04x} {} ra=0x{:016x} sp=0x{:016x} -> next_pc=0x{:016x}{}{}",
                            pc_before,
                            instr16,
                            disas::disas16(instr16),
                            self.regs[1],
                            self.regs[2],
                            self.pc,
                            watch_field2,
                            watch_cstr2
                        );
                    }
                    Err(ref trap) => {
                        eprintln!(
                            "watch2 pc=0x{:016x} c16=0x{:04x} {} trap={:?}{}{}",
                            pc_before,
                            instr16,
                            disas::disas16(instr16),
                            trap,
                            watch_field2,
                            watch_cstr2
                        );
                    }
                }
            }
            return res;
        }
        let upper = self.read_u16(bus, self.pc.wrapping_add(2), AccessType::Fetch)? as u32;
        let instr = (upper << 16) | (instr16 as u32);
        self.record_instr(self.pc, instr, 4);
        let trace_window = self.trace_pc.map_or(false, |start| {
            self.pc >= start && self.pc < start.saturating_add(self.trace_span)
        });
        if trace_window {
            let should_print = match self.trace_pc_left.as_mut() {
                Some(left) => {
                    if *left == 0 {
                        false
                    } else {
                        *left -= 1;
                        true
                    }
                }
                None => true,
            };
            if should_print {
                if self.trace_disas {
                    eprintln!(
                        "instr pc=0x{:016x} i32=0x{:08x} {}",
                        self.pc,
                        instr,
                        disas::disas32(instr)
                    );
                } else {
                    eprintln!("instr pc=0x{:016x} i32=0x{:08x}", self.pc, instr);
                }
            }
        } else if let Some(left) = self.trace_instr.as_mut() {
            if *left > 0 {
                if self.trace_disas {
                    eprintln!(
                        "instr pc=0x{:016x} i32=0x{:08x} {}",
                        self.pc,
                        instr,
                        disas::disas32(instr)
                    );
                } else {
                    eprintln!("instr pc=0x{:016x} i32=0x{:08x}", self.pc, instr);
                }
                *left -= 1;
            }
        }
        let opcode = instr & 0x7f;

        let rd = ((instr >> 7) & 0x1f) as usize;
        let funct3 = (instr >> 12) & 0x7;
        let rs1 = ((instr >> 15) & 0x1f) as usize;
        let rs2 = ((instr >> 20) & 0x1f) as usize;
        let funct7 = (instr >> 25) & 0x7f;
        let funct5 = (instr >> 27) & 0x1f;
        let pc_before = self.pc;
        let watch_hit = self.watch_hit(self.pc);
        let watch_reg = self.watch_reg;
        let watch_before = watch_reg.map(|r| self.regs[r]);
        let watch_hit2 = self.watch_hit2(self.pc);
        let watch_reg2 = self.watch_reg2;
        let watch_before2 = watch_reg2.map(|r| self.regs[r]);
        let rs1_before = self.regs[rs1];
        let rs2_before = self.regs[rs2];
        let rd_before = self.regs[rd];

        let mut next_pc = self.pc.wrapping_add(4);

        match opcode {
            OPCODE_LUI => {
                self.regs[rd] = Self::imm_u(instr) as u64;
            }
            OPCODE_AUIPC => {
                self.regs[rd] = self.pc.wrapping_add(Self::imm_u(instr) as u64);
            }
            OPCODE_JAL => {
                let imm = Self::imm_j(instr) as u64;
                self.regs[rd] = next_pc;
                next_pc = self.pc.wrapping_add(imm);
            }
            OPCODE_JALR => {
                let imm = Self::imm_i(instr) as u64;
                let target = self.regs[rs1].wrapping_add(imm) & !1;
                self.regs[rd] = next_pc;
                next_pc = target;
            }
            OPCODE_BRANCH => {
                let imm = Self::imm_b(instr) as u64;
                let a = self.regs[rs1];
                let b = self.regs[rs2];
                let take = match funct3 {
                    F3_BEQ => a == b,
                    F3_BNE => a != b,
                    F3_BLT => (a as i64) < (b as i64),
                    F3_BGE => (a as i64) >= (b as i64),
                    F3_BLTU => a < b,
                    F3_BGEU => a >= b,
                    _ => return Err(Trap::IllegalInstruction(instr)),
                };
                if take {
                    next_pc = self.pc.wrapping_add(imm);
                }
            }
            OPCODE_LOAD => {
                let imm = Self::imm_i(instr) as u64;
                let addr = self.regs[rs1].wrapping_add(imm);
                let val = match funct3 {
                    F3_LB => self.read_u8(bus, addr, AccessType::Load)? as i8 as i64 as u64,
                    F3_LH => self.read_u16(bus, addr, AccessType::Load)? as i16 as i64 as u64,
                    F3_LW => self.read_u32(bus, addr, AccessType::Load)? as i32 as i64 as u64,
                    F3_LD => self.read_u64(bus, addr, AccessType::Load)?,
                    F3_LBU => self.read_u8(bus, addr, AccessType::Load)? as u64,
                    F3_LHU => self.read_u16(bus, addr, AccessType::Load)? as u64,
                    F3_LWU => self.read_u32(bus, addr, AccessType::Load)? as u64,
                    _ => return Err(Trap::IllegalInstruction(instr)),
                };
                self.regs[rd] = val;
            }
            OPCODE_LOAD_FP => {
                let imm = Self::imm_i(instr) as u64;
                let addr = self.regs[rs1].wrapping_add(imm);
                match funct3 {
                    2 => {
                        // FLW
                        let val = self.read_u32(bus, addr, AccessType::Load)?;
                        self.fregs[rd] = val as u64;
                    }
                    3 => {
                        // FLD
                        let val = self.read_u64(bus, addr, AccessType::Load)?;
                        self.fregs[rd] = val;
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                }
            }
            OPCODE_STORE => {
                let imm = Self::imm_s(instr) as u64;
                let addr = self.regs[rs1].wrapping_add(imm);
                let val = self.regs[rs2];
                match funct3 {
                    F3_SB => self.write_u8(bus, addr, val as u8, AccessType::Store)?,
                    F3_SH => self.write_u16(bus, addr, val as u16, AccessType::Store)?,
                    F3_SW => self.write_u32(bus, addr, val as u32, AccessType::Store)?,
                    F3_SD => self.write_u64(bus, addr, val, AccessType::Store)?,
                    _ => return Err(Trap::IllegalInstruction(instr)),
                }
            }
            OPCODE_STORE_FP => {
                let imm = Self::imm_s(instr) as u64;
                let addr = self.regs[rs1].wrapping_add(imm);
                match funct3 {
                    2 => {
                        // FSW
                        let val = self.fregs[rs2] as u32;
                        self.write_u32(bus, addr, val, AccessType::Store)?;
                    }
                    3 => {
                        // FSD
                        let val = self.fregs[rs2];
                        self.write_u64(bus, addr, val, AccessType::Store)?;
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                }
            }
            OPCODE_OP_IMM => {
                let imm = Self::imm_i(instr) as u64;
                let imm12 = (instr >> 20) & 0xfff;
                let shamt = (imm12 & 0x3f) as u32;
                let imm_hi = (imm12 >> 6) & 0x3f;
                let a = self.regs[rs1];
                let res = match funct3 {
                    F3_ADD_SUB => a.wrapping_add(imm),
                    F3_SLL => {
                        if imm_hi != 0 {
                            return Err(Trap::IllegalInstruction(instr));
                        }
                        a << shamt
                    }
                    F3_SLT => ((a as i64) < (imm as i64)) as u64,
                    F3_SLTU => (a < imm) as u64,
                    F3_XOR => a ^ imm,
                    F3_SRL_SRA => match imm_hi {
                        0x00 => a >> shamt,
                        0x10 => ((a as i64) >> shamt) as u64,
                        _ => return Err(Trap::IllegalInstruction(instr)),
                    },
                    F3_OR => a | imm,
                    F3_AND => a & imm,
                    _ => return Err(Trap::IllegalInstruction(instr)),
                };
                self.regs[rd] = res;
            }
            OPCODE_OP => {
                let a = self.regs[rs1];
                let b = self.regs[rs2];
                let res = match (funct7, funct3) {
                    (F7_BASE, F3_ADD_SUB) => a.wrapping_add(b),
                    (F7_SUB_SRA, F3_ADD_SUB) => a.wrapping_sub(b),
                    (F7_BASE, F3_SLL) => a << (b & 0x3f),
                    (F7_BASE, F3_SLT) => ((a as i64) < (b as i64)) as u64,
                    (F7_BASE, F3_SLTU) => (a < b) as u64,
                    (F7_BASE, F3_XOR) => a ^ b,
                    (F7_BASE, F3_SRL_SRA) => a >> (b & 0x3f),
                    (F7_SUB_SRA, F3_SRL_SRA) => ((a as i64) >> (b & 0x3f)) as u64,
                    (F7_BASE, F3_OR) => a | b,
                    (F7_BASE, F3_AND) => a & b,

                    // RV64M (partial; MULH variants computed via 128-bit)
                    (F7_MULDIV, F3_ADD_SUB) => a.wrapping_mul(b),
                    (F7_MULDIV, F3_SLL) => {
                        let prod = (a as i128).wrapping_mul(b as i128);
                        (prod >> 64) as u64
                    }
                    (F7_MULDIV, F3_SLT) => {
                        let prod = (a as i128).wrapping_mul(b as u128 as i128);
                        (prod >> 64) as u64
                    }
                    (F7_MULDIV, F3_SLTU) => {
                        let prod = (a as u128).wrapping_mul(b as u128);
                        (prod >> 64) as u64
                    }
                    (F7_MULDIV, F3_XOR) => {
                        let dividend = a as i64;
                        let divisor = b as i64;
                        if divisor == 0 {
                            u64::MAX
                        } else if dividend == i64::MIN && divisor == -1 {
                            dividend as u64
                        } else {
                            (dividend / divisor) as u64
                        }
                    }
                    (F7_MULDIV, F3_SRL_SRA) => {
                        if b == 0 {
                            u64::MAX
                        } else {
                            a / b
                        }
                    }
                    (F7_MULDIV, F3_OR) => {
                        let dividend = a as i64;
                        let divisor = b as i64;
                        if divisor == 0 {
                            a
                        } else if dividend == i64::MIN && divisor == -1 {
                            0
                        } else {
                            (dividend % divisor) as u64
                        }
                    }
                    (F7_MULDIV, F3_AND) => {
                        if b == 0 {
                            a
                        } else {
                            a % b
                        }
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                };
                self.regs[rd] = res;
            }
            OPCODE_OP_IMM_32 => {
                let imm = Self::imm_i(instr) as i64;
                let shamt = ((instr >> 20) & 0x1f) as u32;
                let a = self.regs[rs1] as i64;
                let res32 = match funct3 {
                    F3_ADD_SUB => (a.wrapping_add(imm)) as i32,
                    F3_SLL => {
                        if funct7 != F7_BASE {
                            return Err(Trap::IllegalInstruction(instr));
                        }
                        ((a as i32) << shamt) as i32
                    }
                    F3_SRL_SRA => {
                        if funct7 == F7_SUB_SRA {
                            ((a as i32) >> shamt) as i32
                        } else if funct7 == F7_BASE {
                            ((a as u32) >> shamt) as i32
                        } else {
                            return Err(Trap::IllegalInstruction(instr));
                        }
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                };
                self.regs[rd] = res32 as i64 as u64;
            }
            OPCODE_OP_32 => {
                let a = self.regs[rs1] as i64;
                let b = self.regs[rs2] as i64;
                let res32 = match (funct7, funct3) {
                    (F7_BASE, F3_ADD_SUB) => (a.wrapping_add(b)) as i32,
                    (F7_SUB_SRA, F3_ADD_SUB) => (a.wrapping_sub(b)) as i32,
                    (F7_BASE, F3_SLL) => ((a as i32) << (b as u32 & 0x1f)) as i32,
                    (F7_BASE, F3_SRL_SRA) => ((a as u32) >> (b as u32 & 0x1f)) as i32,
                    (F7_SUB_SRA, F3_SRL_SRA) => ((a as i32) >> (b as u32 & 0x1f)) as i32,
                    (F7_MULDIV, F3_ADD_SUB) => ((a as i32).wrapping_mul(b as i32)) as i32,
                    (F7_MULDIV, F3_XOR) => {
                        let dividend = a as i32;
                        let divisor = b as i32;
                        if divisor == 0 {
                            -1i32
                        } else if dividend == i32::MIN && divisor == -1 {
                            dividend
                        } else {
                            dividend / divisor
                        }
                    }
                    (F7_MULDIV, F3_SRL_SRA) => {
                        let dividend = a as u32;
                        let divisor = b as u32;
                        if divisor == 0 {
                            u32::MAX as i32
                        } else {
                            (dividend / divisor) as i32
                        }
                    }
                    (F7_MULDIV, F3_OR) => {
                        let dividend = a as i32;
                        let divisor = b as i32;
                        if divisor == 0 {
                            dividend
                        } else if dividend == i32::MIN && divisor == -1 {
                            0
                        } else {
                            dividend % divisor
                        }
                    }
                    (F7_MULDIV, F3_AND) => {
                        let dividend = a as u32;
                        let divisor = b as u32;
                        if divisor == 0 {
                            dividend as i32
                        } else {
                            (dividend % divisor) as i32
                        }
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                };
                self.regs[rd] = res32 as i64 as u64;
            }
            OPCODE_SYSTEM => {
                let csr_addr = ((instr >> 20) & 0xfff) as u16;
                match funct3 {
                    F3_SYSTEM => {
                        let imm12 = (instr >> 20) & 0xfff;
                        match imm12 {
                            IMM_ECALL => {
                                if self.priv_mode == PrivMode::Supervisor {
                                    if sbi.handle_ecall(self, bus)? {
                                        // handled by virtual SBI
                                    } else {
                                        return Err(Trap::Ecall);
                                    }
                                } else {
                                    return Err(Trap::Ecall);
                                }
                            }
                            IMM_EBREAK => {
                                if !self.ignore_ebreak {
                                    return Err(Trap::Ebreak);
                                }
                            }
                            IMM_SRET => {
                                let mut sstatus = self.csrs.read(CSR_SSTATUS);
                                let spie = (sstatus & SSTATUS_SPIE) != 0;
                                if spie {
                                    sstatus |= SSTATUS_SIE;
                                } else {
                                    sstatus &= !SSTATUS_SIE;
                                }
                                sstatus |= SSTATUS_SPIE;
                                let spp = (sstatus & SSTATUS_SPP) != 0;
                                sstatus &= !SSTATUS_SPP;
                                self.csrs.write(CSR_SSTATUS, sstatus);
                                self.priv_mode = if spp {
                                    PrivMode::Supervisor
                                } else {
                                    PrivMode::User
                                };
                                next_pc = self.csrs.read(CSR_SEPC);
                            }
                            IMM_MRET => {
                                next_pc = self.csrs.read(CSR_MEPC);
                            }
                            IMM_WFI => {
                                // No-op for now.
                            }
                            _ => {
                                // SFENCE.VMA and other priv ops: treat as no-op for now.
                            }
                        }
                    }
                    F3_CSRRW | F3_CSRRS | F3_CSRRC | F3_CSRRWI | F3_CSRRSI | F3_CSRRCI => {
                        let zimm = rs1 as u64;
                        let old = self.csrs.read(csr_addr);
                        let mut new_val = old;
                        let mut do_write = true;
                        match funct3 {
                            F3_CSRRW => {
                                new_val = self.regs[rs1];
                            }
                            F3_CSRRS => {
                                if rs1 == 0 {
                                    do_write = false;
                                } else {
                                    new_val = old | self.regs[rs1];
                                }
                            }
                            F3_CSRRC => {
                                if rs1 == 0 {
                                    do_write = false;
                                } else {
                                    new_val = old & !self.regs[rs1];
                                }
                            }
                            F3_CSRRWI => {
                                new_val = zimm;
                            }
                            F3_CSRRSI => {
                                if zimm == 0 {
                                    do_write = false;
                                } else {
                                    new_val = old | zimm;
                                }
                            }
                            F3_CSRRCI => {
                                if zimm == 0 {
                                    do_write = false;
                                } else {
                                    new_val = old & !zimm;
                                }
                            }
                            _ => {}
                        }
                        if rd != 0 {
                            self.regs[rd] = old;
                        }
                        if do_write {
                            self.csrs.write(csr_addr, new_val);
                        }
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                }
            }
            OPCODE_AMO => {
                let addr = self.regs[rs1];
                match funct3 {
                    F3_AMO_W => {
                        let rs2_val = self.regs[rs2] as u32;
                        match funct5 {
                            F5_LR => {
                                let val = self.read_u32(bus, addr, AccessType::Load)?;
                                self.regs[rd] = (val as i32) as i64 as u64;
                                self.reservation = Some(addr);
                            }
                            F5_SC => {
                                let success = self.reservation == Some(addr);
                                if success {
                                    self.write_u32(bus, addr, rs2_val, AccessType::Store)?;
                                    self.regs[rd] = 0;
                                } else {
                                    self.regs[rd] = 1;
                                }
                                self.reservation = None;
                            }
                            F5_AMOSWAP => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                self.write_u32(bus, addr, rs2_val, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOADD => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = old.wrapping_add(rs2_val);
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOAND => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = old & rs2_val;
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOOR => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = old | rs2_val;
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOXOR => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = old ^ rs2_val;
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOMAX => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = if (old as i32) > (rs2_val as i32) {
                                    old
                                } else {
                                    rs2_val
                                };
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOMIN => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = if (old as i32) < (rs2_val as i32) {
                                    old
                                } else {
                                    rs2_val
                                };
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOMAXU => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = if old > rs2_val { old } else { rs2_val };
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOMINU => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = if old < rs2_val { old } else { rs2_val };
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            _ => return Err(Trap::IllegalInstruction(instr)),
                        }
                    }
                    F3_AMO_D => {
                        let rs2_val = self.regs[rs2];
                        match funct5 {
                            F5_LR => {
                                let val = self.read_u64(bus, addr, AccessType::Load)?;
                                self.regs[rd] = val;
                                self.reservation = Some(addr);
                            }
                            F5_SC => {
                                let success = self.reservation == Some(addr);
                                if success {
                                    self.write_u64(bus, addr, rs2_val, AccessType::Store)?;
                                    self.regs[rd] = 0;
                                } else {
                                    self.regs[rd] = 1;
                                }
                                self.reservation = None;
                            }
                            F5_AMOSWAP => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                self.write_u64(bus, addr, rs2_val, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOADD => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = old.wrapping_add(rs2_val);
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOAND => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = old & rs2_val;
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOOR => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = old | rs2_val;
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOXOR => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = old ^ rs2_val;
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOMAX => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = if (old as i64) > (rs2_val as i64) {
                                    old
                                } else {
                                    rs2_val
                                };
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOMIN => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = if (old as i64) < (rs2_val as i64) {
                                    old
                                } else {
                                    rs2_val
                                };
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOMAXU => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = if old > rs2_val { old } else { rs2_val };
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOMINU => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = if old < rs2_val { old } else { rs2_val };
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            _ => return Err(Trap::IllegalInstruction(instr)),
                        }
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                }
            }
            OPCODE_MISC_MEM => {
                match funct3 {
                    F3_FENCE | F3_FENCE_I => {
                        // No-op for now.
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                }
            }
            _ => return Err(Trap::IllegalInstruction(instr)),
        }

        if self.trace_pc_zero && next_pc == 0 {
            eprintln!(
                "pc->0: pc=0x{:016x} instr=0x{:08x} ra=0x{:016x}",
                self.pc, instr, self.regs[1]
            );
        }
        if self.trace_pc_zero && next_pc == 0 {
            eprintln!(
                "pc->0: pc=0x{:016x} instr=0x{:04x} ra=0x{:016x}",
                self.pc, instr, self.regs[1]
            );
        }
        if watch_hit {
            let rd_after = if rd == 0 { 0 } else { self.regs[rd] };
            let watch_after = watch_reg.map(|r| if r == 0 { 0 } else { self.regs[r] });
            let watch_field = Self::watch_field(watch_reg, watch_before, watch_after);
            let watch_cstr = self.watch_cstr_field(bus, watch_reg, watch_after);
            eprintln!(
                "watch1 pc=0x{:016x} i32=0x{:08x} {} rs1=x{}:0x{:016x} rs2=x{}:0x{:016x} rd=x{}:0x{:016x}->0x{:016x} next_pc=0x{:016x}{}{}",
                pc_before,
                instr,
                disas::disas32(instr),
                rs1,
                rs1_before,
                rs2,
                rs2_before,
                rd,
                rd_before,
                rd_after,
                next_pc,
                watch_field,
                watch_cstr
            );
        }
        if watch_hit2 {
            let rd_after = if rd == 0 { 0 } else { self.regs[rd] };
            let watch_after2 = watch_reg2.map(|r| if r == 0 { 0 } else { self.regs[r] });
            let watch_field2 = Self::watch_field(watch_reg2, watch_before2, watch_after2);
            let watch_cstr2 = self.watch_cstr_field(bus, watch_reg2, watch_after2);
            eprintln!(
                "watch2 pc=0x{:016x} i32=0x{:08x} {} rs1=x{}:0x{:016x} rs2=x{}:0x{:016x} rd=x{}:0x{:016x}->0x{:016x} next_pc=0x{:016x}{}{}",
                pc_before,
                instr,
                disas::disas32(instr),
                rs1,
                rs1_before,
                rs2,
                rs2_before,
                rd,
                rd_before,
                rd_after,
                next_pc,
                watch_field2,
                watch_cstr2
            );
        }
        self.pc = next_pc;
        self.regs[0] = 0;
        self.csrs.increment_instret();
        Ok(())
    }

    fn exec_compressed(&mut self, bus: &mut dyn Bus, instr: u16) -> Result<(), Trap> {
        let funct3 = (instr >> 13) & 0x7;
        let op = instr & 0x3;
        let mut next_pc = self.pc.wrapping_add(2);

        let rd = ((instr >> 7) & 0x1f) as usize;
        let rs2 = ((instr >> 2) & 0x1f) as usize;
        let rd_prime = (((instr >> 2) & 0x7) + 8) as usize;
        let rs1_prime = (((instr >> 7) & 0x7) + 8) as usize;
        let rs2_prime = (((instr >> 2) & 0x7) + 8) as usize;

        let imm_ci = || {
            let imm = (((instr >> 12) & 0x1) << 5) | ((instr >> 2) & 0x1f);
            Self::sign_extend(imm as u64, 6) as u64
        };

        match op {
            0b00 => {
                match funct3 {
                    0b000 => {
                        // C.ADDI4SPN
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 9)
                            | (((instr >> 9) & 0x1) << 8)
                            | (((instr >> 8) & 0x1) << 7)
                            | (((instr >> 7) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 2)
                            | (((instr >> 5) & 0x1) << 3);
                        if imm == 0 {
                            return Err(Trap::IllegalInstruction(instr as u32));
                        }
                        self.regs[rd_prime] = self.regs[2].wrapping_add(imm as u64);
                    }
                    0b001 => {
                        // C.FLD (RV64)
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 5) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 7);
                        let addr = self.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = self.read_u64(bus, addr, AccessType::Load)?;
                        self.fregs[rd_prime] = val;
                    }
                    0b010 => {
                        // C.LW
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 6) & 0x1) << 2)
                            | (((instr >> 5) & 0x1) << 6);
                        let addr = self.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = self.read_u32(bus, addr, AccessType::Load)? as i32 as i64 as u64;
                        self.regs[rd_prime] = val;
                    }
                    0b011 => {
                        // C.LD (RV64)
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 5) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 7);
                        let addr = self.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = self.read_u64(bus, addr, AccessType::Load)?;
                        self.regs[rd_prime] = val;
                    }
                    0b101 => {
                        // C.FSD (RV64)
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 5) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 7);
                        let addr = self.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = self.fregs[rs2_prime];
                        self.write_u64(bus, addr, val, AccessType::Store)?;
                    }
                    0b110 => {
                        // C.SW
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 6) & 0x1) << 2)
                            | (((instr >> 5) & 0x1) << 6);
                        let addr = self.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = self.regs[rs2_prime] as u32;
                        self.write_u32(bus, addr, val, AccessType::Store)?;
                    }
                    0b111 => {
                        // C.SD (RV64)
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 5) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 7);
                        let addr = self.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = self.regs[rs2_prime];
                        self.write_u64(bus, addr, val, AccessType::Store)?;
                    }
                    _ => return Err(Trap::IllegalInstruction(instr as u32)),
                }
            }
            0b01 => {
                match funct3 {
                    0b000 => {
                        // C.ADDI / C.NOP
                        if rd != 0 {
                            let imm = imm_ci();
                            self.regs[rd] = self.regs[rd].wrapping_add(imm);
                        }
                    }
                    0b001 => {
                        // C.ADDIW (RV64)
                        if rd == 0 {
                            return Err(Trap::IllegalInstruction(instr as u32));
                        }
                        let imm = imm_ci() as i64;
                        let res = (self.regs[rd] as i64).wrapping_add(imm) as i32;
                        self.regs[rd] = res as i64 as u64;
                    }
                    0b010 => {
                        // C.LI
                        if rd != 0 {
                            self.regs[rd] = imm_ci();
                        }
                    }
                    0b011 => {
                        if rd == 2 {
                            // C.ADDI16SP
                            let imm = (((instr >> 12) & 0x1) << 9)
                                | (((instr >> 6) & 0x1) << 4)
                                | (((instr >> 5) & 0x1) << 6)
                                | (((instr >> 4) & 0x1) << 8)
                                | (((instr >> 3) & 0x1) << 7)
                                | (((instr >> 2) & 0x1) << 5);
                            let imm = Self::sign_extend(imm as u64, 10) as u64;
                            if imm == 0 {
                                return Err(Trap::IllegalInstruction(instr as u32));
                            }
                            self.regs[2] = self.regs[2].wrapping_add(imm);
                        } else {
                            // C.LUI
                            if rd == 0 {
                                return Err(Trap::IllegalInstruction(instr as u32));
                            }
                            let imm = imm_ci();
                            if imm == 0 {
                                return Err(Trap::IllegalInstruction(instr as u32));
                            }
                            self.regs[rd] = ((imm as i64) << 12) as u64;
                        }
                    }
                    0b100 => {
                        let funct2 = (instr >> 10) & 0x3;
                        match funct2 {
                            0b00 => {
                                // C.SRLI
                                let shamt = (((instr >> 12) & 0x1) << 5) | ((instr >> 2) & 0x1f);
                                let rd = rs1_prime;
                                self.regs[rd] >>= shamt;
                            }
                            0b01 => {
                                // C.SRAI
                                let shamt = (((instr >> 12) & 0x1) << 5) | ((instr >> 2) & 0x1f);
                                let rd = rs1_prime;
                                self.regs[rd] = ((self.regs[rd] as i64) >> shamt) as u64;
                            }
                            0b10 => {
                                // C.ANDI
                                let imm = imm_ci() as i64 as u64;
                                let rd = rs1_prime;
                                self.regs[rd] &= imm;
                            }
                            0b11 => {
                                let rd = rs1_prime;
                                let rs2 = rs2_prime;
                                let subop = (instr >> 12) & 0x1;
                                let funct2 = (instr >> 5) & 0x3;
                                match (subop, funct2) {
                                    (0, 0b00) => {
                                        self.regs[rd] = self.regs[rd].wrapping_sub(self.regs[rs2])
                                    } // C.SUB
                                    (0, 0b01) => self.regs[rd] ^= self.regs[rs2], // C.XOR
                                    (0, 0b10) => self.regs[rd] |= self.regs[rs2], // C.OR
                                    (0, 0b11) => self.regs[rd] &= self.regs[rs2], // C.AND
                                    (1, 0b00) => {
                                        // C.SUBW
                                        let a = self.regs[rd] as i64;
                                        let b = self.regs[rs2] as i64;
                                        self.regs[rd] = (a.wrapping_sub(b) as i32) as i64 as u64;
                                    }
                                    (1, 0b01) => {
                                        // C.ADDW
                                        let a = self.regs[rd] as i64;
                                        let b = self.regs[rs2] as i64;
                                        self.regs[rd] = (a.wrapping_add(b) as i32) as i64 as u64;
                                    }
                                    _ => return Err(Trap::IllegalInstruction(instr as u32)),
                                }
                            }
                            _ => return Err(Trap::IllegalInstruction(instr as u32)),
                        }
                    }
                    0b101 => {
                        // C.J
                        let imm = (((instr >> 12) & 0x1) << 11)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 9)
                            | (((instr >> 9) & 0x1) << 8)
                            | (((instr >> 8) & 0x1) << 10)
                            | (((instr >> 7) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 7)
                            | (((instr >> 5) & 0x1) << 3)
                            | (((instr >> 4) & 0x1) << 2)
                            | (((instr >> 3) & 0x1) << 1)
                            | (((instr >> 2) & 0x1) << 5);
                        let imm = Self::sign_extend(imm as u64, 12) as u64;
                        next_pc = self.pc.wrapping_add(imm);
                    }
                    0b110 | 0b111 => {
                        // C.BEQZ / C.BNEZ
                        let imm = (((instr >> 12) & 0x1) << 8)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 3)
                            | (((instr >> 6) & 0x1) << 7)
                            | (((instr >> 5) & 0x1) << 6)
                            | (((instr >> 4) & 0x1) << 2)
                            | (((instr >> 3) & 0x1) << 1)
                            | (((instr >> 2) & 0x1) << 5);
                        let imm = Self::sign_extend(imm as u64, 9) as u64;
                        let rs1 = rs1_prime;
                        let take = if funct3 == 0b110 {
                            self.regs[rs1] == 0
                        } else {
                            self.regs[rs1] != 0
                        };
                        if take {
                            next_pc = self.pc.wrapping_add(imm);
                        }
                    }
                    _ => return Err(Trap::IllegalInstruction(instr as u32)),
                }
            }
            0b10 => {
                match funct3 {
                    0b000 => {
                        // C.SLLI
                        if rd == 0 {
                            return Err(Trap::IllegalInstruction(instr as u32));
                        }
                        let shamt = (((instr >> 12) & 0x1) << 5) | ((instr >> 2) & 0x1f);
                        self.regs[rd] = self.regs[rd] << shamt;
                    }
                    0b001 => {
                        // C.FLDSP (RV64)
                        if rd == 0 {
                            return Err(Trap::IllegalInstruction(instr as u32));
                        }
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 6) & 0x1) << 4)
                            | (((instr >> 5) & 0x1) << 3)
                            | (((instr >> 4) & 0x1) << 8)
                            | (((instr >> 3) & 0x1) << 7)
                            | (((instr >> 2) & 0x1) << 6);
                        let addr = self.regs[2].wrapping_add(imm as u64);
                        let val = self.read_u64(bus, addr, AccessType::Load)?;
                        self.fregs[rd] = val;
                    }
                    0b010 => {
                        // C.LWSP
                        if rd == 0 {
                            return Err(Trap::IllegalInstruction(instr as u32));
                        }
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 6) & 0x1) << 4)
                            | (((instr >> 5) & 0x1) << 3)
                            | (((instr >> 4) & 0x1) << 2)
                            | (((instr >> 3) & 0x1) << 7)
                            | (((instr >> 2) & 0x1) << 6);
                        let addr = self.regs[2].wrapping_add(imm as u64);
                        let val = self.read_u32(bus, addr, AccessType::Load)? as i32 as i64 as u64;
                        self.regs[rd] = val;
                    }
                    0b011 => {
                        // C.LDSP
                        if rd == 0 {
                            return Err(Trap::IllegalInstruction(instr as u32));
                        }
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 6) & 0x1) << 4)
                            | (((instr >> 5) & 0x1) << 3)
                            | (((instr >> 4) & 0x1) << 8)
                            | (((instr >> 3) & 0x1) << 7)
                            | (((instr >> 2) & 0x1) << 6);
                        let addr = self.regs[2].wrapping_add(imm as u64);
                        let val = self.read_u64(bus, addr, AccessType::Load)?;
                        self.regs[rd] = val;
                    }
                    0b100 => {
                        let bit12 = (instr >> 12) & 0x1;
                        if bit12 == 0 {
                            if rs2 == 0 {
                                // C.JR
                                if rd == 0 {
                                    return Err(Trap::IllegalInstruction(instr as u32));
                                }
                                next_pc = self.regs[rd] & !1;
                            } else {
                                // C.MV
                                if rd == 0 {
                                    return Err(Trap::IllegalInstruction(instr as u32));
                                }
                                self.regs[rd] = self.regs[rs2];
                            }
                        } else {
                            if rs2 == 0 {
                                if rd == 0 {
                                    // C.EBREAK
                                    if !self.ignore_ebreak {
                                        return Err(Trap::Ebreak);
                                    }
                                }
                                // C.JALR
                                let target = self.regs[rd] & !1;
                                if self.trace_cjalr {
                                    eprintln!(
                                        "c.jalr pc=0x{:016x} rd={} target=0x{:016x} a0=0x{:016x} a1=0x{:016x} a2=0x{:016x} a3=0x{:016x} a4=0x{:016x}",
                                        self.pc,
                                        rd,
                                        target,
                                        self.regs[10],
                                        self.regs[11],
                                        self.regs[12],
                                        self.regs[13],
                                        self.regs[14]
                                    );
                                }
                                self.regs[1] = self.pc.wrapping_add(2);
                                next_pc = target;
                            } else {
                                // C.ADD
                                if rd == 0 {
                                    return Err(Trap::IllegalInstruction(instr as u32));
                                }
                                self.regs[rd] = self.regs[rd].wrapping_add(self.regs[rs2]);
                            }
                        }
                    }
                    0b110 => {
                        // C.SWSP
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 3)
                            | (((instr >> 9) & 0x1) << 2)
                            | (((instr >> 8) & 0x1) << 7)
                            | (((instr >> 7) & 0x1) << 6);
                        let addr = self.regs[2].wrapping_add(imm as u64);
                        let val = self.regs[rs2] as u32;
                        self.write_u32(bus, addr, val, AccessType::Store)?;
                    }
                    0b111 => {
                        // C.SDSP
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 3)
                            | (((instr >> 9) & 0x1) << 8)
                            | (((instr >> 8) & 0x1) << 7)
                            | (((instr >> 7) & 0x1) << 6);
                        let addr = self.regs[2].wrapping_add(imm as u64);
                        let val = self.regs[rs2];
                        self.write_u64(bus, addr, val, AccessType::Store)?;
                    }
                    0b101 => {
                        // C.FSDSP (RV64)
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 3)
                            | (((instr >> 9) & 0x1) << 8)
                            | (((instr >> 8) & 0x1) << 7)
                            | (((instr >> 7) & 0x1) << 6);
                        let addr = self.regs[2].wrapping_add(imm as u64);
                        let val = self.fregs[rs2];
                        self.write_u64(bus, addr, val, AccessType::Store)?;
                    }
                    _ => return Err(Trap::IllegalInstruction(instr as u32)),
                }
            }
            _ => return Err(Trap::IllegalInstruction(instr as u32)),
        }

        self.pc = next_pc;
        self.regs[0] = 0;
        self.csrs.increment_instret();
        Ok(())
    }
}
