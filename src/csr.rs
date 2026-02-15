#![allow(dead_code)]

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivMode {
    User = 0,
    Supervisor = 1,
    Machine = 3,
}

pub const CSR_SSTATUS: u16 = 0x100;
pub const CSR_SIE: u16 = 0x104;
pub const CSR_STVEC: u16 = 0x105;
pub const CSR_SCOUNTEREN: u16 = 0x106;
pub const CSR_SSCRATCH: u16 = 0x140;
pub const CSR_SEPC: u16 = 0x141;
pub const CSR_SCAUSE: u16 = 0x142;
pub const CSR_STVAL: u16 = 0x143;
pub const CSR_SIP: u16 = 0x144;
pub const CSR_SATP: u16 = 0x180;

pub const CSR_MSTATUS: u16 = 0x300;
pub const CSR_MISA: u16 = 0x301;
pub const CSR_MEDELEG: u16 = 0x302;
pub const CSR_MIDELEG: u16 = 0x303;
pub const CSR_MIE: u16 = 0x304;
pub const CSR_MTVEC: u16 = 0x305;
pub const CSR_MSCRATCH: u16 = 0x340;
pub const CSR_MEPC: u16 = 0x341;
pub const CSR_MCAUSE: u16 = 0x342;
pub const CSR_MTVAL: u16 = 0x343;
pub const CSR_MIP: u16 = 0x344;

pub const CSR_MHARTID: u16 = 0xF14;

pub const CSR_CYCLE: u16 = 0xC00;
pub const CSR_TIME: u16 = 0xC01;
pub const CSR_INSTRET: u16 = 0xC02;

pub const SSTATUS_SIE: u64 = 1 << 1;
pub const SSTATUS_SPIE: u64 = 1 << 5;
pub const SSTATUS_SPP: u64 = 1 << 8;

pub const SIE_SSIE: u64 = 1 << 1;
pub const SIE_STIE: u64 = 1 << 5;
pub const SIE_SEIE: u64 = 1 << 9;

pub const SIP_SSIP: u64 = 1 << 1;
pub const SIP_STIP: u64 = 1 << 5;
pub const SIP_SEIP: u64 = 1 << 9;

pub struct CsrFile {
    regs: [u64; 4096],
}

#[derive(Clone, Debug)]
pub struct CsrSnapshot {
    pub regs: Vec<u64>,
}

impl CsrFile {
    pub fn new(hart_id: usize, ext_mask: u64) -> Self {
        let mut regs = [0u64; 4096];
        regs[CSR_MHARTID as usize] = hart_id as u64;
        regs[CSR_MISA as usize] = Self::compose_misa(ext_mask);

        Self { regs }
    }

    pub fn reset(&mut self, hart_id: usize, ext_mask: u64) {
        self.regs = [0u64; 4096];
        self.regs[CSR_MHARTID as usize] = hart_id as u64;
        self.regs[CSR_MISA as usize] = Self::compose_misa(ext_mask);
    }

    pub fn read(&self, csr: u16) -> u64 {
        self.regs[csr as usize]
    }

    pub fn write(&mut self, csr: u16, value: u64) {
        // Read-only CSR range: top two bits 11 (e.g. cycle/time/instret).
        if (csr & 0xC00) == 0xC00 {
            return;
        }
        if csr == CSR_SEPC || csr == CSR_MEPC {
            // xepc is WARL: bit 0 is always zero. If IALIGN=32 (no C
            // extension), bit 1 is also forced to zero.
            let has_c = ((self.regs[CSR_MISA as usize] >> 2) & 1) != 0;
            let align_mask = if has_c { !1u64 } else { !3u64 };
            self.regs[csr as usize] = value & align_mask;
            return;
        }
        if csr == CSR_SATP {
            let mode = value >> 60;
            // satp.MODE is WARL. This core currently supports only Bare (0)
            // and Sv39 (8). Ignore writes with unsupported modes (e.g. Sv48/Sv57)
            // so software probing does not leave the hart in an unusable mode.
            if mode != 0 && mode != 8 {
                return;
            }
        }
        self.regs[csr as usize] = value;
    }

    pub fn set_time(&mut self, time: u64) {
        self.regs[CSR_TIME as usize] = time;
        self.regs[CSR_CYCLE as usize] = time;
    }

    #[inline]
    pub fn increment_time(&mut self, delta: u64) {
        let time = self.regs[CSR_TIME as usize].wrapping_add(delta);
        self.regs[CSR_TIME as usize] = time;
        self.regs[CSR_CYCLE as usize] = time;
    }

    pub fn increment_instret(&mut self) {
        let val = self.regs[CSR_INSTRET as usize].wrapping_add(1);
        self.regs[CSR_INSTRET as usize] = val;
    }

    #[inline]
    pub fn increment_instret_n(&mut self, delta: u64) {
        if delta == 0 {
            return;
        }
        let val = self.regs[CSR_INSTRET as usize].wrapping_add(delta);
        self.regs[CSR_INSTRET as usize] = val;
    }

    pub fn set_misa_extensions(&mut self, ext_mask: u64) {
        self.regs[CSR_MISA as usize] = Self::compose_misa(ext_mask);
    }

    fn compose_misa(ext_mask: u64) -> u64 {
        let mut misa = 0u64;
        misa |= 2u64 << 62; // MXL=2 for RV64
        misa |= ext_mask;
        misa
    }

    pub fn snapshot(&self) -> CsrSnapshot {
        CsrSnapshot {
            regs: self.regs.to_vec(),
        }
    }

    pub fn restore(&mut self, snap: &CsrSnapshot) -> Result<(), &'static str> {
        if snap.regs.len() != self.regs.len() {
            return Err("CSR file size mismatch");
        }
        self.regs.copy_from_slice(&snap.regs);
        Ok(())
    }
}
