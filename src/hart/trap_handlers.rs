use super::*;

impl Hart {
    pub(super) fn pending_interrupt(&self) -> Option<u64> {
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

    pub(super) fn take_trap(&mut self, cause: u64, tval: u64) {
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
}
