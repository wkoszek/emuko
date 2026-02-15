use super::*;

impl Hart {
    pub fn native_jit_enabled(&self) -> bool {
        self.native_jit.enabled
    }

    pub fn reset(&mut self, pc: u64, sp: u64, gp: u64) {
        self.regs = [0; 32];
        self.fregs = [0; 32];
        self.pc = pc;
        self.reservation = None;
        self.instret_pending = 0;
        self.priv_mode = PrivMode::Supervisor;
        self.csrs.reset(self.hart_id, self.misa_ext);
        self.last_access = None;
        self.hotpc_counts.clear();
        self.flush_tlb();
        self.flush_decode_cache();
        self.irq_check_countdown = self.irq_check_stride;
        self.time_div_accum = 0;
        self.satp_cached = self.csrs.read(CSR_SATP);
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
            instret_pending: self.instret_pending,
            last_access: self.last_access,
            trace_instr: self.trace_instr,
            trace_pc_left: self.trace_pc_left,
            watch_left: self.watch_left,
            watch_left2: self.watch_left2,
            mmu_trace_left: self.mmu_trace_left,
            time_div_accum: self.time_div_accum,
            time_jitter_state: self.time_jitter_state,
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
        self.instret_pending = snap.instret_pending;
        self.last_access = snap.last_access;
        self.trace_instr = snap.trace_instr;
        self.trace_pc_left = snap.trace_pc_left;
        self.watch_left = snap.watch_left;
        self.watch_left2 = snap.watch_left2;
        self.mmu_trace_left = snap.mmu_trace_left;
        self.time_div_accum = snap.time_div_accum % self.time_divider;
        self.time_jitter_state = if snap.time_jitter_state == 0 {
            1
        } else {
            snap.time_jitter_state
        };
        self.hotpc_counts.clear();
        self.last_instrs.clear();
        self.trace_last_dumped = false;
        self.flush_tlb();
        self.flush_decode_cache();
        self.irq_check_countdown = self.irq_check_stride;
        self.satp_cached = self.csrs.read(CSR_SATP);
        Ok(())
    }

    pub fn set_satp(&mut self, val: u64) {
        self.csrs.write(CSR_SATP, val);
        self.satp_cached = self.csrs.read(CSR_SATP);
        self.flush_tlb();
    }

    #[inline]
    pub(super) fn commit_instret(&mut self) {
        if self.instret_pending != 0 {
            self.csrs.increment_instret_n(self.instret_pending);
            self.instret_pending = 0;
        }
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

    #[allow(dead_code)]
    pub fn recent_instrs(&self) -> &[(u64, u32, u8)] {
        &self.last_instrs
    }

    pub(super) fn record_instr(&mut self, pc: u64, instr: u32, len: u8) {
        if !self.trace_last {
            return;
        }
        const MAX: usize = 64;
        if self.last_instrs.len() >= MAX {
            self.last_instrs.remove(0);
        }
        self.last_instrs.push((pc, instr, len));
    }
}
