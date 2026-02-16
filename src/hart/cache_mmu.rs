use super::*;

impl Hart {
    pub(super) fn flush_tlb(&mut self) {
        self.tlb.fill(None);
        self.fast_tlb_fetch = None;
        self.fast_tlb_load = None;
        self.fast_tlb_store = None;
        self.native_jit.clear();
    }

    #[inline]
    pub(super) fn flush_decode_cache(&mut self) {
        self.decode_cache.fill(None);
    }

    #[inline]
    pub(super) fn tlb_index(satp: u64, vpage: u64) -> usize {
        let mixed = vpage ^ satp ^ satp.rotate_right(17) ^ vpage.rotate_left(13) ^ (vpage >> 7);
        (mixed as usize) & (TLB_CACHE_SIZE - 1)
    }

    #[inline]
    pub(super) fn decode_cache_index(satp: u64, pc: u64) -> usize {
        let _ = satp;
        ((pc >> 2) as usize) & (DECODE_CACHE_SIZE - 1)
    }

    #[inline]
    pub(super) fn tlb_allow(kind: AccessType, perms: u8) -> bool {
        match kind {
            AccessType::Fetch => (perms & TLB_PERM_X) != 0,
            AccessType::Load => (perms & TLB_PERM_R) != 0,
            AccessType::Store => (perms & TLB_PERM_W) != 0,
            AccessType::Debug => true,
        }
    }

    #[inline]
    pub(super) fn tlb_lookup(&self, kind: AccessType, satp: u64, vpage: u64) -> Option<u64> {
        if matches!(kind, AccessType::Debug) {
            return None;
        }
        let idx = Self::tlb_index(satp, vpage);
        let entry = self.tlb[idx]?;
        if entry.vpage == vpage && Self::tlb_allow(kind, entry.perms) {
            Some(entry.ppage)
        } else {
            None
        }
    }

    #[inline]
    pub(super) fn fast_tlb_lookup(&self, kind: AccessType, satp: u64, vpage: u64) -> Option<u64> {
        let slot = match kind {
            AccessType::Fetch => self.fast_tlb_fetch,
            AccessType::Load => self.fast_tlb_load,
            AccessType::Store => self.fast_tlb_store,
            AccessType::Debug => None,
        }?;
        if slot.satp == satp && slot.vpage == vpage {
            Some(slot.ppage)
        } else {
            None
        }
    }

    #[inline]
    pub(super) fn fast_tlb_insert(&mut self, kind: AccessType, satp: u64, vpage: u64, ppage: u64) {
        let entry = Some(FastTlbEntry { satp, vpage, ppage });
        match kind {
            AccessType::Fetch => self.fast_tlb_fetch = entry,
            AccessType::Load => self.fast_tlb_load = entry,
            AccessType::Store => self.fast_tlb_store = entry,
            AccessType::Debug => {}
        }
    }

    #[inline]
    pub(super) fn tlb_insert(&mut self, satp: u64, vpage: u64, ppage: u64, perms: u8) {
        if perms == 0 {
            return;
        }
        let idx = Self::tlb_index(satp, vpage);
        self.tlb[idx] = Some(TlbEntry {
            vpage,
            ppage,
            perms,
        });
    }

    #[inline]
    pub(super) fn decode32_cached(&mut self, pc: u64, instr: u32) -> Decoded32 {
        if !self.decode_jit_enabled {
            return Self::decode32(instr);
        }
        let satp = self.satp_cached;
        let idx = Self::decode_cache_index(satp, pc);
        if let Some(entry) = self.decode_cache[idx] {
            if entry.satp == satp && entry.pc == pc && entry.instr == instr {
                return entry.decoded;
            }
        }
        let decoded = Self::decode32(instr);
        self.decode_cache[idx] = Some(DecodeCacheEntry {
            satp,
            pc,
            instr,
            decoded,
        });
        decoded
    }

    #[inline]
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    pub(super) fn reg_off(reg: usize) -> u16 {
        (reg as u16) * 8
    }
}
