use super::*;

impl Hart {
    #[inline]
    pub(super) fn check_align(&self, addr: u64, align: u64) -> Result<(), Trap> {
        if addr & (align - 1) != 0 {
            return Err(Trap::MisalignedAccess { addr, size: align });
        }
        Ok(())
    }

    #[inline]
    pub(super) fn next_time_delta(&mut self) -> u64 {
        if !self.time_jitter_enabled {
            return 1;
        }
        // Deterministic xorshift64 stream used to introduce tiny timing jitter.
        let mut x = self.time_jitter_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        if x == 0 {
            x = 1;
        }
        self.time_jitter_state = x;
        match x & 0x7 {
            0 => 2,
            1 => 0,
            _ => 1,
        }
    }

    pub(super) fn read_phys_u64(
        &mut self,
        bus: &mut (impl Bus + ?Sized),
        addr: u64,
    ) -> Result<u64, Trap> {
        bus.read_u64(self.hart_id, addr, AccessType::Debug)
    }

    pub(super) fn write_phys_u64(
        &mut self,
        bus: &mut (impl Bus + ?Sized),
        addr: u64,
        value: u64,
    ) -> Result<(), Trap> {
        bus.write_u64(self.hart_id, addr, value, AccessType::Debug)
    }

    #[allow(dead_code)]
    pub fn debug_read_u16_virt(&mut self, bus: &mut impl Bus, addr: u64) -> Result<u16, Trap> {
        self.read_u16(bus, addr, AccessType::Debug)
    }

    #[allow(dead_code)]
    pub fn debug_read_u32_virt(&mut self, bus: &mut impl Bus, addr: u64) -> Result<u32, Trap> {
        self.read_u32(bus, addr, AccessType::Debug)
    }

    pub(super) fn translate_addr(
        &mut self,
        bus: &mut (impl Bus + ?Sized),
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
                vaddr, kind, self.priv_mode, self.satp_cached
            );
        }
        if self.priv_mode == PrivMode::Machine {
            if mmu_trace {
                eprintln!("  bypass machine mode -> phys=0x{:016x}", vaddr);
            }
            return Ok(vaddr);
        }

        let satp = self.satp_cached;
        let mode = satp >> 60;
        let vpage = vaddr >> 12;
        let page_offset = vaddr & 0xfff;
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

        if !mmu_trace {
            if let Some(ppage) = self.fast_tlb_lookup(kind, satp, vpage) {
                return Ok((ppage << 12) | page_offset);
            }
            if let Some(ppage) = self.tlb_lookup(kind, satp, vpage) {
                self.fast_tlb_insert(kind, satp, vpage, ppage);
                return Ok((ppage << 12) | page_offset);
            }
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
                if !mmu_trace {
                    let mut perms = 0u8;
                    if r {
                        perms |= TLB_PERM_R;
                    }
                    if w {
                        perms |= TLB_PERM_W;
                    }
                    if x {
                        perms |= TLB_PERM_X;
                    }
                    self.tlb_insert(satp, vpage, phys >> 12, perms);
                    self.fast_tlb_insert(kind, satp, vpage, phys >> 12);
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
    pub(super) fn read_u8(
        &mut self,
        bus: &mut (impl Bus + ?Sized),
        addr: u64,
        kind: AccessType,
    ) -> Result<u8, Trap> {
        self.last_access = Some((kind, addr, 1));
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.read_u8(self.hart_id, paddr, kind)
    }

    #[inline]
    pub(super) fn read_u16(
        &mut self,
        bus: &mut (impl Bus + ?Sized),
        addr: u64,
        kind: AccessType,
    ) -> Result<u16, Trap> {
        self.last_access = Some((kind, addr, 2));
        self.check_align(addr, 2)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.read_u16(self.hart_id, paddr, kind)
    }

    #[inline]
    pub(super) fn read_u32(
        &mut self,
        bus: &mut (impl Bus + ?Sized),
        addr: u64,
        kind: AccessType,
    ) -> Result<u32, Trap> {
        self.last_access = Some((kind, addr, 4));
        self.check_align(addr, 4)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.read_u32(self.hart_id, paddr, kind)
    }

    #[inline]
    #[allow(dead_code)]
    pub(super) fn read_u64(
        &mut self,
        bus: &mut (impl Bus + ?Sized),
        addr: u64,
        kind: AccessType,
    ) -> Result<u64, Trap> {
        self.last_access = Some((kind, addr, 8));
        self.check_align(addr, 8)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.read_u64(self.hart_id, paddr, kind)
    }

    #[inline]
    pub(super) fn write_u8(
        &mut self,
        bus: &mut (impl Bus + ?Sized),
        addr: u64,
        val: u8,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.last_access = Some((kind, addr, 1));
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.write_u8(self.hart_id, paddr, val, kind)
    }

    #[inline]
    pub(super) fn write_u16(
        &mut self,
        bus: &mut (impl Bus + ?Sized),
        addr: u64,
        val: u16,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.last_access = Some((kind, addr, 2));
        self.check_align(addr, 2)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.write_u16(self.hart_id, paddr, val, kind)
    }

    #[inline]
    pub(super) fn write_u32(
        &mut self,
        bus: &mut (impl Bus + ?Sized),
        addr: u64,
        val: u32,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.last_access = Some((kind, addr, 4));
        self.check_align(addr, 4)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.write_u32(self.hart_id, paddr, val, kind)
    }

    #[inline]
    #[allow(dead_code)]
    pub(super) fn write_u64(
        &mut self,
        bus: &mut (impl Bus + ?Sized),
        addr: u64,
        val: u64,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.last_access = Some((kind, addr, 8));
        self.check_align(addr, 8)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.write_u64(self.hart_id, paddr, val, kind)
    }
}
