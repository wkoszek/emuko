use super::*;

impl Hart {
    pub(super) fn has_debug_hooks(&self) -> bool {
        self.hotpc_top != 0
            || self.trace_pc_zero
            || self.trace_last
            || self.trace_pc.is_some()
            || self.trace_instr.is_some()
            || self.watch_left > 0
            || self.watch_left2 > 0
    }

    pub(super) fn exec32_decoded(
        &mut self,
        bus: &mut dyn Bus,
        sbi: &mut (impl Sbi + ?Sized),
        instr: u32,
        d: Decoded32,
    ) -> Result<u64, Trap> {
        let opcode = d.opcode as u32;
        let rd = d.rd as usize;
        let funct3 = d.funct3 as u32;
        let rs1 = d.rs1 as usize;
        let rs2 = d.rs2 as usize;
        let funct7 = d.funct7 as u32;
        let funct5 = d.funct5 as u32;
        let imm12 = d.imm12 as u32;
        let shamt = (imm12 & 0x3f) as u32;
        let imm_hi = (imm12 >> 6) & 0x3f;
        let csr_addr = d.csr_addr;
        let zimm = rs1 as u64;

        let mut next_pc = self.pc.wrapping_add(4);
        match opcode {
            OPCODE_LUI => {
                self.regs[rd] = Self::imm_u(instr) as u64;
            }
            OPCODE_AUIPC => {
                self.regs[rd] = self.pc.wrapping_add(Self::imm_u(instr) as u64);
            }
            OPCODE_JAL => {
                let imm_j = Self::imm_j(instr) as u64;
                self.regs[rd] = next_pc;
                next_pc = self.pc.wrapping_add(imm_j);
            }
            OPCODE_JALR => {
                let imm_i = Self::imm_i(instr) as u64;
                let target = self.regs[rs1].wrapping_add(imm_i) & !1;
                self.regs[rd] = next_pc;
                next_pc = target;
            }
            OPCODE_BRANCH => {
                let imm_b = Self::imm_b(instr) as u64;
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
                    next_pc = self.pc.wrapping_add(imm_b);
                }
            }
            OPCODE_LOAD => {
                let imm_i = Self::imm_i(instr) as u64;
                let addr = self.regs[rs1].wrapping_add(imm_i);
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
                let imm_i = Self::imm_i(instr) as u64;
                let addr = self.regs[rs1].wrapping_add(imm_i);
                match funct3 {
                    2 => {
                        let val = self.read_u32(bus, addr, AccessType::Load)?;
                        self.fregs[rd] = val as u64;
                    }
                    3 => {
                        let val = self.read_u64(bus, addr, AccessType::Load)?;
                        self.fregs[rd] = val;
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                }
            }
            OPCODE_STORE => {
                let imm_s = Self::imm_s(instr) as u64;
                let addr = self.regs[rs1].wrapping_add(imm_s);
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
                let imm_s = Self::imm_s(instr) as u64;
                let addr = self.regs[rs1].wrapping_add(imm_s);
                match funct3 {
                    2 => {
                        let val = self.fregs[rs2] as u32;
                        self.write_u32(bus, addr, val, AccessType::Store)?;
                    }
                    3 => {
                        let val = self.fregs[rs2];
                        self.write_u64(bus, addr, val, AccessType::Store)?;
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                }
            }
            OPCODE_OP_IMM => {
                let imm_i = Self::imm_i(instr) as u64;
                let a = self.regs[rs1];
                let res = match funct3 {
                    F3_ADD_SUB => a.wrapping_add(imm_i),
                    F3_SLL => {
                        if imm_hi != 0 {
                            return Err(Trap::IllegalInstruction(instr));
                        }
                        a << shamt
                    }
                    F3_SLT => ((a as i64) < (imm_i as i64)) as u64,
                    F3_SLTU => (a < imm_i) as u64,
                    F3_XOR => a ^ imm_i,
                    F3_SRL_SRA => match imm_hi {
                        0x00 => a >> shamt,
                        0x10 => ((a as i64) >> shamt) as u64,
                        _ => return Err(Trap::IllegalInstruction(instr)),
                    },
                    F3_OR => a | imm_i,
                    F3_AND => a & imm_i,
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
                    (F7_MULDIV, F3_ADD_SUB) => a.wrapping_mul(b),
                    (F7_MULDIV, F3_SLL) => {
                        let prod = (a as i64 as i128).wrapping_mul(b as i64 as i128);
                        (prod >> 64) as u64
                    }
                    (F7_MULDIV, F3_SLT) => {
                        let prod = (a as i64 as i128).wrapping_mul(b as u128 as i128);
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
                let imm = Self::imm_i(instr);
                let shamt = (imm12 & 0x1f) as u32;
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
            OPCODE_SYSTEM => match funct3 {
                F3_SYSTEM => match imm12 {
                    IMM_ECALL => {
                        if self.priv_mode == PrivMode::Supervisor {
                            if !sbi.handle_ecall(self, bus)? {
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
                    IMM_WFI => {}
                    _ => {
                        if (instr >> 25) == 0x09 {
                            self.flush_tlb();
                        }
                    }
                },
                F3_CSRRW | F3_CSRRS | F3_CSRRC | F3_CSRRWI | F3_CSRRSI | F3_CSRRCI => {
                    if csr_addr == crate::csr::CSR_INSTRET {
                        self.commit_instret();
                    }
                    let old = self.csrs.read(csr_addr);
                    let mut new_val = old;
                    let mut do_write = true;
                    match funct3 {
                        F3_CSRRW => new_val = self.regs[rs1],
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
                        F3_CSRRWI => new_val = zimm,
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
                        if csr_addr == CSR_SATP {
                            self.satp_cached = self.csrs.read(CSR_SATP);
                            self.flush_tlb();
                        }
                    }
                }
                _ => return Err(Trap::IllegalInstruction(instr)),
            },
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
            OPCODE_MISC_MEM => match funct3 {
                F3_FENCE | F3_FENCE_I => {}
                _ => return Err(Trap::IllegalInstruction(instr)),
            },
            _ => return Err(Trap::IllegalInstruction(instr)),
        }
        Ok(next_pc)
    }

    pub fn step(&mut self, bus: &mut impl Bus, sbi: &mut impl Sbi) -> Result<(), Trap> {
        // Keep rdtime/cycle moving each simulated step even when runtime
        // housekeeping is batched in System::run.
        let dt = self.next_time_delta() as u32;
        let total = self.time_div_accum.saturating_add(dt);
        if total >= self.time_divider {
            let ticks = total / self.time_divider;
            self.time_div_accum = total % self.time_divider;
            self.csrs.increment_time(ticks as u64);
        } else {
            self.time_div_accum = total;
        }
        if self.hotpc_top != 0 {
            *self.hotpc_counts.entry(self.pc).or_insert(0) += 1;
        }
        if self.irq_check_countdown <= 1 {
            self.irq_check_countdown = self.irq_check_stride;
            if let Some(code) = self.pending_interrupt() {
                let cause = (1u64 << 63) | code;
                self.take_trap(cause, 0);
                return Ok(());
            }
        } else {
            self.irq_check_countdown -= 1;
        }

        self.check_align(self.pc, 2)?;
        let (instr16, instr32_cached) = if (self.pc & 0x3) == 0 {
            let word = self.read_u32(bus, self.pc, AccessType::Fetch)?;
            ((word & 0xffff) as u16, Some(word))
        } else {
            (self.read_u16(bus, self.pc, AccessType::Fetch)?, None)
        };
        let debug_hooks = self.has_debug_hooks();
        if (instr16 & 0x3) != 0x3 {
            if !debug_hooks {
                return self.exec_compressed(bus, instr16);
            }
            self.record_instr(self.pc, instr16 as u32, 2);
            let pc_before = self.pc;
            let watch_hit = self.watch_hit(self.pc);
            let watch_reg = self.watch_reg;
            let watch_before = if watch_hit {
                watch_reg.map(|r| self.regs[r])
            } else {
                None
            };
            let watch_hit2 = self.watch_hit2(self.pc);
            let watch_reg2 = self.watch_reg2;
            let watch_before2 = if watch_hit2 {
                watch_reg2.map(|r| self.regs[r])
            } else {
                None
            };
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
        let instr = if let Some(word) = instr32_cached {
            word
        } else {
            let upper = self.read_u16(bus, self.pc.wrapping_add(2), AccessType::Fetch)? as u32;
            (upper << 16) | (instr16 as u32)
        };
        if !debug_hooks {
            let d = self.decode32_cached(self.pc, instr);
            let next_pc = self.exec32_decoded(bus, sbi, instr, d)?;
            self.pc = next_pc;
            self.regs[0] = 0;
            self.instret_pending = self.instret_pending.wrapping_add(1);
            return Ok(());
        }
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
        let d = self.decode32_cached(self.pc, instr);
        let rd = d.rd as usize;
        let rs1 = d.rs1 as usize;
        let rs2 = d.rs2 as usize;
        let pc_before = self.pc;
        let watch_hit = self.watch_hit(self.pc);
        let watch_reg = self.watch_reg;
        let watch_before = if watch_hit {
            watch_reg.map(|r| self.regs[r])
        } else {
            None
        };
        let watch_hit2 = self.watch_hit2(self.pc);
        let watch_reg2 = self.watch_reg2;
        let watch_before2 = if watch_hit2 {
            watch_reg2.map(|r| self.regs[r])
        } else {
            None
        };
        let (rs1_before, rs2_before, rd_before) = if watch_hit || watch_hit2 {
            (self.regs[rs1], self.regs[rs2], self.regs[rd])
        } else {
            (0, 0, 0)
        };
        let next_pc = self.exec32_decoded(bus, sbi, instr, d)?;

        if self.trace_pc_zero && next_pc == 0 {
            eprintln!(
                "pc->0: pc=0x{:016x} instr=0x{:08x} ra=0x{:016x}",
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
        self.instret_pending = self.instret_pending.wrapping_add(1);
        Ok(())
    }

    pub(super) fn exec_compressed(&mut self, bus: &mut impl Bus, instr: u16) -> Result<(), Trap> {
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
        self.instret_pending = self.instret_pending.wrapping_add(1);
        Ok(())
    }
}
