use super::*;

impl Hart {
    #[cfg(target_arch = "aarch64")]
    fn emit_native_instr16(&self, em: &mut A64Emitter, pc: u64, instr: u16) -> Option<EmitFlow> {
        const C_EQ: u8 = 0x0;
        const C_NE: u8 = 0x1;

        let funct3 = (instr >> 13) & 0x7;
        let op = instr & 0x3;
        let rd = ((instr >> 7) & 0x1f) as usize;
        let rs2 = ((instr >> 2) & 0x1f) as usize;
        let rd_prime = (((instr >> 2) & 0x7) + 8) as usize;
        let rs1_prime = (((instr >> 7) & 0x7) + 8) as usize;
        let rs2_prime = (((instr >> 2) & 0x7) + 8) as usize;
        let bit12 = (instr >> 12) & 0x1;

        let imm_ci = || {
            let imm = (((instr >> 12) & 0x1) << 5) | ((instr >> 2) & 0x1f);
            Self::sign_extend(imm as u64, 6) as u64
        };

        let store_rd = |em: &mut A64Emitter, rd: usize| {
            if rd != 0 {
                em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
            }
        };

        match op {
            0b00 => match funct3 {
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
                        return None;
                    }
                    em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(2)));
                    em.mov_imm64(10, imm as u64);
                    em.emit(A64Emitter::add_x(11, 9, 10));
                    em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd_prime)));
                    Some(EmitFlow::Continue)
                }
                _ => None,
            },
            0b01 => match funct3 {
                0b000 => {
                    // C.ADDI / C.NOP
                    if rd != 0 {
                        em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rd)));
                        em.mov_imm64(10, imm_ci());
                        em.emit(A64Emitter::add_x(11, 9, 10));
                        em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
                    }
                    Some(EmitFlow::Continue)
                }
                0b001 => {
                    // C.ADDIW
                    if rd == 0 {
                        return None;
                    }
                    em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rd)));
                    em.mov_imm64(10, imm_ci());
                    em.emit(A64Emitter::add_x(11, 9, 10));
                    em.emit(A64Emitter::sxtw_x(11, 11));
                    em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
                    Some(EmitFlow::Continue)
                }
                0b010 => {
                    // C.LI
                    if rd != 0 {
                        em.mov_imm64(11, imm_ci());
                        em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
                    }
                    Some(EmitFlow::Continue)
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
                            return None;
                        }
                        em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(2)));
                        em.mov_imm64(10, imm);
                        em.emit(A64Emitter::add_x(11, 9, 10));
                        em.emit(A64Emitter::str_x(11, 0, Self::reg_off(2)));
                        Some(EmitFlow::Continue)
                    } else {
                        // C.LUI
                        if rd == 0 {
                            return None;
                        }
                        let imm = imm_ci();
                        if imm == 0 {
                            return None;
                        }
                        em.mov_imm64(11, ((imm as i64) << 12) as u64);
                        em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
                        Some(EmitFlow::Continue)
                    }
                }
                0b100 => {
                    let funct2 = (instr >> 10) & 0x3;
                    match funct2 {
                        0b00 => {
                            // C.SRLI
                            let shamt = (((instr >> 12) & 0x1) << 5) | ((instr >> 2) & 0x1f);
                            em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1_prime)));
                            em.mov_imm64(10, shamt as u64);
                            em.emit(A64Emitter::lsrv_x(11, 9, 10));
                            em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rs1_prime)));
                            Some(EmitFlow::Continue)
                        }
                        0b01 => {
                            // C.SRAI
                            let shamt = (((instr >> 12) & 0x1) << 5) | ((instr >> 2) & 0x1f);
                            em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1_prime)));
                            em.mov_imm64(10, shamt as u64);
                            em.emit(A64Emitter::asrv_x(11, 9, 10));
                            em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rs1_prime)));
                            Some(EmitFlow::Continue)
                        }
                        0b10 => {
                            // C.ANDI
                            em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1_prime)));
                            em.mov_imm64(10, imm_ci() as i64 as u64);
                            em.emit(A64Emitter::and_x(11, 9, 10));
                            em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rs1_prime)));
                            Some(EmitFlow::Continue)
                        }
                        0b11 => {
                            let subop = (instr >> 12) & 0x1;
                            let alu2 = (instr >> 5) & 0x3;
                            em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1_prime)));
                            em.emit(A64Emitter::ldr_x(10, 0, Self::reg_off(rs2_prime)));
                            match (subop, alu2) {
                                (0, 0b00) => em.emit(A64Emitter::sub_x(11, 9, 10)), // C.SUB
                                (0, 0b01) => em.emit(A64Emitter::eor_x(11, 9, 10)), // C.XOR
                                (0, 0b10) => em.emit(A64Emitter::orr_x(11, 9, 10)), // C.OR
                                (0, 0b11) => em.emit(A64Emitter::and_x(11, 9, 10)), // C.AND
                                (1, 0b00) => {
                                    // C.SUBW
                                    em.emit(A64Emitter::sub_x(11, 9, 10));
                                    em.emit(A64Emitter::sxtw_x(11, 11));
                                }
                                (1, 0b01) => {
                                    // C.ADDW
                                    em.emit(A64Emitter::add_x(11, 9, 10));
                                    em.emit(A64Emitter::sxtw_x(11, 11));
                                }
                                _ => return None,
                            }
                            em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rs1_prime)));
                            Some(EmitFlow::Continue)
                        }
                        _ => None,
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
                    em.mov_imm64(0, pc.wrapping_add(imm));
                    Some(EmitFlow::Terminate)
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
                    em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1_prime)));
                    em.mov_imm64(10, 0);
                    em.emit(A64Emitter::cmp_x(9, 10));
                    em.mov_imm64(12, pc.wrapping_add(imm));
                    em.mov_imm64(13, pc.wrapping_add(2));
                    let cond = if funct3 == 0b110 { C_EQ } else { C_NE };
                    em.emit(A64Emitter::csel_x(0, 12, 13, cond));
                    Some(EmitFlow::Terminate)
                }
                _ => None,
            },
            0b10 => match funct3 {
                0b000 => {
                    // C.SLLI
                    if rd == 0 {
                        return None;
                    }
                    let shamt = (((instr >> 12) & 0x1) << 5) | ((instr >> 2) & 0x1f);
                    em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rd)));
                    em.mov_imm64(10, shamt as u64);
                    em.emit(A64Emitter::lslv_x(11, 9, 10));
                    em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
                    Some(EmitFlow::Continue)
                }
                0b100 => {
                    if bit12 == 0 {
                        if rs2 == 0 {
                            // C.JR
                            if rd == 0 {
                                return None;
                            }
                            em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rd)));
                            em.mov_imm64(10, !1u64);
                            em.emit(A64Emitter::and_x(0, 9, 10));
                            Some(EmitFlow::Terminate)
                        } else {
                            // C.MV
                            if rd == 0 {
                                return None;
                            }
                            em.emit(A64Emitter::ldr_x(11, 0, Self::reg_off(rs2)));
                            em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
                            Some(EmitFlow::Continue)
                        }
                    } else if rs2 == 0 {
                        if rd == 0 {
                            // C.EBREAK
                            if !self.ignore_ebreak {
                                return None;
                            }
                            Some(EmitFlow::Continue)
                        } else {
                            // C.JALR
                            em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rd)));
                            em.mov_imm64(10, !1u64);
                            em.emit(A64Emitter::and_x(11, 9, 10));
                            em.mov_imm64(12, pc.wrapping_add(2));
                            em.emit(A64Emitter::str_x(12, 0, Self::reg_off(1)));
                            em.emit(A64Emitter::orr_x(0, 11, 31));
                            Some(EmitFlow::Terminate)
                        }
                    } else {
                        // C.ADD
                        if rd == 0 {
                            return None;
                        }
                        em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rd)));
                        em.emit(A64Emitter::ldr_x(10, 0, Self::reg_off(rs2)));
                        em.emit(A64Emitter::add_x(11, 9, 10));
                        store_rd(em, rd);
                        Some(EmitFlow::Continue)
                    }
                }
                _ => None,
            },
            _ => None,
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn emit_native_term_helper32(
        &self,
        em: &mut A64Emitter,
        pc: u64,
        instr: u32,
        d: Decoded32,
        prefix_count: u32,
    ) -> bool {
        let opcode = d.opcode as u32;
        if opcode == OPCODE_SYSTEM {
            return false;
        }
        if opcode == OPCODE_LOAD || opcode == OPCODE_STORE {
            let funct3 = d.funct3 as u32;
            let rs1 = d.rs1 as usize;
            let rs2 = d.rs2 as usize;
            let rd = d.rd as usize;
            let (mem_op, imm, is_store) = if opcode == OPCODE_LOAD {
                let op = match funct3 {
                    F3_LB => Self::MEM_OP_LB,
                    F3_LH => Self::MEM_OP_LH,
                    F3_LW => Self::MEM_OP_LW,
                    F3_LD => Self::MEM_OP_LD,
                    F3_LBU => Self::MEM_OP_LBU,
                    F3_LHU => Self::MEM_OP_LHU,
                    F3_LWU => Self::MEM_OP_LWU,
                    _ => return false,
                };
                (op, Self::imm_i(instr), false)
            } else {
                let op = match funct3 {
                    F3_SB => Self::MEM_OP_SB,
                    F3_SH => Self::MEM_OP_SH,
                    F3_SW => Self::MEM_OP_SW,
                    F3_SD => Self::MEM_OP_SD,
                    _ => return false,
                };
                (op, Self::imm_s(instr), true)
            };

            // Compute effective address in native code.
            em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1)));
            em.mov_imm64(10, imm as u64);
            em.emit(A64Emitter::add_x(11, 9, 10));
            if is_store {
                em.emit(A64Emitter::ldr_x(12, 0, Self::reg_off(rs2)));
            }

            // x0=regs_ptr, x1=hart_ptr, x2=bus_data, x3=bus_vtable.
            // Helper args:
            //   x0=hart_ptr, x1=bus_data, x2=bus_vtable, x3=mem_op, x4=rd, x5=store_val,
            //   x6=addr, x7=pc
            em.emit(A64Emitter::mov_x(0, 1));
            em.emit(A64Emitter::mov_x(1, 2));
            em.emit(A64Emitter::mov_x(2, 3));
            em.mov_imm64(3, mem_op);
            em.mov_imm64(4, rd as u64);
            if is_store {
                em.emit(A64Emitter::mov_x(5, 12));
            } else {
                em.mov_imm64(5, 0);
            }
            em.emit(A64Emitter::mov_x(6, 11));
            em.mov_imm64(7, pc);
            em.mov_imm64(
                16,
                Self::native_exec_mem_term_helper as *const () as usize as u64,
            );
            em.emit(A64Emitter::sub_sp_imm(16));
            em.emit(A64Emitter::str_x(30, 31, 0));
            em.emit(A64Emitter::blr(16));
            em.emit(A64Emitter::ldr_x(30, 31, 0));
            em.emit(A64Emitter::add_sp_imm(16));
            if prefix_count != 0 {
                em.mov_imm64(12, prefix_count as u64);
                em.emit(A64Emitter::add_x(1, 1, 12));
            }
            em.emit(0xD65F_03C0); // ret
            return true;
        }

        match opcode {
            OPCODE_LOAD | OPCODE_STORE | OPCODE_LOAD_FP | OPCODE_STORE_FP | OPCODE_SYSTEM
            | OPCODE_AMO => {}
            _ => return false,
        }
        // x0=regs_ptr, x1=hart_ptr, x2=bus_data, x3=bus_vtable.
        // Call helper as:
        //   x0=hart_ptr, x1=bus_data, x2=bus_vtable, x3=sbi_data, x4=sbi_vtable,
        //   x5=instr, x6=pc
        // Helper returns NativeBlockResult in x0/x1.
        em.emit(A64Emitter::mov_x(0, 1));
        em.emit(A64Emitter::mov_x(1, 2));
        em.emit(A64Emitter::mov_x(2, 3));
        em.emit(A64Emitter::mov_x(3, 4));
        em.emit(A64Emitter::mov_x(4, 5));
        em.mov_imm64(5, instr as u64);
        em.mov_imm64(6, pc);
        em.mov_imm64(
            16,
            Self::native_exec32_term_helper as *const () as usize as u64,
        );
        em.emit(A64Emitter::sub_sp_imm(16));
        em.emit(A64Emitter::str_x(30, 31, 0));
        em.emit(A64Emitter::blr(16));
        em.emit(A64Emitter::ldr_x(30, 31, 0));
        em.emit(A64Emitter::add_sp_imm(16));
        if prefix_count != 0 {
            em.mov_imm64(12, prefix_count as u64);
            em.emit(A64Emitter::add_x(1, 1, 12));
        }
        em.emit(0xD65F_03C0); // ret
        true
    }

    #[cfg(target_arch = "aarch64")]
    fn emit_native_term_helper16(
        &self,
        em: &mut A64Emitter,
        pc: u64,
        instr: u16,
        prefix_count: u32,
    ) -> bool {
        let funct3 = (instr >> 13) & 0x7;
        let op = instr & 0x3;
        let supports = match op {
            0b00 => matches!(funct3, 0b010 | 0b011 | 0b110 | 0b111),
            0b10 => matches!(funct3, 0b010 | 0b011 | 0b110 | 0b111),
            _ => false,
        };
        if !supports {
            return false;
        }

        // x0=regs_ptr, x1=hart_ptr, x2=bus_data, x3=bus_vtable.
        // Call helper as:
        //   x0=hart_ptr, x1=bus_data, x2=bus_vtable, x3=sbi_data, x4=sbi_vtable,
        //   x5=instr16, x6=pc
        // Helper returns NativeBlockResult in x0/x1.
        em.emit(A64Emitter::mov_x(0, 1));
        em.emit(A64Emitter::mov_x(1, 2));
        em.emit(A64Emitter::mov_x(2, 3));
        em.emit(A64Emitter::mov_x(3, 4));
        em.emit(A64Emitter::mov_x(4, 5));
        em.mov_imm64(5, instr as u64);
        em.mov_imm64(6, pc);
        em.mov_imm64(
            16,
            Self::native_exec16_term_helper as *const () as usize as u64,
        );
        em.emit(A64Emitter::sub_sp_imm(16));
        em.emit(A64Emitter::str_x(30, 31, 0));
        em.emit(A64Emitter::blr(16));
        em.emit(A64Emitter::ldr_x(30, 31, 0));
        em.emit(A64Emitter::add_sp_imm(16));
        if prefix_count != 0 {
            em.mov_imm64(12, prefix_count as u64);
            em.emit(A64Emitter::add_x(1, 1, 12));
        }
        em.emit(0xD65F_03C0); // ret
        true
    }

    #[cfg(target_arch = "aarch64")]
    unsafe extern "C" fn native_exec_mem_term_helper(
        hart_ptr: *mut Hart,
        bus_data: *mut (),
        bus_vtable: *mut (),
        mem_op: u64,
        rd: u64,
        store_val: u64,
        addr: u64,
        pc: u64,
    ) -> NativeBlockResult {
        if hart_ptr.is_null() || bus_data.is_null() || bus_vtable.is_null() {
            return NativeBlockResult {
                next_pc: pc,
                executed: 0,
            };
        }

        let hart = unsafe { &mut *hart_ptr };
        let bus_ptr: *mut dyn Bus = unsafe {
            std::mem::transmute::<(*mut (), *mut ()), *mut dyn Bus>((bus_data, bus_vtable))
        };
        let bus = unsafe { &mut *bus_ptr };
        let rd = (rd as usize) & 31;

        let mut is_load = true;
        let mem_res: Result<u64, Trap> = match mem_op {
            Self::MEM_OP_LB => hart
                .read_u8(bus, addr, AccessType::Load)
                .map(|v| (v as i8 as i64) as u64),
            Self::MEM_OP_LH => hart
                .read_u16(bus, addr, AccessType::Load)
                .map(|v| (v as i16 as i64) as u64),
            Self::MEM_OP_LW => hart
                .read_u32(bus, addr, AccessType::Load)
                .map(|v| (v as i32 as i64) as u64),
            Self::MEM_OP_LD => hart.read_u64(bus, addr, AccessType::Load),
            Self::MEM_OP_LBU => hart.read_u8(bus, addr, AccessType::Load).map(|v| v as u64),
            Self::MEM_OP_LHU => hart.read_u16(bus, addr, AccessType::Load).map(|v| v as u64),
            Self::MEM_OP_LWU => hart.read_u32(bus, addr, AccessType::Load).map(|v| v as u64),
            Self::MEM_OP_SB => {
                is_load = false;
                hart.write_u8(bus, addr, store_val as u8, AccessType::Store)
                    .map(|_| 0)
            }
            Self::MEM_OP_SH => {
                is_load = false;
                hart.write_u16(bus, addr, store_val as u16, AccessType::Store)
                    .map(|_| 0)
            }
            Self::MEM_OP_SW => {
                is_load = false;
                hart.write_u32(bus, addr, store_val as u32, AccessType::Store)
                    .map(|_| 0)
            }
            Self::MEM_OP_SD => {
                is_load = false;
                hart.write_u64(bus, addr, store_val, AccessType::Store)
                    .map(|_| 0)
            }
            _ => Err(Trap::IllegalInstruction(0)),
        };

        match mem_res {
            Ok(v) => {
                if is_load && rd != 0 {
                    hart.regs[rd] = v;
                }
                NativeBlockResult {
                    next_pc: pc.wrapping_add(4),
                    executed: 1,
                }
            }
            Err(trap) => {
                hart.pc = pc;
                hart.handle_trap(trap);
                NativeBlockResult {
                    next_pc: hart.pc,
                    executed: NATIVE_EXEC_FLAG_LAST_TRAP | 1,
                }
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe extern "C" fn native_exec32_term_helper(
        hart_ptr: *mut Hart,
        bus_data: *mut (),
        bus_vtable: *mut (),
        sbi_data: *mut (),
        sbi_vtable: *mut (),
        instr: u64,
        pc: u64,
    ) -> NativeBlockResult {
        if hart_ptr.is_null()
            || bus_data.is_null()
            || bus_vtable.is_null()
            || sbi_data.is_null()
            || sbi_vtable.is_null()
        {
            return NativeBlockResult {
                next_pc: pc,
                executed: 0,
            };
        }

        let hart = unsafe { &mut *hart_ptr };
        let bus_ptr: *mut dyn Bus = unsafe {
            std::mem::transmute::<(*mut (), *mut ()), *mut dyn Bus>((bus_data, bus_vtable))
        };
        let bus = unsafe { &mut *bus_ptr };
        let sbi_ptr: *mut dyn Sbi = unsafe {
            std::mem::transmute::<(*mut (), *mut ()), *mut dyn Sbi>((sbi_data, sbi_vtable))
        };
        let sbi = unsafe { &mut *sbi_ptr };

        hart.pc = pc;
        let instr = instr as u32;
        let d = Self::decode32(instr);
        let next_pc = match hart.exec32_decoded(bus, sbi, instr, d) {
            Ok(v) => v,
            Err(trap) => {
                hart.handle_trap(trap);
                return NativeBlockResult {
                    next_pc: hart.pc,
                    executed: NATIVE_EXEC_FLAG_LAST_TRAP | 1,
                };
            }
        };
        NativeBlockResult {
            next_pc,
            executed: 1,
        }
    }

    #[cfg(target_arch = "aarch64")]
    unsafe extern "C" fn native_exec16_term_helper(
        hart_ptr: *mut Hart,
        bus_data: *mut (),
        bus_vtable: *mut (),
        _sbi_data: *mut (),
        _sbi_vtable: *mut (),
        instr: u64,
        pc: u64,
    ) -> NativeBlockResult {
        if hart_ptr.is_null() || bus_data.is_null() || bus_vtable.is_null() {
            return NativeBlockResult {
                next_pc: pc,
                executed: 0,
            };
        }

        let hart = unsafe { &mut *hart_ptr };
        let bus_ptr: *mut dyn Bus = unsafe {
            std::mem::transmute::<(*mut (), *mut ()), *mut dyn Bus>((bus_data, bus_vtable))
        };
        let bus = unsafe { &mut *bus_ptr };
        let instr = instr as u16;
        let funct3 = (instr >> 13) & 0x7;
        let op = instr & 0x3;
        let rd = ((instr >> 7) & 0x1f) as usize;
        let rs2 = ((instr >> 2) & 0x1f) as usize;
        let rd_prime = (((instr >> 2) & 0x7) + 8) as usize;
        let rs1_prime = (((instr >> 7) & 0x7) + 8) as usize;
        let rs2_prime = (((instr >> 2) & 0x7) + 8) as usize;
        let next_pc = pc.wrapping_add(2);

        let res: Result<(), Trap> = (|| {
            match op {
                0b00 => match funct3 {
                    0b010 => {
                        // C.LW
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 6) & 0x1) << 2)
                            | (((instr >> 5) & 0x1) << 6);
                        let addr = hart.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = hart.read_u32(bus, addr, AccessType::Load)? as i32 as i64 as u64;
                        hart.regs[rd_prime] = val;
                        Ok(())
                    }
                    0b011 => {
                        // C.LD
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 5) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 7);
                        let addr = hart.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = hart.read_u64(bus, addr, AccessType::Load)?;
                        hart.regs[rd_prime] = val;
                        Ok(())
                    }
                    0b110 => {
                        // C.SW
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 6) & 0x1) << 2)
                            | (((instr >> 5) & 0x1) << 6);
                        let addr = hart.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = hart.regs[rs2_prime] as u32;
                        hart.write_u32(bus, addr, val, AccessType::Store)?;
                        Ok(())
                    }
                    0b111 => {
                        // C.SD
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 5) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 7);
                        let addr = hart.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = hart.regs[rs2_prime];
                        hart.write_u64(bus, addr, val, AccessType::Store)?;
                        Ok(())
                    }
                    _ => Err(Trap::IllegalInstruction(instr as u32)),
                },
                0b10 => match funct3 {
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
                        let addr = hart.regs[2].wrapping_add(imm as u64);
                        let val = hart.read_u32(bus, addr, AccessType::Load)? as i32 as i64 as u64;
                        hart.regs[rd] = val;
                        Ok(())
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
                        let addr = hart.regs[2].wrapping_add(imm as u64);
                        let val = hart.read_u64(bus, addr, AccessType::Load)?;
                        hart.regs[rd] = val;
                        Ok(())
                    }
                    0b110 => {
                        // C.SWSP
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 3)
                            | (((instr >> 9) & 0x1) << 2)
                            | (((instr >> 8) & 0x1) << 7)
                            | (((instr >> 7) & 0x1) << 6);
                        let addr = hart.regs[2].wrapping_add(imm as u64);
                        let val = hart.regs[rs2] as u32;
                        hart.write_u32(bus, addr, val, AccessType::Store)?;
                        Ok(())
                    }
                    0b111 => {
                        // C.SDSP
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 3)
                            | (((instr >> 9) & 0x1) << 8)
                            | (((instr >> 8) & 0x1) << 7)
                            | (((instr >> 7) & 0x1) << 6);
                        let addr = hart.regs[2].wrapping_add(imm as u64);
                        let val = hart.regs[rs2];
                        hart.write_u64(bus, addr, val, AccessType::Store)?;
                        Ok(())
                    }
                    _ => Err(Trap::IllegalInstruction(instr as u32)),
                },
                _ => Err(Trap::IllegalInstruction(instr as u32)),
            }
        })();

        match res {
            Ok(()) => NativeBlockResult {
                next_pc,
                executed: 1,
            },
            Err(trap) => {
                hart.pc = pc;
                hart.handle_trap(trap);
                NativeBlockResult {
                    next_pc: hart.pc,
                    executed: NATIVE_EXEC_FLAG_LAST_TRAP | 1,
                }
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn emit_native_instr(
        &self,
        em: &mut A64Emitter,
        pc: u64,
        instr: u32,
        d: Decoded32,
    ) -> Option<EmitFlow> {
        const C_EQ: u8 = 0x0;
        const C_NE: u8 = 0x1;
        const C_CS: u8 = 0x2;
        const C_CC: u8 = 0x3;
        const C_MI: u8 = 0x4;
        const C_GE: u8 = 0xA;
        const C_LT: u8 = 0xB;
        let rd = d.rd as usize;
        let rs1 = d.rs1 as usize;
        let rs2 = d.rs2 as usize;
        let funct3 = d.funct3 as u32;
        let funct7 = d.funct7 as u32;
        let imm12 = d.imm12 as u32;
        let imm_hi = (imm12 >> 6) & 0x3f;

        let store_rd = |em: &mut A64Emitter, rd: usize| {
            if rd != 0 {
                em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
            }
        };

        match d.opcode as u32 {
            OPCODE_LUI => {
                if rd != 0 {
                    em.mov_imm64(11, Self::imm_u(instr) as u64);
                    em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
                }
                Some(EmitFlow::Continue)
            }
            OPCODE_AUIPC => {
                if rd != 0 {
                    em.mov_imm64(11, pc.wrapping_add(Self::imm_u(instr) as u64));
                    em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
                }
                Some(EmitFlow::Continue)
            }
            OPCODE_JAL => {
                if rd != 0 {
                    em.mov_imm64(11, pc.wrapping_add(4));
                    em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
                }
                em.mov_imm64(0, pc.wrapping_add(Self::imm_j(instr) as u64));
                Some(EmitFlow::Terminate)
            }
            OPCODE_JALR => {
                em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1)));
                if rd != 0 {
                    em.mov_imm64(11, pc.wrapping_add(4));
                    em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
                }
                em.mov_imm64(10, Self::imm_i(instr) as u64);
                em.emit(A64Emitter::add_x(11, 9, 10));
                em.mov_imm64(12, !1u64);
                em.emit(A64Emitter::and_x(0, 11, 12));
                Some(EmitFlow::Terminate)
            }
            OPCODE_BRANCH => {
                let cond = match funct3 {
                    F3_BEQ => C_EQ,
                    F3_BNE => C_NE,
                    F3_BLT => C_LT,
                    F3_BGE => C_GE,
                    F3_BLTU => C_CC,
                    F3_BGEU => C_CS,
                    _ => return None,
                };
                em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1)));
                em.emit(A64Emitter::ldr_x(10, 0, Self::reg_off(rs2)));
                em.emit(A64Emitter::cmp_x(9, 10));
                em.mov_imm64(12, pc.wrapping_add(Self::imm_b(instr) as u64));
                em.mov_imm64(13, pc.wrapping_add(4));
                em.emit(A64Emitter::csel_x(0, 12, 13, cond));
                Some(EmitFlow::Terminate)
            }
            OPCODE_OP_IMM => {
                em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1)));
                match funct3 {
                    F3_ADD_SUB => {
                        em.mov_imm64(10, Self::imm_i(instr) as u64);
                        em.emit(A64Emitter::add_x(11, 9, 10));
                    }
                    F3_SLT => {
                        em.mov_imm64(10, Self::imm_i(instr) as u64);
                        em.emit(A64Emitter::cmp_x(9, 10));
                        em.mov_imm64(12, 1);
                        em.mov_imm64(13, 0);
                        em.emit(A64Emitter::csel_x(11, 12, 13, C_LT));
                    }
                    F3_SLTU => {
                        em.mov_imm64(10, Self::imm_i(instr) as u64);
                        em.emit(A64Emitter::cmp_x(9, 10));
                        em.mov_imm64(12, 1);
                        em.mov_imm64(13, 0);
                        em.emit(A64Emitter::csel_x(11, 12, 13, C_CC));
                    }
                    F3_XOR => {
                        em.mov_imm64(10, Self::imm_i(instr) as u64);
                        em.emit(A64Emitter::eor_x(11, 9, 10));
                    }
                    F3_OR => {
                        em.mov_imm64(10, Self::imm_i(instr) as u64);
                        em.emit(A64Emitter::orr_x(11, 9, 10));
                    }
                    F3_AND => {
                        em.mov_imm64(10, Self::imm_i(instr) as u64);
                        em.emit(A64Emitter::and_x(11, 9, 10));
                    }
                    F3_SLL => {
                        if imm_hi != 0 {
                            return None;
                        }
                        em.mov_imm64(10, (imm12 & 0x3f) as u64);
                        em.emit(A64Emitter::lslv_x(11, 9, 10));
                    }
                    F3_SRL_SRA => {
                        em.mov_imm64(10, (imm12 & 0x3f) as u64);
                        match imm_hi {
                            0x00 => em.emit(A64Emitter::lsrv_x(11, 9, 10)),
                            0x10 => em.emit(A64Emitter::asrv_x(11, 9, 10)),
                            _ => return None,
                        }
                    }
                    _ => return None,
                }
                store_rd(em, rd);
                Some(EmitFlow::Continue)
            }
            OPCODE_OP_IMM_32 => {
                em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1)));
                match funct3 {
                    F3_ADD_SUB => {
                        em.mov_imm64(10, Self::imm_i(instr) as u64);
                        em.emit(A64Emitter::add_x(11, 9, 10));
                        em.emit(A64Emitter::sxtw_x(11, 11));
                    }
                    F3_SLL => {
                        if funct7 != F7_BASE {
                            return None;
                        }
                        em.mov_imm64(10, (imm12 & 0x1f) as u64);
                        em.emit(A64Emitter::lslv_x(11, 9, 10));
                        em.emit(A64Emitter::sxtw_x(11, 11));
                    }
                    F3_SRL_SRA => {
                        em.mov_imm64(10, (imm12 & 0x1f) as u64);
                        match funct7 {
                            F7_BASE => {
                                em.mov_imm64(12, 0xffff_ffff);
                                em.emit(A64Emitter::and_x(11, 9, 12));
                                em.emit(A64Emitter::lsrv_x(11, 11, 10));
                                em.emit(A64Emitter::sxtw_x(11, 11));
                            }
                            F7_SUB_SRA => {
                                em.emit(A64Emitter::sxtw_x(11, 9));
                                em.emit(A64Emitter::asrv_x(11, 11, 10));
                                em.emit(A64Emitter::sxtw_x(11, 11));
                            }
                            _ => return None,
                        }
                    }
                    _ => return None,
                }
                store_rd(em, rd);
                Some(EmitFlow::Continue)
            }
            OPCODE_OP_32 => {
                em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1)));
                em.emit(A64Emitter::ldr_x(10, 0, Self::reg_off(rs2)));
                match (funct7, funct3) {
                    (F7_BASE, F3_ADD_SUB) => {
                        em.emit(A64Emitter::add_x(11, 9, 10));
                        em.emit(A64Emitter::sxtw_x(11, 11));
                    }
                    (F7_SUB_SRA, F3_ADD_SUB) => {
                        em.emit(A64Emitter::sub_x(11, 9, 10));
                        em.emit(A64Emitter::sxtw_x(11, 11));
                    }
                    (F7_BASE, F3_SLL) => {
                        em.mov_imm64(12, 31);
                        em.emit(A64Emitter::and_x(10, 10, 12));
                        em.emit(A64Emitter::lslv_x(11, 9, 10));
                        em.emit(A64Emitter::sxtw_x(11, 11));
                    }
                    (F7_BASE, F3_SRL_SRA) => {
                        em.mov_imm64(12, 0xffff_ffff);
                        em.emit(A64Emitter::and_x(11, 9, 12));
                        em.mov_imm64(13, 31);
                        em.emit(A64Emitter::and_x(10, 10, 13));
                        em.emit(A64Emitter::lsrv_x(11, 11, 10));
                        em.emit(A64Emitter::sxtw_x(11, 11));
                    }
                    (F7_SUB_SRA, F3_SRL_SRA) => {
                        em.emit(A64Emitter::sxtw_x(11, 9));
                        em.mov_imm64(12, 31);
                        em.emit(A64Emitter::and_x(10, 10, 12));
                        em.emit(A64Emitter::asrv_x(11, 11, 10));
                        em.emit(A64Emitter::sxtw_x(11, 11));
                    }
                    (F7_MULDIV, F3_ADD_SUB) => {
                        // MULW
                        em.emit(A64Emitter::mul_x(11, 9, 10));
                        em.emit(A64Emitter::sxtw_x(11, 11));
                    }
                    (F7_MULDIV, F3_XOR) => {
                        // DIVW
                        em.emit(A64Emitter::sxtw_x(9, 9));
                        em.emit(A64Emitter::sxtw_x(10, 10));
                        em.emit(A64Emitter::sdiv_x(11, 9, 10));
                        em.mov_imm64(12, 0);
                        em.emit(A64Emitter::cmp_x(10, 12));
                        em.mov_imm64(13, u64::MAX);
                        em.emit(A64Emitter::csel_x(11, 13, 11, C_EQ));
                        em.emit(A64Emitter::sxtw_x(11, 11));
                    }
                    (F7_MULDIV, F3_SRL_SRA) => {
                        // DIVUW
                        em.mov_imm64(12, 0xffff_ffff);
                        em.emit(A64Emitter::and_x(9, 9, 12));
                        em.emit(A64Emitter::and_x(10, 10, 12));
                        em.emit(A64Emitter::udiv_x(11, 9, 10));
                        em.mov_imm64(13, 0);
                        em.emit(A64Emitter::cmp_x(10, 13));
                        em.mov_imm64(14, u64::MAX);
                        em.emit(A64Emitter::csel_x(11, 14, 11, C_EQ));
                        em.emit(A64Emitter::sxtw_x(11, 11));
                    }
                    (F7_MULDIV, F3_OR) => {
                        // REMW
                        em.emit(A64Emitter::sxtw_x(9, 9));
                        em.emit(A64Emitter::sxtw_x(10, 10));
                        em.emit(A64Emitter::sdiv_x(12, 9, 10));
                        em.emit(A64Emitter::mul_x(12, 12, 10));
                        em.emit(A64Emitter::sub_x(11, 9, 12));
                        em.mov_imm64(13, 0);
                        em.emit(A64Emitter::cmp_x(10, 13));
                        em.emit(A64Emitter::csel_x(11, 9, 11, C_EQ));
                        em.emit(A64Emitter::sxtw_x(11, 11));
                    }
                    (F7_MULDIV, F3_AND) => {
                        // REMUW
                        em.mov_imm64(12, 0xffff_ffff);
                        em.emit(A64Emitter::and_x(9, 9, 12));
                        em.emit(A64Emitter::and_x(10, 10, 12));
                        em.emit(A64Emitter::udiv_x(13, 9, 10));
                        em.emit(A64Emitter::mul_x(13, 13, 10));
                        em.emit(A64Emitter::sub_x(11, 9, 13));
                        em.mov_imm64(14, 0);
                        em.emit(A64Emitter::cmp_x(10, 14));
                        em.emit(A64Emitter::csel_x(11, 9, 11, C_EQ));
                        em.emit(A64Emitter::sxtw_x(11, 11));
                    }
                    _ => return None,
                }
                store_rd(em, rd);
                Some(EmitFlow::Continue)
            }
            OPCODE_OP => {
                em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1)));
                em.emit(A64Emitter::ldr_x(10, 0, Self::reg_off(rs2)));
                match (funct7, funct3) {
                    (F7_BASE, F3_ADD_SUB) => em.emit(A64Emitter::add_x(11, 9, 10)),
                    (F7_SUB_SRA, F3_ADD_SUB) => em.emit(A64Emitter::sub_x(11, 9, 10)),
                    (F7_BASE, F3_SLT) => {
                        em.emit(A64Emitter::cmp_x(9, 10));
                        em.mov_imm64(12, 1);
                        em.mov_imm64(13, 0);
                        em.emit(A64Emitter::csel_x(11, 12, 13, C_LT));
                    }
                    (F7_BASE, F3_SLTU) => {
                        em.emit(A64Emitter::cmp_x(9, 10));
                        em.mov_imm64(12, 1);
                        em.mov_imm64(13, 0);
                        em.emit(A64Emitter::csel_x(11, 12, 13, C_CC));
                    }
                    (F7_BASE, F3_AND) => em.emit(A64Emitter::and_x(11, 9, 10)),
                    (F7_BASE, F3_OR) => em.emit(A64Emitter::orr_x(11, 9, 10)),
                    (F7_BASE, F3_XOR) => em.emit(A64Emitter::eor_x(11, 9, 10)),
                    (F7_BASE, F3_SLL) => em.emit(A64Emitter::lslv_x(11, 9, 10)),
                    (F7_BASE, F3_SRL_SRA) => em.emit(A64Emitter::lsrv_x(11, 9, 10)),
                    (F7_SUB_SRA, F3_SRL_SRA) => em.emit(A64Emitter::asrv_x(11, 9, 10)),
                    (F7_MULDIV, F3_ADD_SUB) => em.emit(A64Emitter::mul_x(11, 9, 10)),
                    (F7_MULDIV, F3_SLL) => em.emit(A64Emitter::smulh_x(11, 9, 10)),
                    (F7_MULDIV, F3_SLT) => {
                        // MULHSU = high64((rs1 as i64) * (rs2 as u64))
                        em.emit(A64Emitter::umulh_x(11, 9, 10));
                        em.mov_imm64(12, 0);
                        em.emit(A64Emitter::cmp_x(9, 12));
                        em.mov_imm64(13, 0);
                        em.emit(A64Emitter::csel_x(12, 10, 13, C_MI));
                        em.emit(A64Emitter::sub_x(11, 11, 12));
                    }
                    (F7_MULDIV, F3_SLTU) => em.emit(A64Emitter::umulh_x(11, 9, 10)),
                    (F7_MULDIV, F3_XOR) => {
                        // DIV
                        em.emit(A64Emitter::sdiv_x(11, 9, 10));
                        em.mov_imm64(12, 0);
                        em.emit(A64Emitter::cmp_x(10, 12));
                        em.mov_imm64(13, u64::MAX);
                        em.emit(A64Emitter::csel_x(11, 13, 11, C_EQ));
                        em.mov_imm64(12, i64::MIN as u64);
                        em.emit(A64Emitter::cmp_x(9, 12));
                        em.mov_imm64(14, 1);
                        em.mov_imm64(15, 0);
                        em.emit(A64Emitter::csel_x(14, 14, 15, C_EQ));
                        em.mov_imm64(12, u64::MAX);
                        em.emit(A64Emitter::cmp_x(10, 12));
                        em.mov_imm64(15, 1);
                        em.mov_imm64(16, 0);
                        em.emit(A64Emitter::csel_x(15, 15, 16, C_EQ));
                        em.emit(A64Emitter::and_x(14, 14, 15));
                        em.mov_imm64(16, 1);
                        em.emit(A64Emitter::cmp_x(14, 16));
                        em.emit(A64Emitter::csel_x(11, 9, 11, C_EQ));
                    }
                    (F7_MULDIV, F3_SRL_SRA) => {
                        // DIVU
                        em.emit(A64Emitter::udiv_x(11, 9, 10));
                        em.mov_imm64(12, 0);
                        em.emit(A64Emitter::cmp_x(10, 12));
                        em.mov_imm64(13, u64::MAX);
                        em.emit(A64Emitter::csel_x(11, 13, 11, C_EQ));
                    }
                    (F7_MULDIV, F3_OR) => {
                        // REM
                        em.emit(A64Emitter::sdiv_x(12, 9, 10));
                        em.emit(A64Emitter::mul_x(12, 12, 10));
                        em.emit(A64Emitter::sub_x(11, 9, 12));
                        em.mov_imm64(13, 0);
                        em.emit(A64Emitter::cmp_x(10, 13));
                        em.emit(A64Emitter::csel_x(11, 9, 11, C_EQ));
                        em.mov_imm64(12, i64::MIN as u64);
                        em.emit(A64Emitter::cmp_x(9, 12));
                        em.mov_imm64(14, 1);
                        em.mov_imm64(15, 0);
                        em.emit(A64Emitter::csel_x(14, 14, 15, C_EQ));
                        em.mov_imm64(12, u64::MAX);
                        em.emit(A64Emitter::cmp_x(10, 12));
                        em.mov_imm64(15, 1);
                        em.mov_imm64(16, 0);
                        em.emit(A64Emitter::csel_x(15, 15, 16, C_EQ));
                        em.emit(A64Emitter::and_x(14, 14, 15));
                        em.mov_imm64(16, 1);
                        em.emit(A64Emitter::cmp_x(14, 16));
                        em.mov_imm64(17, 0);
                        em.emit(A64Emitter::csel_x(11, 17, 11, C_EQ));
                    }
                    (F7_MULDIV, F3_AND) => {
                        // REMU
                        em.emit(A64Emitter::udiv_x(12, 9, 10));
                        em.emit(A64Emitter::mul_x(12, 12, 10));
                        em.emit(A64Emitter::sub_x(11, 9, 12));
                        em.mov_imm64(13, 0);
                        em.emit(A64Emitter::cmp_x(10, 13));
                        em.emit(A64Emitter::csel_x(11, 9, 11, C_EQ));
                    }
                    _ => return None,
                }
                store_rd(em, rd);
                Some(EmitFlow::Continue)
            }
            OPCODE_MISC_MEM => match funct3 {
                F3_FENCE | F3_FENCE_I => Some(EmitFlow::Continue),
                _ => None,
            },
            _ => None,
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn compile_native_block(
        &mut self,
        bus: &mut impl Bus,
        max_steps: u32,
    ) -> Result<Option<NativeBlock>, Trap> {
        if !self.native_jit.enabled {
            return Ok(None);
        }
        if self.native_jit_trace {
            eprintln!(
                "jit-a64: compile-enter pc=0x{:016x} max_steps={}",
                self.pc, max_steps
            );
        }
        let max_steps = max_steps.min(64);
        if max_steps < 1 {
            return Ok(None);
        }
        let satp = self.satp_cached;
        let start_pc = self.pc;
        let mut pc = start_pc;
        let mut emitted = 0u32;
        let mut terminated = false;
        let mut helper_terminator = false;
        let mut em = A64Emitter::new();
        let mut instr_log: Vec<(u64, u32, u8)> = Vec::new();

        while emitted < max_steps {
            if (pc & 0x1) != 0 {
                if emitted == 0 {
                    self.check_align(pc, 2)?;
                }
                break;
            }
            let instr16 = match self.read_u16(bus, pc, AccessType::Fetch) {
                Ok(v) => v,
                Err(t) => {
                    if emitted == 0 {
                        if self.native_jit_trace {
                            eprintln!("jit-a64: skip pc=0x{:016x} fetch-trap={:?}", pc, t);
                        }
                        return Err(t);
                    }
                    break;
                }
            };

            if (instr16 & 0x3) != 0x3 {
                let Some(flow) = self.emit_native_instr16(&mut em, pc, instr16) else {
                    if self.emit_native_term_helper16(&mut em, pc, instr16, emitted) {
                        helper_terminator = true;
                        terminated = true;
                        emitted += 1;
                        if self.native_jit_trace {
                            instr_log.push((pc, instr16 as u32, 2));
                        }
                        break;
                    }
                    if emitted == 0 && self.native_jit_trace {
                        eprintln!(
                            "jit-a64: skip pc=0x{:016x} unsupported c16=0x{:04x}",
                            pc, instr16
                        );
                    }
                    break;
                };
                if self.native_jit_trace {
                    instr_log.push((pc, instr16 as u32, 2));
                }
                pc = pc.wrapping_add(2);
                emitted += 1;
                if flow == EmitFlow::Terminate {
                    terminated = true;
                    break;
                }
                continue;
            }

            let upper = match self.read_u16(bus, pc.wrapping_add(2), AccessType::Fetch) {
                Ok(v) => v as u32,
                Err(t) => {
                    if emitted == 0 {
                        if self.native_jit_trace {
                            eprintln!("jit-a64: skip pc=0x{:016x} fetch-trap={:?}", pc, t);
                        }
                        return Err(t);
                    }
                    break;
                }
            };
            let instr = (upper << 16) | instr16 as u32;
            let d = Self::decode32(instr);
            let Some(flow) = self.emit_native_instr(&mut em, pc, instr, d) else {
                if self.emit_native_term_helper32(&mut em, pc, instr, d, emitted) {
                    helper_terminator = true;
                    terminated = true;
                    emitted += 1;
                    if self.native_jit_trace {
                        instr_log.push((pc, instr, 4));
                    }
                    break;
                }
                if emitted == 0 && self.native_jit_trace {
                    eprintln!(
                        "jit-a64: skip pc=0x{:016x} unsupported i32=0x{:08x}",
                        pc, instr
                    );
                }
                break;
            };
            if self.native_jit_trace {
                instr_log.push((pc, instr, 4));
            }
            pc = pc.wrapping_add(4);
            emitted += 1;
            if flow == EmitFlow::Terminate {
                terminated = true;
                break;
            }
        }

        if emitted < 1 {
            self.native_jit.mark_failed(satp, start_pc);
            return Ok(None);
        }

        if !helper_terminator {
            if !terminated {
                em.mov_imm64(0, pc);
            }
            em.mov_imm64(1, emitted as u64);
            em.emit(0xD65F_03C0); // ret
        }
        let code = em.finish();

        let Some(cache) = self.native_jit.cache.as_mut() else {
            if self.native_jit_trace {
                eprintln!("jit-a64: disable (missing executable cache)");
            }
            self.native_jit.enabled = false;
            return Ok(None);
        };
        let Some(offset) = cache.alloc(&code) else {
            if self.native_jit_trace {
                eprintln!(
                    "jit-a64: disable (code cache full/alloc failed, used={} size={} block_bytes={})",
                    cache.used,
                    cache.size,
                    code.len()
                );
            }
            self.native_jit.enabled = false;
            return Ok(None);
        };
        let block = NativeBlock {
            offset,
            instrs: emitted,
        };
        self.native_jit.insert(satp, start_pc, block);
        if self.native_jit_trace {
            eprintln!(
                "jit-a64: compiled hart={} satp=0x{:016x} pc=0x{:016x} instrs={}",
                self.hart_id, satp, start_pc, emitted
            );
            for (ipc, raw, len) in instr_log {
                if len == 2 {
                    eprintln!(
                        "  jit-a64:   pc=0x{:016x} c16=0x{:04x} {}",
                        ipc,
                        raw as u16,
                        disas::disas16(raw as u16)
                    );
                } else {
                    eprintln!(
                        "  jit-a64:   pc=0x{:016x} i32=0x{:08x} {}",
                        ipc,
                        raw,
                        disas::disas32(raw)
                    );
                }
            }
        }
        Ok(Some(block))
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    fn compile_native_block(
        &mut self,
        _bus: &mut impl Bus,
        _max_steps: u32,
    ) -> Result<Option<NativeBlock>, Trap> {
        Ok(None)
    }

    #[cfg(not(target_arch = "x86_64"))]
    pub fn try_run_native_jit(
        &mut self,
        bus: &mut impl Bus,
        sbi: &mut impl Sbi,
        max_steps: u32,
    ) -> Result<Option<u32>, Trap> {
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = (bus, sbi, max_steps);
            return Ok(None);
        }
        #[cfg(target_arch = "aarch64")]
        {
            if self.native_jit_trace && !self.native_jit_probe_printed {
                self.native_jit_probe_printed = true;
                eprintln!(
                    "jit-a64: probe pc=0x{:016x} max_steps={} irq_cd={} debug_hooks={} jitter={} enabled={}",
                    self.pc,
                    max_steps,
                    self.irq_check_countdown,
                    self.has_debug_hooks(),
                    self.time_jitter_enabled,
                    self.native_jit.enabled
                );
            }
            if !self.native_jit.enabled || max_steps < 1 || self.has_debug_hooks() {
                return Ok(None);
            }
            if self.time_jitter_enabled {
                return Ok(None);
            }
            if (self.pc & 0x3) != 0 {
                return Ok(None);
            }
            if self.irq_check_countdown <= 1 {
                return Ok(None);
            }
            let mut remaining = max_steps.min(self.irq_check_countdown.saturating_sub(1));
            if remaining < 1 {
                return Ok(None);
            }
            let mut done_total = 0u32;
            while remaining > 0 {
                let satp = self.satp_cached;
                let start_pc = self.pc;
                let mut block = self.native_jit.lookup(satp, start_pc);
                if block.is_none() {
                    if self.native_jit.is_failed(satp, start_pc) {
                        break;
                    }
                    if self.native_jit_hot_threshold > 1 {
                        let seen = self.native_jit.bump_hot(satp, start_pc);
                        if seen < self.native_jit_hot_threshold {
                            break;
                        }
                    }
                    block = match self.compile_native_block(bus, remaining) {
                        Ok(v) => v,
                        Err(_) => {
                            self.native_jit.mark_failed(satp, start_pc);
                            None
                        }
                    };
                }
                let Some(block) = block else {
                    break;
                };
                if block.instrs < 1 || block.instrs > remaining {
                    break;
                }

                let Some(cache) = self.native_jit.cache.as_ref() else {
                    self.native_jit.enabled = false;
                    break;
                };
                cache.prepare_execute();
                let fn_ptr = cache.ptr_at(block.offset);
                let func: NativeBlockFn = unsafe { std::mem::transmute(fn_ptr) };
                let bus_dyn: &mut dyn Bus = bus;
                let bus_ptr: *mut dyn Bus = bus_dyn as *mut dyn Bus;
                let (bus_data, bus_vtable): (*mut (), *mut ()) =
                    unsafe { std::mem::transmute::<*mut dyn Bus, (*mut (), *mut ())>(bus_ptr) };
                let sbi_dyn: &mut dyn Sbi = sbi;
                let sbi_ptr: *mut dyn Sbi = sbi_dyn as *mut dyn Sbi;
                let (sbi_data, sbi_vtable): (*mut (), *mut ()) =
                    unsafe { std::mem::transmute::<*mut dyn Sbi, (*mut (), *mut ())>(sbi_ptr) };
                let res = unsafe {
                    func(
                        self.regs.as_mut_ptr(),
                        self as *mut Hart,
                        bus_data,
                        bus_vtable,
                        sbi_data,
                        sbi_vtable,
                    )
                };
                let done_raw = res.executed;
                let done = (done_raw & !NATIVE_EXEC_FLAG_LAST_TRAP) as u32;
                if done != block.instrs || done == 0 {
                    break;
                }

                self.pc = res.next_pc;
                self.regs[0] = 0;
                done_total = done_total.saturating_add(done);
                remaining = remaining.saturating_sub(done);

                // Match interpreter-visible timing/accounting semantics between
                // native blocks, so subsequent helpers (e.g. CSR reads) observe
                // up-to-date counters.
                let retired = done.saturating_sub(((done_raw & NATIVE_EXEC_FLAG_LAST_TRAP) != 0) as u32);
                self.instret_pending = self.instret_pending.wrapping_add(retired as u64);
                let total = self.time_div_accum.saturating_add(done);
                if total >= self.time_divider {
                    let ticks = total / self.time_divider;
                    self.time_div_accum = total % self.time_divider;
                    self.csrs.increment_time(ticks as u64);
                } else {
                    self.time_div_accum = total;
                }
                self.irq_check_countdown = self.irq_check_countdown.saturating_sub(done);
                if self.irq_check_countdown <= 1 {
                    break;
                }
            }
            if done_total == 0 {
                return Ok(None);
            }
            Ok(Some(done_total))
        }
    }
}
