use super::*;

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum X64EmitFlow {
    Continue,
    Terminate,
}

#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
#[repr(u8)]
enum X64Cc {
    B = 0x2,
    AE = 0x3,
    E = 0x4,
    NE = 0x5,
    L = 0xC,
    GE = 0xD,
}

#[cfg(target_arch = "x86_64")]
struct X64Emitter {
    bytes: Vec<u8>,
}

#[cfg(target_arch = "x86_64")]
impl X64Emitter {
    const RAX: u8 = 0;
    const RCX: u8 = 1;
    const RDX: u8 = 2;
    const RBX: u8 = 3;
    const RSP: u8 = 4;
    const RBP: u8 = 5;
    const RSI: u8 = 6;
    const RDI: u8 = 7;
    const R8: u8 = 8;
    const R9: u8 = 9;
    const R10: u8 = 10;
    const R11: u8 = 11;
    const R12: u8 = 12;
    const R13: u8 = 13;
    const R14: u8 = 14;
    const R15: u8 = 15;

    fn new() -> Self {
        Self {
            bytes: Vec::with_capacity(512),
        }
    }

    #[inline]
    fn emit_u8(&mut self, b: u8) {
        self.bytes.push(b);
    }

    #[inline]
    fn emit_u32(&mut self, v: u32) {
        self.bytes.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    fn emit_u64(&mut self, v: u64) {
        self.bytes.extend_from_slice(&v.to_le_bytes());
    }

    #[inline]
    fn emit_rex(&mut self, w: bool, r: u8, x: u8, b: u8) {
        let rex = 0x40
            | ((w as u8) << 3)
            | (((r >> 3) & 1) << 2)
            | (((x >> 3) & 1) << 1)
            | ((b >> 3) & 1);
        if rex != 0x40 {
            self.emit_u8(rex);
        }
    }

    #[inline]
    fn emit_modrm(&mut self, mode: u8, reg: u8, rm: u8) {
        self.emit_u8(((mode & 0x3) << 6) | ((reg & 0x7) << 3) | (rm & 0x7));
    }

    #[inline]
    fn emit_sib(&mut self, scale: u8, index: u8, base: u8) {
        self.emit_u8(((scale & 0x3) << 6) | ((index & 0x7) << 3) | (base & 0x7));
    }

    fn emit_mem_disp32(&mut self, reg_field: u8, base: u8, disp: i32) {
        if (base & 0x7) == 0x4 {
            self.emit_modrm(0b10, reg_field, 0x4);
            self.emit_sib(0, 0x4, base & 0x7);
        } else {
            self.emit_modrm(0b10, reg_field, base & 0x7);
        }
        self.emit_u32(disp as u32);
    }

    fn push_r64(&mut self, reg: u8) {
        if reg >= 8 {
            self.emit_u8(0x41);
        }
        self.emit_u8(0x50 + (reg & 0x7));
    }

    fn pop_r64(&mut self, reg: u8) {
        if reg >= 8 {
            self.emit_u8(0x41);
        }
        self.emit_u8(0x58 + (reg & 0x7));
    }

    fn mov_r64_r64(&mut self, dst: u8, src: u8) {
        self.emit_rex(true, src, 0, dst);
        self.emit_u8(0x89);
        self.emit_modrm(0b11, src, dst);
    }

    fn mov_r64_imm64(&mut self, dst: u8, imm: u64) {
        self.emit_rex(true, 0, 0, dst);
        self.emit_u8(0xB8 + (dst & 0x7));
        self.emit_u64(imm);
    }

    fn mov_r64_m64_disp32(&mut self, dst: u8, base: u8, disp: i32) {
        self.emit_rex(true, dst, 0, base);
        self.emit_u8(0x8B);
        self.emit_mem_disp32(dst, base, disp);
    }

    fn mov_m64_disp32_r64(&mut self, base: u8, disp: i32, src: u8) {
        self.emit_rex(true, src, 0, base);
        self.emit_u8(0x89);
        self.emit_mem_disp32(src, base, disp);
    }

    fn add_r64_r64(&mut self, dst: u8, src: u8) {
        self.emit_rex(true, src, 0, dst);
        self.emit_u8(0x01);
        self.emit_modrm(0b11, src, dst);
    }

    fn add_r32_r32(&mut self, dst: u8, src: u8) {
        self.emit_rex(false, src, 0, dst);
        self.emit_u8(0x01);
        self.emit_modrm(0b11, src, dst);
    }

    fn add_r64_imm32(&mut self, dst: u8, imm: i32) {
        self.emit_rex(true, 0, 0, dst);
        self.emit_u8(0x81);
        self.emit_modrm(0b11, 0, dst);
        self.emit_u32(imm as u32);
    }

    fn sub_r64_r64(&mut self, dst: u8, src: u8) {
        self.emit_rex(true, src, 0, dst);
        self.emit_u8(0x29);
        self.emit_modrm(0b11, src, dst);
    }

    fn sub_r32_r32(&mut self, dst: u8, src: u8) {
        self.emit_rex(false, src, 0, dst);
        self.emit_u8(0x29);
        self.emit_modrm(0b11, src, dst);
    }

    fn and_r64_r64(&mut self, dst: u8, src: u8) {
        self.emit_rex(true, src, 0, dst);
        self.emit_u8(0x21);
        self.emit_modrm(0b11, src, dst);
    }

    fn and_r64_imm32(&mut self, dst: u8, imm: i32) {
        self.emit_rex(true, 0, 0, dst);
        self.emit_u8(0x81);
        self.emit_modrm(0b11, 4, dst);
        self.emit_u32(imm as u32);
    }

    fn or_r64_r64(&mut self, dst: u8, src: u8) {
        self.emit_rex(true, src, 0, dst);
        self.emit_u8(0x09);
        self.emit_modrm(0b11, src, dst);
    }

    fn xor_r64_r64(&mut self, dst: u8, src: u8) {
        self.emit_rex(true, src, 0, dst);
        self.emit_u8(0x31);
        self.emit_modrm(0b11, src, dst);
    }

    fn xor_r64_imm32(&mut self, dst: u8, imm: i32) {
        self.emit_rex(true, 0, 0, dst);
        self.emit_u8(0x81);
        self.emit_modrm(0b11, 6, dst);
        self.emit_u32(imm as u32);
    }

    fn or_r64_imm32(&mut self, dst: u8, imm: i32) {
        self.emit_rex(true, 0, 0, dst);
        self.emit_u8(0x81);
        self.emit_modrm(0b11, 1, dst);
        self.emit_u32(imm as u32);
    }

    fn and_r64_imm8(&mut self, dst: u8, imm: i8) {
        self.emit_rex(true, 0, 0, dst);
        self.emit_u8(0x83);
        self.emit_modrm(0b11, 4, dst);
        self.emit_u8(imm as u8);
    }

    fn cmp_r64_r64(&mut self, lhs: u8, rhs: u8) {
        self.emit_rex(true, rhs, 0, lhs);
        self.emit_u8(0x39);
        self.emit_modrm(0b11, rhs, lhs);
    }

    fn cmp_r64_imm32(&mut self, lhs: u8, imm: i32) {
        self.emit_rex(true, 0, 0, lhs);
        self.emit_u8(0x81);
        self.emit_modrm(0b11, 7, lhs);
        self.emit_u32(imm as u32);
    }

    fn shl_r64_cl(&mut self, reg: u8) {
        self.emit_rex(true, 0, 0, reg);
        self.emit_u8(0xD3);
        self.emit_modrm(0b11, 4, reg);
    }

    fn shr_r64_cl(&mut self, reg: u8) {
        self.emit_rex(true, 0, 0, reg);
        self.emit_u8(0xD3);
        self.emit_modrm(0b11, 5, reg);
    }

    fn sar_r64_cl(&mut self, reg: u8) {
        self.emit_rex(true, 0, 0, reg);
        self.emit_u8(0xD3);
        self.emit_modrm(0b11, 7, reg);
    }

    fn shl_r64_imm8(&mut self, reg: u8, imm: u8) {
        self.emit_rex(true, 0, 0, reg);
        self.emit_u8(0xC1);
        self.emit_modrm(0b11, 4, reg);
        self.emit_u8(imm);
    }

    fn shr_r64_imm8(&mut self, reg: u8, imm: u8) {
        self.emit_rex(true, 0, 0, reg);
        self.emit_u8(0xC1);
        self.emit_modrm(0b11, 5, reg);
        self.emit_u8(imm);
    }

    fn sar_r64_imm8(&mut self, reg: u8, imm: u8) {
        self.emit_rex(true, 0, 0, reg);
        self.emit_u8(0xC1);
        self.emit_modrm(0b11, 7, reg);
        self.emit_u8(imm);
    }

    fn shl_r32_cl(&mut self, reg: u8) {
        self.emit_rex(false, 0, 0, reg);
        self.emit_u8(0xD3);
        self.emit_modrm(0b11, 4, reg);
    }

    fn shr_r32_cl(&mut self, reg: u8) {
        self.emit_rex(false, 0, 0, reg);
        self.emit_u8(0xD3);
        self.emit_modrm(0b11, 5, reg);
    }

    fn sar_r32_cl(&mut self, reg: u8) {
        self.emit_rex(false, 0, 0, reg);
        self.emit_u8(0xD3);
        self.emit_modrm(0b11, 7, reg);
    }

    fn shl_r32_imm8(&mut self, reg: u8, imm: u8) {
        self.emit_rex(false, 0, 0, reg);
        self.emit_u8(0xC1);
        self.emit_modrm(0b11, 4, reg);
        self.emit_u8(imm);
    }

    fn shr_r32_imm8(&mut self, reg: u8, imm: u8) {
        self.emit_rex(false, 0, 0, reg);
        self.emit_u8(0xC1);
        self.emit_modrm(0b11, 5, reg);
        self.emit_u8(imm);
    }

    fn sar_r32_imm8(&mut self, reg: u8, imm: u8) {
        self.emit_rex(false, 0, 0, reg);
        self.emit_u8(0xC1);
        self.emit_modrm(0b11, 7, reg);
        self.emit_u8(imm);
    }

    fn imul_r64_r64(&mut self, dst: u8, src: u8) {
        self.emit_rex(true, dst, 0, src);
        self.emit_u8(0x0F);
        self.emit_u8(0xAF);
        self.emit_modrm(0b11, dst, src);
    }

    fn imul_r32_r32(&mut self, dst: u8, src: u8) {
        self.emit_rex(false, dst, 0, src);
        self.emit_u8(0x0F);
        self.emit_u8(0xAF);
        self.emit_modrm(0b11, dst, src);
    }

    fn movsxd_r64_r32(&mut self, dst: u8, src: u8) {
        self.emit_rex(true, dst, 0, src);
        self.emit_u8(0x63);
        self.emit_modrm(0b11, dst, src);
    }

    fn setcc_al(&mut self, cc: X64Cc) {
        self.emit_u8(0x0F);
        self.emit_u8(0x90 + (cc as u8));
        self.emit_u8(0xC0);
    }

    fn movzx_r64_r8(&mut self, dst: u8, src: u8) {
        self.emit_rex(true, dst, 0, src);
        self.emit_u8(0x0F);
        self.emit_u8(0xB6);
        self.emit_modrm(0b11, dst, src);
    }

    fn cmovcc_r64_r64(&mut self, dst: u8, src: u8, cc: X64Cc) {
        self.emit_rex(true, dst, 0, src);
        self.emit_u8(0x0F);
        self.emit_u8(0x40 + (cc as u8));
        self.emit_modrm(0b11, dst, src);
    }

    fn sub_rsp_imm8(&mut self, imm: u8) {
        self.emit_rex(true, 0, 0, Self::RSP);
        self.emit_u8(0x83);
        self.emit_modrm(0b11, 5, Self::RSP);
        self.emit_u8(imm);
    }

    fn add_rsp_imm8(&mut self, imm: u8) {
        self.emit_rex(true, 0, 0, Self::RSP);
        self.emit_u8(0x83);
        self.emit_modrm(0b11, 0, Self::RSP);
        self.emit_u8(imm);
    }

    fn call_rax(&mut self) {
        self.emit_u8(0xFF);
        self.emit_u8(0xD0);
    }

    fn ret(&mut self) {
        self.emit_u8(0xC3);
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

impl Hart {
    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn x64_emit_prologue(em: &mut X64Emitter) {
        em.push_r64(X64Emitter::RBX);
        em.push_r64(X64Emitter::RBP);
        em.push_r64(X64Emitter::R12);
        em.push_r64(X64Emitter::R13);
        em.push_r64(X64Emitter::R14);
        em.push_r64(X64Emitter::R15);
        em.sub_rsp_imm8(8);

        // Keep incoming block-call arguments in callee-saved registers.
        em.mov_r64_r64(X64Emitter::RBX, X64Emitter::RDI); // regs_ptr
        em.mov_r64_r64(X64Emitter::R12, X64Emitter::RSI); // hart_ptr
        em.mov_r64_r64(X64Emitter::R13, X64Emitter::RDX); // bus_data
        em.mov_r64_r64(X64Emitter::R14, X64Emitter::RCX); // bus_vtable
        em.mov_r64_r64(X64Emitter::R15, X64Emitter::R8); // sbi_data
        em.mov_r64_r64(X64Emitter::RBP, X64Emitter::R9); // sbi_vtable
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn x64_emit_epilogue(em: &mut X64Emitter) {
        em.add_rsp_imm8(8);
        em.pop_r64(X64Emitter::R15);
        em.pop_r64(X64Emitter::R14);
        em.pop_r64(X64Emitter::R13);
        em.pop_r64(X64Emitter::R12);
        em.pop_r64(X64Emitter::RBP);
        em.pop_r64(X64Emitter::RBX);
        em.ret();
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn x64_reg_disp(reg: usize) -> i32 {
        Self::reg_off(reg) as i32
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn x64_emit_load_reg(em: &mut X64Emitter, host: u8, reg: usize) {
        em.mov_r64_m64_disp32(host, X64Emitter::RBX, Self::x64_reg_disp(reg));
    }

    #[cfg(target_arch = "x86_64")]
    #[inline]
    fn x64_emit_store_reg(em: &mut X64Emitter, reg: usize, host: u8) {
        if reg != 0 {
            em.mov_m64_disp32_r64(X64Emitter::RBX, Self::x64_reg_disp(reg), host);
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn emit_native_instr_x64(
        &self,
        em: &mut X64Emitter,
        pc: u64,
        instr: u32,
        d: Decoded32,
    ) -> Option<X64EmitFlow> {
        let opcode = d.opcode as u32;
        let rd = d.rd as usize;
        let funct3 = d.funct3 as u32;
        let rs1 = d.rs1 as usize;
        let rs2 = d.rs2 as usize;
        let funct7 = d.funct7 as u32;
        let imm12 = d.imm12 as u32;
        let shamt = (imm12 & 0x3f) as u8;
        let imm_hi = (imm12 >> 6) & 0x3f;

        let store_rd = |em: &mut X64Emitter, rd: usize| {
            Self::x64_emit_store_reg(em, rd, X64Emitter::R10);
        };

        match opcode {
            OPCODE_LUI => {
                if rd != 0 {
                    em.mov_r64_imm64(X64Emitter::R10, Self::imm_u(instr) as u64);
                    store_rd(em, rd);
                }
                Some(X64EmitFlow::Continue)
            }
            OPCODE_AUIPC => {
                if rd != 0 {
                    em.mov_r64_imm64(
                        X64Emitter::R10,
                        pc.wrapping_add(Self::imm_u(instr) as u64),
                    );
                    store_rd(em, rd);
                }
                Some(X64EmitFlow::Continue)
            }
            OPCODE_JAL => {
                if rd != 0 {
                    em.mov_r64_imm64(X64Emitter::R10, pc.wrapping_add(4));
                    store_rd(em, rd);
                }
                em.mov_r64_imm64(X64Emitter::RAX, pc.wrapping_add(Self::imm_j(instr) as u64));
                Some(X64EmitFlow::Terminate)
            }
            OPCODE_JALR => {
                Self::x64_emit_load_reg(em, X64Emitter::R10, rs1);
                em.add_r64_imm32(X64Emitter::R10, Self::imm_i(instr) as i32);
                em.and_r64_imm32(X64Emitter::R10, -2);
                if rd != 0 {
                    em.mov_r64_imm64(X64Emitter::R11, pc.wrapping_add(4));
                    Self::x64_emit_store_reg(em, rd, X64Emitter::R11);
                }
                em.mov_r64_r64(X64Emitter::RAX, X64Emitter::R10);
                Some(X64EmitFlow::Terminate)
            }
            OPCODE_BRANCH => {
                Self::x64_emit_load_reg(em, X64Emitter::R10, rs1);
                Self::x64_emit_load_reg(em, X64Emitter::R11, rs2);
                em.cmp_r64_r64(X64Emitter::R10, X64Emitter::R11);
                let cc = match funct3 {
                    F3_BEQ => X64Cc::E,
                    F3_BNE => X64Cc::NE,
                    F3_BLT => X64Cc::L,
                    F3_BGE => X64Cc::GE,
                    F3_BLTU => X64Cc::B,
                    F3_BGEU => X64Cc::AE,
                    _ => return None,
                };
                em.mov_r64_imm64(X64Emitter::R11, pc.wrapping_add(4));
                em.mov_r64_imm64(X64Emitter::RAX, pc.wrapping_add(Self::imm_b(instr) as u64));
                em.cmovcc_r64_r64(X64Emitter::R11, X64Emitter::RAX, cc);
                em.mov_r64_r64(X64Emitter::RAX, X64Emitter::R11);
                Some(X64EmitFlow::Terminate)
            }
            OPCODE_OP_IMM => {
                Self::x64_emit_load_reg(em, X64Emitter::R10, rs1);
                match funct3 {
                    F3_ADD_SUB => {
                        em.add_r64_imm32(X64Emitter::R10, Self::imm_i(instr) as i32);
                    }
                    F3_SLT => {
                        em.cmp_r64_imm32(X64Emitter::R10, Self::imm_i(instr) as i32);
                        em.setcc_al(X64Cc::L);
                        em.movzx_r64_r8(X64Emitter::R10, X64Emitter::RAX);
                    }
                    F3_SLTU => {
                        em.cmp_r64_imm32(X64Emitter::R10, Self::imm_i(instr) as i32);
                        em.setcc_al(X64Cc::B);
                        em.movzx_r64_r8(X64Emitter::R10, X64Emitter::RAX);
                    }
                    F3_XOR => {
                        em.xor_r64_imm32(X64Emitter::R10, Self::imm_i(instr) as i32);
                    }
                    F3_OR => {
                        em.or_r64_imm32(X64Emitter::R10, Self::imm_i(instr) as i32);
                    }
                    F3_AND => {
                        em.and_r64_imm32(X64Emitter::R10, Self::imm_i(instr) as i32);
                    }
                    F3_SLL => {
                        if imm_hi != 0 {
                            return None;
                        }
                        em.shl_r64_imm8(X64Emitter::R10, shamt);
                    }
                    F3_SRL_SRA => match imm_hi {
                        0x00 => em.shr_r64_imm8(X64Emitter::R10, shamt),
                        0x10 => em.sar_r64_imm8(X64Emitter::R10, shamt),
                        _ => return None,
                    },
                    _ => return None,
                }
                store_rd(em, rd);
                Some(X64EmitFlow::Continue)
            }
            OPCODE_OP_IMM_32 => {
                Self::x64_emit_load_reg(em, X64Emitter::R10, rs1);
                match funct3 {
                    F3_ADD_SUB => {
                        em.add_r64_imm32(X64Emitter::R10, Self::imm_i(instr) as i32);
                    }
                    F3_SLL => {
                        if funct7 != F7_BASE {
                            return None;
                        }
                        em.shl_r32_imm8(X64Emitter::R10, (imm12 & 0x1f) as u8);
                    }
                    F3_SRL_SRA => {
                        match funct7 {
                            F7_BASE => em.shr_r32_imm8(X64Emitter::R10, (imm12 & 0x1f) as u8),
                            F7_SUB_SRA => em.sar_r32_imm8(X64Emitter::R10, (imm12 & 0x1f) as u8),
                            _ => return None,
                        }
                    }
                    _ => return None,
                }
                em.movsxd_r64_r32(X64Emitter::R10, X64Emitter::R10);
                store_rd(em, rd);
                Some(X64EmitFlow::Continue)
            }
            OPCODE_OP => {
                Self::x64_emit_load_reg(em, X64Emitter::R10, rs1);
                Self::x64_emit_load_reg(em, X64Emitter::R11, rs2);
                match (funct7, funct3) {
                    (F7_BASE, F3_ADD_SUB) => em.add_r64_r64(X64Emitter::R10, X64Emitter::R11),
                    (F7_SUB_SRA, F3_ADD_SUB) => em.sub_r64_r64(X64Emitter::R10, X64Emitter::R11),
                    (F7_BASE, F3_AND) => em.and_r64_r64(X64Emitter::R10, X64Emitter::R11),
                    (F7_BASE, F3_OR) => em.or_r64_r64(X64Emitter::R10, X64Emitter::R11),
                    (F7_BASE, F3_XOR) => em.xor_r64_r64(X64Emitter::R10, X64Emitter::R11),
                    (F7_BASE, F3_SLL) => {
                        em.mov_r64_r64(X64Emitter::RCX, X64Emitter::R11);
                        em.shl_r64_cl(X64Emitter::R10);
                    }
                    (F7_BASE, F3_SRL_SRA) => {
                        em.mov_r64_r64(X64Emitter::RCX, X64Emitter::R11);
                        em.shr_r64_cl(X64Emitter::R10);
                    }
                    (F7_SUB_SRA, F3_SRL_SRA) => {
                        em.mov_r64_r64(X64Emitter::RCX, X64Emitter::R11);
                        em.sar_r64_cl(X64Emitter::R10);
                    }
                    (F7_BASE, F3_SLT) => {
                        em.cmp_r64_r64(X64Emitter::R10, X64Emitter::R11);
                        em.setcc_al(X64Cc::L);
                        em.movzx_r64_r8(X64Emitter::R10, X64Emitter::RAX);
                    }
                    (F7_BASE, F3_SLTU) => {
                        em.cmp_r64_r64(X64Emitter::R10, X64Emitter::R11);
                        em.setcc_al(X64Cc::B);
                        em.movzx_r64_r8(X64Emitter::R10, X64Emitter::RAX);
                    }
                    (F7_MULDIV, F3_ADD_SUB) => em.imul_r64_r64(X64Emitter::R10, X64Emitter::R11),
                    _ => return None,
                }
                store_rd(em, rd);
                Some(X64EmitFlow::Continue)
            }
            OPCODE_OP_32 => {
                Self::x64_emit_load_reg(em, X64Emitter::R10, rs1);
                Self::x64_emit_load_reg(em, X64Emitter::R11, rs2);
                match (funct7, funct3) {
                    (F7_BASE, F3_ADD_SUB) => em.add_r32_r32(X64Emitter::R10, X64Emitter::R11),
                    (F7_SUB_SRA, F3_ADD_SUB) => em.sub_r32_r32(X64Emitter::R10, X64Emitter::R11),
                    (F7_BASE, F3_SLL) => {
                        em.mov_r64_r64(X64Emitter::RCX, X64Emitter::R11);
                        em.and_r64_imm8(X64Emitter::RCX, 0x1f);
                        em.shl_r32_cl(X64Emitter::R10);
                    }
                    (F7_BASE, F3_SRL_SRA) => {
                        em.mov_r64_r64(X64Emitter::RCX, X64Emitter::R11);
                        em.and_r64_imm8(X64Emitter::RCX, 0x1f);
                        em.shr_r32_cl(X64Emitter::R10);
                    }
                    (F7_SUB_SRA, F3_SRL_SRA) => {
                        em.mov_r64_r64(X64Emitter::RCX, X64Emitter::R11);
                        em.and_r64_imm8(X64Emitter::RCX, 0x1f);
                        em.sar_r32_cl(X64Emitter::R10);
                    }
                    (F7_MULDIV, F3_ADD_SUB) => em.imul_r32_r32(X64Emitter::R10, X64Emitter::R11),
                    _ => return None,
                }
                em.movsxd_r64_r32(X64Emitter::R10, X64Emitter::R10);
                store_rd(em, rd);
                Some(X64EmitFlow::Continue)
            }
            OPCODE_MISC_MEM => match funct3 {
                F3_FENCE | F3_FENCE_I => Some(X64EmitFlow::Continue),
                _ => None,
            },
            _ => None,
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn emit_native_term_helper16_x64(
        &self,
        em: &mut X64Emitter,
        pc: u64,
        instr: u16,
        prefix_count: u32,
    ) {
        em.mov_r64_r64(X64Emitter::RDI, X64Emitter::R12);
        em.mov_r64_r64(X64Emitter::RSI, X64Emitter::R13);
        em.mov_r64_r64(X64Emitter::RDX, X64Emitter::R14);
        em.mov_r64_imm64(X64Emitter::RCX, instr as u64);
        em.mov_r64_imm64(X64Emitter::R8, pc);
        em.mov_r64_imm64(
            X64Emitter::RAX,
            Self::native_exec16_term_helper_x64 as *const () as usize as u64,
        );
        em.call_rax();
        if prefix_count != 0 {
            em.add_r64_imm32(X64Emitter::RDX, prefix_count as i32);
        }
        Self::x64_emit_epilogue(em);
    }

    #[cfg(target_arch = "x86_64")]
    fn emit_native_term_mem_helper_x64(
        &self,
        em: &mut X64Emitter,
        pc: u64,
        instr: u32,
        prefix_count: u32,
    ) -> bool {
        let d = Self::decode32(instr);
        let opcode = d.opcode as u32;
        let funct3 = d.funct3 as u32;
        let supported = match opcode {
            OPCODE_LOAD => matches!(
                funct3,
                F3_LB | F3_LH | F3_LW | F3_LD | F3_LBU | F3_LHU | F3_LWU
            ),
            OPCODE_STORE => matches!(funct3, F3_SB | F3_SH | F3_SW | F3_SD),
            _ => false,
        };
        if !supported {
            return false;
        }

        em.mov_r64_r64(X64Emitter::RDI, X64Emitter::R12);
        em.mov_r64_r64(X64Emitter::RSI, X64Emitter::R13);
        em.mov_r64_r64(X64Emitter::RDX, X64Emitter::R14);
        em.mov_r64_imm64(X64Emitter::RCX, instr as u64);
        em.mov_r64_imm64(X64Emitter::R8, pc);
        em.mov_r64_imm64(
            X64Emitter::RAX,
            Self::native_exec_mem_term_helper_x64 as *const () as usize as u64,
        );
        em.call_rax();
        if prefix_count != 0 {
            em.add_r64_imm32(X64Emitter::RDX, prefix_count as i32);
        }
        Self::x64_emit_epilogue(em);
        true
    }

    #[cfg(target_arch = "x86_64")]
    unsafe extern "C" fn native_exec16_term_helper_x64(
        hart_ptr: *mut Hart,
        bus_data: *mut (),
        bus_vtable: *mut (),
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

        hart.pc = pc;
        let instret_before = hart.instret_pending;
        match hart.exec_compressed(bus, instr as u16) {
            Ok(()) => {
                hart.instret_pending = instret_before;
                NativeBlockResult {
                    next_pc: hart.pc,
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

    #[cfg(target_arch = "x86_64")]
    unsafe extern "C" fn native_exec_mem_term_helper_x64(
        hart_ptr: *mut Hart,
        bus_data: *mut (),
        bus_vtable: *mut (),
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

        hart.pc = pc;
        let instr = instr as u32;
        let d = Self::decode32(instr);
        let opcode = d.opcode as u32;
        let rd = d.rd as usize;
        let funct3 = d.funct3 as u32;
        let rs1 = d.rs1 as usize;
        let rs2 = d.rs2 as usize;

        let mem_res: Result<(), Trap> = match opcode {
            OPCODE_LOAD => {
                let imm_i = Self::imm_i(instr) as u64;
                let addr = hart.regs[rs1].wrapping_add(imm_i);
                match match funct3 {
                    F3_LB => hart
                        .read_u8(bus, addr, AccessType::Load)
                        .map(|v| (v as i8 as i64) as u64),
                    F3_LH => hart
                        .read_u16(bus, addr, AccessType::Load)
                        .map(|v| (v as i16 as i64) as u64),
                    F3_LW => hart
                        .read_u32(bus, addr, AccessType::Load)
                        .map(|v| (v as i32 as i64) as u64),
                    F3_LD => hart.read_u64(bus, addr, AccessType::Load),
                    F3_LBU => hart.read_u8(bus, addr, AccessType::Load).map(|v| v as u64),
                    F3_LHU => hart.read_u16(bus, addr, AccessType::Load).map(|v| v as u64),
                    F3_LWU => hart.read_u32(bus, addr, AccessType::Load).map(|v| v as u64),
                    _ => Err(Trap::IllegalInstruction(instr)),
                } {
                    Ok(val) => {
                        if rd != 0 {
                            hart.regs[rd] = val;
                        }
                        Ok(())
                    }
                    Err(e) => Err(e),
                }
            }
            OPCODE_STORE => {
                let imm_s = Self::imm_s(instr) as u64;
                let addr = hart.regs[rs1].wrapping_add(imm_s);
                let val = hart.regs[rs2];
                match funct3 {
                    F3_SB => hart.write_u8(bus, addr, val as u8, AccessType::Store),
                    F3_SH => hart.write_u16(bus, addr, val as u16, AccessType::Store),
                    F3_SW => hart.write_u32(bus, addr, val as u32, AccessType::Store),
                    F3_SD => hart.write_u64(bus, addr, val, AccessType::Store),
                    _ => Err(Trap::IllegalInstruction(instr)),
                }
            }
            _ => Err(Trap::IllegalInstruction(instr)),
        };

        match mem_res {
            Ok(()) => NativeBlockResult {
                next_pc: pc.wrapping_add(4),
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

    #[cfg(target_arch = "x86_64")]
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
                "jit-x64: compile-enter pc=0x{:016x} max_steps={}",
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
        let mut em = X64Emitter::new();
        let mut instr_log: Vec<(u64, u32, u8)> = Vec::new();

        Self::x64_emit_prologue(&mut em);

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
                            eprintln!("jit-x64: skip pc=0x{:016x} fetch-trap={:?}", pc, t);
                        }
                        return Err(t);
                    }
                    break;
                }
            };

            if (instr16 & 0x3) != 0x3 {
                self.emit_native_term_helper16_x64(&mut em, pc, instr16, emitted);
                helper_terminator = true;
                terminated = true;
                emitted += 1;
                if self.native_jit_trace {
                    instr_log.push((pc, instr16 as u32, 2));
                }
                break;
            }

            let upper = match self.read_u16(bus, pc.wrapping_add(2), AccessType::Fetch) {
                Ok(v) => v as u32,
                Err(t) => {
                    if emitted == 0 {
                        if self.native_jit_trace {
                            eprintln!("jit-x64: skip pc=0x{:016x} fetch-trap={:?}", pc, t);
                        }
                        return Err(t);
                    }
                    break;
                }
            };
            let instr = (upper << 16) | instr16 as u32;
            let d = Self::decode32(instr);
            let Some(flow) = self.emit_native_instr_x64(&mut em, pc, instr, d) else {
                if self.emit_native_term_mem_helper_x64(&mut em, pc, instr, emitted) {
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
                        "jit-x64: skip pc=0x{:016x} unsupported i32=0x{:08x}",
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
            if flow == X64EmitFlow::Terminate {
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
                em.mov_r64_imm64(X64Emitter::RAX, pc);
            }
            em.mov_r64_imm64(X64Emitter::RDX, emitted as u64);
            Self::x64_emit_epilogue(&mut em);
        }

        let code = em.finish();
        let Some(cache) = self.native_jit.cache.as_mut() else {
            self.native_jit.enabled = false;
            return Ok(None);
        };
        let Some(offset) = cache.alloc(&code) else {
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
                "jit-x64: compiled hart={} satp=0x{:016x} pc=0x{:016x} instrs={}",
                self.hart_id, satp, start_pc, emitted
            );
            for (ipc, raw, len) in instr_log {
                if len == 2 {
                    eprintln!(
                        "  jit-x64:   pc=0x{:016x} c16=0x{:04x} {}",
                        ipc,
                        raw as u16,
                        disas::disas16(raw as u16)
                    );
                } else {
                    eprintln!(
                        "  jit-x64:   pc=0x{:016x} i32=0x{:08x} {}",
                        ipc,
                        raw,
                        disas::disas32(raw)
                    );
                }
            }
        }
        Ok(Some(block))
    }

    #[cfg(target_arch = "x86_64")]
    pub fn try_run_native_jit(
        &mut self,
        bus: &mut impl Bus,
        sbi: &mut impl Sbi,
        max_steps: u32,
    ) -> Result<Option<u32>, Trap> {
        if self.native_jit_trace && !self.native_jit_probe_printed {
            self.native_jit_probe_printed = true;
            eprintln!(
                "jit-x64: probe pc=0x{:016x} max_steps={} irq_cd={} debug_hooks={} jitter={} enabled={}",
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
        if self.irq_check_countdown <= 1 {
            return Ok(None);
        }

        let mut remaining = max_steps.min(self.irq_check_countdown.saturating_sub(1));
        if remaining < 1 {
            return Ok(None);
        }

        let mut done_total = 0u32;
        let mut chained_block: Option<NativeBlock> = None;
        while remaining > 0 {
            let satp = self.satp_cached;
            let start_pc = self.pc;
            let mut block = chained_block.take().or_else(|| self.native_jit.lookup(satp, start_pc));

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

            // Keep counters/time/IRQ cadence aligned with interpreter semantics
            // between blocks so helper-executed CSRs observe current values.
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

            if remaining == 0 {
                break;
            }

            let next_pc = self.pc;
            if let Some(next_block) = self.native_jit.lookup_link(satp, block.offset, next_pc) {
                chained_block = Some(next_block);
                continue;
            }
            if let Some(next_block) = self.native_jit.lookup(satp, next_pc) {
                self.native_jit
                    .insert_link(satp, block.offset, next_pc, next_block);
                chained_block = Some(next_block);
            }
        }

        if done_total == 0 {
            return Ok(None);
        }
        Ok(Some(done_total))
    }
}
