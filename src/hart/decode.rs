use super::*;

impl Hart {
    #[inline]
    pub(super) fn sign_extend(val: u64, bits: u32) -> i64 {
        let shift = 64 - bits;
        ((val << shift) as i64) >> shift
    }

    #[inline]
    pub(super) fn imm_i(instr: u32) -> i64 {
        Self::sign_extend((instr >> 20) as u64, 12)
    }

    #[inline]
    pub(super) fn imm_s(instr: u32) -> i64 {
        let imm = ((instr >> 25) << 5) | ((instr >> 7) & 0x1f);
        Self::sign_extend(imm as u64, 12)
    }

    #[inline]
    pub(super) fn imm_b(instr: u32) -> i64 {
        let bit12 = (instr >> 31) & 0x1;
        let bit11 = (instr >> 7) & 0x1;
        let bits10_5 = (instr >> 25) & 0x3f;
        let bits4_1 = (instr >> 8) & 0x0f;
        let imm = (bit12 << 12) | (bit11 << 11) | (bits10_5 << 5) | (bits4_1 << 1);
        Self::sign_extend(imm as u64, 13)
    }

    #[inline]
    pub(super) fn imm_u(instr: u32) -> i64 {
        Self::sign_extend((instr & 0xfffff000) as u64, 32)
    }

    #[inline]
    pub(super) fn imm_j(instr: u32) -> i64 {
        let bit20 = (instr >> 31) & 0x1;
        let bits19_12 = (instr >> 12) & 0xff;
        let bit11 = (instr >> 20) & 0x1;
        let bits10_1 = (instr >> 21) & 0x3ff;
        let imm = (bit20 << 20) | (bits19_12 << 12) | (bit11 << 11) | (bits10_1 << 1);
        Self::sign_extend(imm as u64, 21)
    }

    #[inline]
    pub(super) fn decode32(instr: u32) -> Decoded32 {
        let rd = ((instr >> 7) & 0x1f) as u8;
        let funct3 = ((instr >> 12) & 0x7) as u8;
        let rs1 = ((instr >> 15) & 0x1f) as u8;
        let rs2 = ((instr >> 20) & 0x1f) as u8;
        let funct7 = ((instr >> 25) & 0x7f) as u8;
        let imm12 = (instr >> 20) & 0xfff;
        Decoded32 {
            opcode: (instr & 0x7f) as u8,
            rd,
            funct3,
            rs1,
            rs2,
            funct7,
            funct5: ((instr >> 27) & 0x1f) as u8,
            imm12: imm12 as u16,
            csr_addr: ((instr >> 20) & 0xfff) as u16,
        }
    }
}
