use crate::isa::*;

pub fn disas16(instr: u16) -> String {
    let op = instr & 0x3;
    let funct3 = (instr >> 13) & 0x7;
    let name = match (op, funct3) {
        (0b00, 0b000) => "c.addi4spn",
        (0b00, 0b010) => "c.lw",
        (0b00, 0b011) => "c.ld",
        (0b00, 0b110) => "c.sw",
        (0b00, 0b111) => "c.sd",
        (0b01, 0b000) => {
            if ((instr >> 2) & 0x1f) == 0 && ((instr >> 12) & 0x1) == 0 {
                "c.nop"
            } else {
                "c.addi"
            }
        }
        (0b01, 0b001) => "c.addiw",
        (0b01, 0b010) => "c.li",
        (0b01, 0b011) => "c.addi16sp/lui",
        (0b01, 0b100) => "c.misc-alu",
        (0b01, 0b101) => "c.j",
        (0b01, 0b110) => "c.beqz",
        (0b01, 0b111) => "c.bnez",
        (0b10, 0b000) => "c.slli",
        (0b10, 0b010) => "c.lwsp",
        (0b10, 0b011) => "c.ldsp",
        (0b10, 0b100) => {
            let bit12 = (instr >> 12) & 1;
            let rs2 = (instr >> 2) & 0x1f;
            let rd = (instr >> 7) & 0x1f;
            match (bit12, rs2, rd) {
                (0, 0, _) => "c.jr",
                (0, _, _) => "c.mv",
                (1, 0, 0) => "c.ebreak",
                (1, 0, _) => "c.jalr",
                (1, _, _) => "c.add",
                _ => "c.unknown",
            }
        }
        (0b10, 0b110) => "c.swsp",
        (0b10, 0b111) => "c.sdsp",
        _ => "c.unknown",
    };
    name.to_string()
}

pub fn disas32(instr: u32) -> String {
    let opcode = instr & 0x7f;
    let funct3 = (instr >> 12) & 0x7;
    let funct7 = (instr >> 25) & 0x7f;
    let funct5 = (instr >> 27) & 0x1f;

    let name = match opcode {
        OPCODE_LUI => "lui",
        OPCODE_AUIPC => "auipc",
        OPCODE_JAL => "jal",
        OPCODE_JALR => "jalr",
        OPCODE_BRANCH => match funct3 {
            F3_BEQ => "beq",
            F3_BNE => "bne",
            F3_BLT => "blt",
            F3_BGE => "bge",
            F3_BLTU => "bltu",
            F3_BGEU => "bgeu",
            _ => "branch?",
        },
        OPCODE_LOAD => match funct3 {
            F3_LB => "lb",
            F3_LH => "lh",
            F3_LW => "lw",
            F3_LD => "ld",
            F3_LBU => "lbu",
            F3_LHU => "lhu",
            F3_LWU => "lwu",
            _ => "load?",
        },
        OPCODE_STORE => match funct3 {
            F3_SB => "sb",
            F3_SH => "sh",
            F3_SW => "sw",
            F3_SD => "sd",
            _ => "store?",
        },
        OPCODE_LOAD_FP => match funct3 {
            2 => "flw",
            3 => "fld",
            _ => "load-fp?",
        },
        OPCODE_STORE_FP => match funct3 {
            2 => "fsw",
            3 => "fsd",
            _ => "store-fp?",
        },
        OPCODE_OP_IMM => match funct3 {
            F3_ADD_SUB => "addi",
            F3_SLL => "slli",
            F3_SLT => "slti",
            F3_SLTU => "sltiu",
            F3_XOR => "xori",
            F3_SRL_SRA => {
                if funct7 == F7_SUB_SRA {
                    "srai"
                } else {
                    "srli"
                }
            }
            F3_OR => "ori",
            F3_AND => "andi",
            _ => "op-imm?",
        },
        OPCODE_OP => match (funct7, funct3) {
            (F7_BASE, F3_ADD_SUB) => "add",
            (F7_SUB_SRA, F3_ADD_SUB) => "sub",
            (F7_BASE, F3_SLL) => "sll",
            (F7_BASE, F3_SLT) => "slt",
            (F7_BASE, F3_SLTU) => "sltu",
            (F7_BASE, F3_XOR) => "xor",
            (F7_BASE, F3_SRL_SRA) => "srl",
            (F7_SUB_SRA, F3_SRL_SRA) => "sra",
            (F7_BASE, F3_OR) => "or",
            (F7_BASE, F3_AND) => "and",
            (F7_MULDIV, F3_ADD_SUB) => "mul",
            (F7_MULDIV, F3_SLL) => "mulh",
            (F7_MULDIV, F3_SLT) => "mulhsu",
            (F7_MULDIV, F3_SLTU) => "mulhu",
            (F7_MULDIV, F3_XOR) => "div",
            (F7_MULDIV, F3_SRL_SRA) => "divu",
            (F7_MULDIV, F3_OR) => "rem",
            (F7_MULDIV, F3_AND) => "remu",
            _ => "op?",
        },
        OPCODE_OP_IMM_32 => match funct3 {
            F3_ADD_SUB => "addiw",
            F3_SLL => "slliw",
            F3_SRL_SRA => {
                if funct7 == F7_SUB_SRA {
                    "sraiw"
                } else {
                    "srliw"
                }
            }
            _ => "op-imm-32?",
        },
        OPCODE_OP_32 => match (funct7, funct3) {
            (F7_BASE, F3_ADD_SUB) => "addw",
            (F7_SUB_SRA, F3_ADD_SUB) => "subw",
            (F7_BASE, F3_SLL) => "sllw",
            (F7_BASE, F3_SRL_SRA) => "srlw",
            (F7_SUB_SRA, F3_SRL_SRA) => "sraw",
            (F7_MULDIV, F3_ADD_SUB) => "mulw",
            (F7_MULDIV, F3_XOR) => "divw",
            (F7_MULDIV, F3_SRL_SRA) => "divuw",
            (F7_MULDIV, F3_OR) => "remw",
            (F7_MULDIV, F3_AND) => "remuw",
            _ => "op32?",
        },
        OPCODE_MISC_MEM => match funct3 {
            F3_FENCE => "fence",
            F3_FENCE_I => "fence.i",
            _ => "misc-mem?",
        },
        OPCODE_SYSTEM => match funct3 {
            F3_SYSTEM => match (instr >> 20) & 0xfff {
                IMM_ECALL => "ecall",
                IMM_EBREAK => "ebreak",
                IMM_SRET => "sret",
                IMM_MRET => "mret",
                IMM_WFI => "wfi",
                _ => "system",
            },
            F3_CSRRW => "csrrw",
            F3_CSRRS => "csrrs",
            F3_CSRRC => "csrrc",
            F3_CSRRWI => "csrrwi",
            F3_CSRRSI => "csrrsi",
            F3_CSRRCI => "csrrci",
            _ => "system?",
        },
        OPCODE_AMO => {
            let suf = match funct3 {
                F3_AMO_W => ".w",
                F3_AMO_D => ".d",
                _ => "",
            };
            let base = match funct5 {
                F5_LR => "lr",
                F5_SC => "sc",
                F5_AMOSWAP => "amoswap",
                F5_AMOADD => "amoadd",
                F5_AMOXOR => "amoxor",
                F5_AMOAND => "amoand",
                F5_AMOOR => "amoor",
                F5_AMOMIN => "amomin",
                F5_AMOMAX => "amomax",
                F5_AMOMINU => "amominu",
                F5_AMOMAXU => "amomaxu",
                _ => "amo?",
            };
            return format!("{base}{suf}");
        }
        0b1010011 => "op-fp",
        _ => "unknown",
    };
    name.to_string()
}
