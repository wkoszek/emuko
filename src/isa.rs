// RISC-V RV32I/RV32M/RV32A opcode and funct constants.
// Keep this file close to the reference card for readability.

// Opcodes (instr[6:0])
pub const OPCODE_LUI: u32     = 0b0110111; // U-type: LUI
pub const OPCODE_AUIPC: u32   = 0b0010111; // U-type: AUIPC
pub const OPCODE_JAL: u32     = 0b1101111; // J-type: JAL
pub const OPCODE_JALR: u32    = 0b1100111; // I-type: JALR
pub const OPCODE_BRANCH: u32  = 0b1100011; // B-type: branches
pub const OPCODE_LOAD: u32    = 0b0000011; // I-type: loads
pub const OPCODE_LOAD_FP: u32 = 0b0000111; // I-type: FP loads
pub const OPCODE_STORE: u32   = 0b0100011; // S-type: stores
pub const OPCODE_STORE_FP: u32 = 0b0100111; // S-type: FP stores
pub const OPCODE_OP_IMM: u32  = 0b0010011; // I-type: ALU immediate
pub const OPCODE_OP: u32      = 0b0110011; // R-type: ALU register
pub const OPCODE_OP_IMM_32: u32 = 0b0011011; // I-type: ALU immediate word (RV64)
pub const OPCODE_OP_32: u32     = 0b0111011; // R-type: ALU register word (RV64)
pub const OPCODE_SYSTEM: u32  = 0b1110011; // I-type: system (ecall/ebreak)
pub const OPCODE_AMO: u32     = 0b0101111; // R-type: atomics (A extension)
pub const OPCODE_MISC_MEM: u32 = 0b0001111; // fence/fence.i

// funct3 values
pub const F3_ADD_SUB: u32 = 0b000;
pub const F3_SLL: u32     = 0b001;
pub const F3_SLT: u32     = 0b010;
pub const F3_SLTU: u32    = 0b011;
pub const F3_XOR: u32     = 0b100;
pub const F3_SRL_SRA: u32 = 0b101;
pub const F3_OR: u32      = 0b110;
pub const F3_AND: u32     = 0b111;

// branch funct3
pub const F3_BEQ: u32  = 0b000;
pub const F3_BNE: u32  = 0b001;
pub const F3_BLT: u32  = 0b100;
pub const F3_BGE: u32  = 0b101;
pub const F3_BLTU: u32 = 0b110;
pub const F3_BGEU: u32 = 0b111;

// load/store funct3
pub const F3_LB: u32  = 0b000;
pub const F3_LH: u32  = 0b001;
pub const F3_LW: u32  = 0b010;
pub const F3_LD: u32  = 0b011;
pub const F3_LBU: u32 = 0b100;
pub const F3_LHU: u32 = 0b101;
pub const F3_LWU: u32 = 0b110;

pub const F3_SB: u32 = 0b000;
pub const F3_SH: u32 = 0b001;
pub const F3_SW: u32 = 0b010;
pub const F3_SD: u32 = 0b011;

// system
pub const F3_SYSTEM: u32 = 0b000;
pub const F3_CSRRW: u32 = 0b001;
pub const F3_CSRRS: u32 = 0b010;
pub const F3_CSRRC: u32 = 0b011;
pub const F3_CSRRWI: u32 = 0b101;
pub const F3_CSRRSI: u32 = 0b110;
pub const F3_CSRRCI: u32 = 0b111;

// fence
pub const F3_FENCE: u32 = 0b000;
pub const F3_FENCE_I: u32 = 0b001;

// funct7 values
pub const F7_BASE: u32 = 0b0000000;
pub const F7_SUB_SRA: u32 = 0b0100000;
pub const F7_MULDIV: u32 = 0b0000001;

// AMO funct3
pub const F3_AMO_W: u32 = 0b010;
pub const F3_AMO_D: u32 = 0b011;

// AMO funct5 (instr[31:27])
pub const F5_LR: u32      = 0b00010;
pub const F5_SC: u32      = 0b00011;
pub const F5_AMOSWAP: u32 = 0b00001;
pub const F5_AMOADD: u32  = 0b00000;
pub const F5_AMOXOR: u32  = 0b00100;
pub const F5_AMOAND: u32  = 0b01100;
pub const F5_AMOOR: u32   = 0b01000;
pub const F5_AMOMIN: u32  = 0b10000;
pub const F5_AMOMAX: u32  = 0b10100;
pub const F5_AMOMINU: u32 = 0b11000;
pub const F5_AMOMAXU: u32 = 0b11100;

// System imm12 for ecall/ebreak
pub const IMM_ECALL: u32 = 0x000;
pub const IMM_EBREAK: u32 = 0x001;
pub const IMM_SRET: u32 = 0x102;
pub const IMM_MRET: u32 = 0x302;
pub const IMM_WFI: u32 = 0x105;
