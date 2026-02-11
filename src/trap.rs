#[derive(Debug, Clone, Copy)]
pub enum Trap {
    IllegalInstruction(u32),
    MisalignedAccess {
        addr: u64,
        size: u64,
    },
    MemoryOutOfBounds {
        addr: u64,
        size: u64,
    },
    PageFault {
        addr: u64,
        kind: crate::bus::AccessType,
    },
    Ecall,
    Ebreak,
}
