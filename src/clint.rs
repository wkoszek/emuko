use crate::bus::Device;
use crate::trap::Trap;
use std::cell::RefCell;
use std::rc::Rc;

pub const CLINT_BASE: u64 = 0x0200_0000;
pub const CLINT_SIZE: u64 = 0x0001_0000;

const MTIMECMP_BASE: u64 = 0x4000;
const MTIME_OFFSET: u64 = 0xBFF8;
const MSIP_BASE: u64 = 0x0000;

pub struct ClintState {
    pub mtime: u64,
    pub mtimecmp: Vec<u64>,
    pub msip: Vec<u32>,
}

impl ClintState {
    pub fn new(num_harts: usize) -> Self {
        Self {
            mtime: 0,
            mtimecmp: vec![u64::MAX; num_harts],
            msip: vec![0; num_harts],
        }
    }

    pub fn tick(&mut self, cycles: u64) {
        self.mtime = self.mtime.wrapping_add(cycles);
    }

    pub fn timer_due(&self, hart_id: usize) -> bool {
        if let Some(cmp) = self.mtimecmp.get(hart_id) {
            self.mtime >= *cmp
        } else {
            false
        }
    }

    pub fn software_pending(&self, hart_id: usize) -> bool {
        if let Some(msip) = self.msip.get(hart_id) {
            (*msip & 1) != 0
        } else {
            false
        }
    }

    pub fn set_msip(&mut self, hart_id: usize, value: bool) {
        if let Some(msip) = self.msip.get_mut(hart_id) {
            *msip = if value { 1 } else { 0 };
        }
    }
}

pub struct ClintDevice {
    state: Rc<RefCell<ClintState>>,
}

impl ClintDevice {
    pub fn new(state: Rc<RefCell<ClintState>>) -> Self {
        Self { state }
    }

    fn read32(value: u64, addr: u64) -> u64 {
        if addr & 0x4 == 0 {
            (value & 0xFFFF_FFFF) as u64
        } else {
            (value >> 32) as u64
        }
    }

    fn write32(orig: u64, addr: u64, val: u64) -> u64 {
        if addr & 0x4 == 0 {
            (orig & 0xFFFF_FFFF_0000_0000) | (val & 0xFFFF_FFFF)
        } else {
            (orig & 0x0000_0000_FFFF_FFFF) | ((val & 0xFFFF_FFFF) << 32)
        }
    }
}

impl Device for ClintDevice {
    fn read(&mut self, addr: u64, size: usize) -> Result<u64, Trap> {
        let state = self.state.borrow();
        if addr >= MSIP_BASE && addr < MTIMECMP_BASE {
            let index = (addr / 4) as usize;
            if let Some(msip) = state.msip.get(index) {
                return Ok(match size {
                    4 => *msip as u64,
                    _ => return Err(Trap::MemoryOutOfBounds { addr, size: size as u64 }),
                });
            }
        }
        if addr >= MTIME_OFFSET && addr < MTIME_OFFSET + 8 {
            return Ok(match size {
                8 => state.mtime,
                4 => Self::read32(state.mtime, addr),
                _ => return Err(Trap::MemoryOutOfBounds { addr, size: size as u64 }),
            });
        }

        if addr >= MTIMECMP_BASE {
            let index = ((addr - MTIMECMP_BASE) / 8) as usize;
            if let Some(cmp) = state.mtimecmp.get(index) {
                return Ok(match size {
                    8 => *cmp,
                    4 => Self::read32(*cmp, addr),
                    _ => return Err(Trap::MemoryOutOfBounds { addr, size: size as u64 }),
                });
            }
        }

        Err(Trap::MemoryOutOfBounds { addr, size: size as u64 })
    }

    fn write(&mut self, addr: u64, size: usize, value: u64) -> Result<(), Trap> {
        let mut state = self.state.borrow_mut();
        if addr >= MSIP_BASE && addr < MTIMECMP_BASE {
            let index = (addr / 4) as usize;
            if let Some(msip) = state.msip.get_mut(index) {
                match size {
                    4 => *msip = value as u32,
                    _ => return Err(Trap::MemoryOutOfBounds { addr, size: size as u64 }),
                }
                return Ok(());
            }
        }
        if addr >= MTIME_OFFSET && addr < MTIME_OFFSET + 8 {
            match size {
                8 => state.mtime = value,
                4 => state.mtime = Self::write32(state.mtime, addr, value),
                _ => return Err(Trap::MemoryOutOfBounds { addr, size: size as u64 }),
            }
            return Ok(());
        }

        if addr >= MTIMECMP_BASE {
            let index = ((addr - MTIMECMP_BASE) / 8) as usize;
            if let Some(cmp) = state.mtimecmp.get_mut(index) {
                match size {
                    8 => *cmp = value,
                    4 => *cmp = Self::write32(*cmp, addr, value),
                    _ => return Err(Trap::MemoryOutOfBounds { addr, size: size as u64 }),
                }
                return Ok(());
            }
        }

        Err(Trap::MemoryOutOfBounds { addr, size: size as u64 })
    }
}
