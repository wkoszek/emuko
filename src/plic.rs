use crate::bus::Device;
use crate::trap::Trap;
use std::cell::RefCell;
use std::rc::Rc;

pub const PLIC_BASE: u64 = 0x0c00_0000;
pub const PLIC_SIZE: u64 = 0x0040_0000;

const PLIC_NUM_SOURCES: usize = 32;
const PLIC_WORDS: usize = (PLIC_NUM_SOURCES + 32) / 32;
const PLIC_CTX_STRIDE: u64 = 0x1000;
const PLIC_ENABLE_BASE: u64 = 0x2000;
const PLIC_PENDING_BASE: u64 = 0x1000;
const PLIC_CONTEXT_BASE: u64 = 0x200000;

#[derive(Debug)]
pub struct PlicState {
    priority: [u32; PLIC_NUM_SOURCES + 1],
    pending: [u32; PLIC_WORDS],
    enable: Vec<[u32; PLIC_WORDS]>,
    threshold: Vec<u32>,
}

impl PlicState {
    pub fn new(num_harts: usize) -> Self {
        let contexts = num_harts * 2;
        Self {
            priority: [0; PLIC_NUM_SOURCES + 1],
            pending: [0; PLIC_WORDS],
            enable: vec![[0; PLIC_WORDS]; contexts],
            threshold: vec![0; contexts],
        }
    }

    fn context_index(hart_id: usize) -> usize {
        hart_id * 2 + 1
    }

    pub fn set_pending(&mut self, irq: usize, pending: bool) {
        if irq == 0 || irq > PLIC_NUM_SOURCES {
            return;
        }
        let word = irq / 32;
        let bit = irq % 32;
        if pending {
            self.pending[word] |= 1 << bit;
        } else {
            self.pending[word] &= !(1 << bit);
        }
    }

    pub fn pending_for_hart(&self, hart_id: usize) -> bool {
        let ctx = Self::context_index(hart_id);
        let threshold = *self.threshold.get(ctx).unwrap_or(&0);
        let enables = self.enable.get(ctx);
        for irq in 1..=PLIC_NUM_SOURCES {
            let word = irq / 32;
            let bit = irq % 32;
            let is_pending = (self.pending[word] & (1 << bit)) != 0;
            let is_enabled = enables.map_or(false, |e| (e[word] & (1 << bit)) != 0);
            let prio = self.priority[irq];
            if is_pending && is_enabled && prio > threshold {
                return true;
            }
        }
        false
    }

    fn claim(&mut self, ctx: usize) -> u32 {
        let threshold = *self.threshold.get(ctx).unwrap_or(&0);
        let enables = self.enable.get(ctx);
        let mut best_irq = 0;
        let mut best_prio = 0;
        for irq in 1..=PLIC_NUM_SOURCES {
            let word = irq / 32;
            let bit = irq % 32;
            let is_pending = (self.pending[word] & (1 << bit)) != 0;
            let is_enabled = enables.map_or(false, |e| (e[word] & (1 << bit)) != 0);
            let prio = self.priority[irq];
            if is_pending && is_enabled && prio > threshold {
                if prio > best_prio {
                    best_prio = prio;
                    best_irq = irq as u32;
                }
            }
        }
        if best_irq != 0 {
            let word = best_irq as usize / 32;
            let bit = best_irq as usize % 32;
            self.pending[word] &= !(1 << bit);
        }
        best_irq
    }
}

pub struct PlicDevice {
    state: Rc<RefCell<PlicState>>,
    num_contexts: usize,
}

impl PlicDevice {
    pub fn new(state: Rc<RefCell<PlicState>>, num_harts: usize) -> Self {
        Self {
            state,
            num_contexts: num_harts * 2,
        }
    }
}

impl Device for PlicDevice {
    fn read(&mut self, addr: u64, size: usize) -> Result<u64, Trap> {
        if size != 4 {
            return Err(Trap::MemoryOutOfBounds { addr, size: size as u64 });
        }
        let mut state = self.state.borrow_mut();
        if addr < PLIC_PENDING_BASE {
            let irq = (addr / 4) as usize;
            if irq <= PLIC_NUM_SOURCES {
                return Ok(state.priority[irq] as u64);
            }
        } else if addr >= PLIC_PENDING_BASE && addr < PLIC_ENABLE_BASE {
            let index = ((addr - PLIC_PENDING_BASE) / 4) as usize;
            if let Some(word) = state.pending.get(index) {
                return Ok(*word as u64);
            }
        } else if addr >= PLIC_ENABLE_BASE && addr < PLIC_CONTEXT_BASE {
            let ctx = ((addr - PLIC_ENABLE_BASE) / 0x80) as usize;
            let word = (((addr - PLIC_ENABLE_BASE) % 0x80) / 4) as usize;
            if ctx < self.num_contexts {
                if let Some(en) = state.enable.get(ctx) {
                    if let Some(val) = en.get(word) {
                        return Ok(*val as u64);
                    }
                }
            }
        } else if addr >= PLIC_CONTEXT_BASE {
            let ctx = ((addr - PLIC_CONTEXT_BASE) / PLIC_CTX_STRIDE) as usize;
            let offset = (addr - PLIC_CONTEXT_BASE) % PLIC_CTX_STRIDE;
            if ctx < self.num_contexts {
                if offset == 0 {
                    let thr = state.threshold[ctx];
                    return Ok(thr as u64);
                }
                if offset == 4 {
                    let irq = state.claim(ctx);
                    return Ok(irq as u64);
                }
            }
        }

        Err(Trap::MemoryOutOfBounds { addr, size: size as u64 })
    }

    fn write(&mut self, addr: u64, size: usize, value: u64) -> Result<(), Trap> {
        if size != 4 {
            return Err(Trap::MemoryOutOfBounds { addr, size: size as u64 });
        }
        let mut state = self.state.borrow_mut();
        if addr < PLIC_PENDING_BASE {
            let irq = (addr / 4) as usize;
            if irq <= PLIC_NUM_SOURCES {
                state.priority[irq] = value as u32;
                return Ok(());
            }
        } else if addr >= PLIC_ENABLE_BASE && addr < PLIC_CONTEXT_BASE {
            let ctx = ((addr - PLIC_ENABLE_BASE) / 0x80) as usize;
            let word = (((addr - PLIC_ENABLE_BASE) % 0x80) / 4) as usize;
            if ctx < self.num_contexts {
                if let Some(en) = state.enable.get_mut(ctx) {
                    if let Some(val) = en.get_mut(word) {
                        *val = value as u32;
                        return Ok(());
                    }
                }
            }
        } else if addr >= PLIC_CONTEXT_BASE {
            let ctx = ((addr - PLIC_CONTEXT_BASE) / PLIC_CTX_STRIDE) as usize;
            let offset = (addr - PLIC_CONTEXT_BASE) % PLIC_CTX_STRIDE;
            if ctx < self.num_contexts {
                if offset == 0 {
                    state.threshold[ctx] = value as u32;
                    return Ok(());
                }
                if offset == 4 {
                    let irq = value as usize;
                    if irq <= PLIC_NUM_SOURCES && irq != 0 {
                        state.set_pending(irq, false);
                    }
                    return Ok(());
                }
            }
        }

        Err(Trap::MemoryOutOfBounds { addr, size: size as u64 })
    }
}
