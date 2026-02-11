use crate::bus::Device;
use crate::plic::PlicState;
use crate::trap::Trap;
use std::any::Any;
use std::cell::RefCell;
use std::rc::Rc;

pub struct Ram {
    data: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct RamSnapshot {
    pub data: Vec<u8>,
}

impl Ram {
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
        }
    }

    #[inline]
    fn check(&self, addr: u64, size: usize) -> Result<usize, Trap> {
        let addr_usize = addr as usize;
        let end = addr_usize
            .checked_add(size)
            .ok_or(Trap::MemoryOutOfBounds {
                addr,
                size: size as u64,
            })?;
        if end > self.data.len() {
            return Err(Trap::MemoryOutOfBounds {
                addr,
                size: size as u64,
            });
        }
        Ok(addr_usize)
    }

    pub fn snapshot(&self) -> RamSnapshot {
        RamSnapshot {
            data: self.data.clone(),
        }
    }

    pub fn restore(&mut self, snap: &RamSnapshot) -> Result<(), &'static str> {
        if self.data.len() != snap.data.len() {
            return Err("RAM size mismatch");
        }
        self.data.copy_from_slice(&snap.data);
        Ok(())
    }
}

impl Device for Ram {
    fn read(&mut self, addr: u64, size: usize) -> Result<u64, Trap> {
        let idx = self.check(addr, size)?;
        let val = match size {
            1 => self.data[idx] as u64,
            2 => u16::from_le_bytes([self.data[idx], self.data[idx + 1]]) as u64,
            4 => u32::from_le_bytes([
                self.data[idx],
                self.data[idx + 1],
                self.data[idx + 2],
                self.data[idx + 3],
            ]) as u64,
            8 => u64::from_le_bytes([
                self.data[idx],
                self.data[idx + 1],
                self.data[idx + 2],
                self.data[idx + 3],
                self.data[idx + 4],
                self.data[idx + 5],
                self.data[idx + 6],
                self.data[idx + 7],
            ]),
            _ => {
                return Err(Trap::MemoryOutOfBounds {
                    addr,
                    size: size as u64,
                })
            }
        };
        Ok(val)
    }

    fn write(&mut self, addr: u64, size: usize, value: u64) -> Result<(), Trap> {
        let idx = self.check(addr, size)?;
        match size {
            1 => {
                self.data[idx] = value as u8;
            }
            2 => {
                let bytes = (value as u16).to_le_bytes();
                self.data[idx] = bytes[0];
                self.data[idx + 1] = bytes[1];
            }
            4 => {
                let bytes = (value as u32).to_le_bytes();
                self.data[idx] = bytes[0];
                self.data[idx + 1] = bytes[1];
                self.data[idx + 2] = bytes[2];
                self.data[idx + 3] = bytes[3];
            }
            8 => {
                let bytes = value.to_le_bytes();
                self.data[idx] = bytes[0];
                self.data[idx + 1] = bytes[1];
                self.data[idx + 2] = bytes[2];
                self.data[idx + 3] = bytes[3];
                self.data[idx + 4] = bytes[4];
                self.data[idx + 5] = bytes[5];
                self.data[idx + 6] = bytes[6];
                self.data[idx + 7] = bytes[7];
            }
            _ => {
                return Err(Trap::MemoryOutOfBounds {
                    addr,
                    size: size as u64,
                })
            }
        }
        Ok(())
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

pub struct Uart16550 {
    ier: u8,
    irq: Option<(Rc<RefCell<PlicState>>, usize)>,
    color_enabled: bool,
    color_active: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct UartSnapshot {
    pub ier: u8,
    pub color_enabled: bool,
    pub color_active: bool,
}

impl Uart16550 {
    pub fn with_irq(plic: Rc<RefCell<PlicState>>, irq: usize) -> Self {
        Self {
            ier: 0,
            irq: Some((plic, irq)),
            color_enabled: true,
            color_active: false,
        }
    }

    fn emit_char(&mut self, ch: u8) {
        if self.color_enabled && !self.color_active {
            print!("\x1b[33m");
            self.color_active = true;
        }
        print!("{}", ch as char);
    }

    fn set_irq(&mut self, pending: bool) {
        if let Some((plic, irq)) = &self.irq {
            plic.borrow_mut().set_pending(*irq, pending);
        }
    }

    pub fn snapshot(&self) -> UartSnapshot {
        UartSnapshot {
            ier: self.ier,
            color_enabled: self.color_enabled,
            color_active: self.color_active,
        }
    }

    pub fn restore(&mut self, snap: UartSnapshot) {
        self.ier = snap.ier;
        self.color_enabled = snap.color_enabled;
        self.color_active = snap.color_active;
    }
}

impl Device for Uart16550 {
    fn read(&mut self, addr: u64, size: usize) -> Result<u64, Trap> {
        if size != 1 {
            return Err(Trap::MemoryOutOfBounds {
                addr,
                size: size as u64,
            });
        }
        match addr {
            1 => Ok(self.ier as u64),
            5 => Ok(0x60), // LSR: THR empty + TEMT set.
            _ => Ok(0),
        }
    }

    fn write(&mut self, addr: u64, size: usize, value: u64) -> Result<(), Trap> {
        if size != 1 {
            return Err(Trap::MemoryOutOfBounds {
                addr,
                size: size as u64,
            });
        }
        match addr {
            0 => {
                let ch = value as u8;
                self.emit_char(ch);
                if (self.ier & 0x02) != 0 {
                    self.set_irq(true);
                }
            }
            1 => {
                self.ier = value as u8;
                if (self.ier & 0x02) == 0 {
                    self.set_irq(false);
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
