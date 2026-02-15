use crate::dev::Ram;
use crate::trap::Trap;
use std::any::Any;
use std::ptr::NonNull;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    Fetch,
    Load,
    Store,
    Debug,
}

#[derive(Default, Debug, Clone, Copy)]
pub struct Counter {
    pub reads: u64,
    pub writes: u64,
    pub fetches: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone)]
pub struct DeviceStats {
    pub name: String,
    pub counter: Counter,
}

#[derive(Debug, Clone)]
pub struct BusStats {
    pub total: Counter,
    pub per_hart: Vec<Counter>,
    pub per_device: Vec<DeviceStats>,
}

impl BusStats {
    pub fn new(num_harts: usize) -> Self {
        Self {
            total: Counter::default(),
            per_hart: vec![Counter::default(); num_harts],
            per_device: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        self.total = Counter::default();
        for counter in &mut self.per_hart {
            *counter = Counter::default();
        }
        for dev in &mut self.per_device {
            dev.counter = Counter::default();
        }
    }

    fn record(&mut self, hart: usize, dev: usize, kind: AccessType, bytes: u64) {
        if matches!(kind, AccessType::Debug) {
            return;
        }

        let update = |c: &mut Counter| {
            match kind {
                AccessType::Fetch => c.fetches += 1,
                AccessType::Load => c.reads += 1,
                AccessType::Store => c.writes += 1,
                AccessType::Debug => {}
            }
            c.bytes = c.bytes.saturating_add(bytes);
        };

        update(&mut self.total);
        if let Some(counter) = self.per_hart.get_mut(hart) {
            update(counter);
        }
        if let Some(dev_stats) = self.per_device.get_mut(dev) {
            update(&mut dev_stats.counter);
        }
    }
}

pub trait Device {
    fn read(&mut self, addr: u64, size: usize) -> Result<u64, Trap>;
    fn write(&mut self, addr: u64, size: usize, value: u64) -> Result<(), Trap>;
    fn tick(&mut self) {}
    fn tick_n(&mut self, n: u32) {
        for _ in 0..n {
            self.tick();
        }
    }
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

struct DeviceRegion {
    base: u64,
    size: u64,
    name: String,
    dev: Box<dyn Device>,
}

pub struct Interconnect {
    devices: Vec<DeviceRegion>,
    stats: BusStats,
    stats_enabled: bool,
    ram_idx: Option<usize>,
    ram_base: u64,
    ram_size: u64,
    ram_ptr: Option<NonNull<Ram>>,
    uart_idx: Option<usize>,
}

impl Interconnect {
    fn env_flag(name: &str, default: bool) -> bool {
        match std::env::var(name) {
            Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
                "1" | "true" | "yes" | "on" => true,
                "0" | "false" | "no" | "off" => false,
                _ => default,
            },
            Err(_) => default,
        }
    }

    pub fn new(num_harts: usize) -> Self {
        Self {
            devices: Vec::new(),
            stats: BusStats::new(num_harts),
            stats_enabled: Self::env_flag("KOR_ENABLE_BUS_STATS", false),
            ram_idx: None,
            ram_base: 0,
            ram_size: 0,
            ram_ptr: None,
            uart_idx: None,
        }
    }

    pub fn add_device(
        &mut self,
        name: impl Into<String>,
        base: u64,
        size: u64,
        dev: Box<dyn Device>,
    ) -> usize {
        let idx = self.devices.len();
        let name = name.into();
        self.devices.push(DeviceRegion {
            base,
            size,
            name: name.clone(),
            dev,
        });
        self.stats.per_device.push(DeviceStats {
            name: name.clone(),
            counter: Counter::default(),
        });
        if name == "ram" {
            self.ram_idx = Some(idx);
            self.ram_base = base;
            self.ram_size = size;
            let ram = self.devices[idx].dev.as_any_mut().downcast_mut::<Ram>();
            self.ram_ptr = ram.map(NonNull::from);
        } else if name == "uart" {
            self.uart_idx = Some(idx);
        }
        idx
    }

    pub fn stats(&self) -> &BusStats {
        &self.stats
    }

    pub fn stats_mut(&mut self) -> &mut BusStats {
        &mut self.stats
    }

    fn find_device(&self, addr: u64, size: usize) -> Option<usize> {
        let end = addr.checked_add(size as u64)?;
        self.devices
            .iter()
            .position(|dev| addr >= dev.base && end <= dev.base + dev.size)
    }

    fn read(&mut self, hart: usize, addr: u64, size: usize, kind: AccessType) -> Result<u64, Trap> {
        if let (Some(ram_idx), Some(mut ram_ptr)) = (self.ram_idx, self.ram_ptr) {
            if addr >= self.ram_base {
                let off = addr - self.ram_base;
                if let Some(end) = off.checked_add(size as u64) {
                    if end <= self.ram_size {
                        // SAFETY: ram_ptr is created from the owned RAM device and remains valid
                        // for the Interconnect lifetime.
                        let value = unsafe { ram_ptr.as_mut().read_fast(off as usize, size)? };
                        if self.stats_enabled {
                            self.stats.record(hart, ram_idx, kind, size as u64);
                        }
                        return Ok(value);
                    }
                }
            }
        }
        let dev_idx = self
            .find_device(addr, size)
            .ok_or(Trap::MemoryOutOfBounds {
                addr,
                size: size as u64,
            })?;
        let dev = &mut self.devices[dev_idx];
        let value = dev.dev.read(addr - dev.base, size)?;
        if self.stats_enabled {
            self.stats.record(hart, dev_idx, kind, size as u64);
        }
        Ok(value)
    }

    fn write(
        &mut self,
        hart: usize,
        addr: u64,
        size: usize,
        value: u64,
        kind: AccessType,
    ) -> Result<(), Trap> {
        if let (Some(ram_idx), Some(mut ram_ptr)) = (self.ram_idx, self.ram_ptr) {
            if addr >= self.ram_base {
                let off = addr - self.ram_base;
                if let Some(end) = off.checked_add(size as u64) {
                    if end <= self.ram_size {
                        // SAFETY: ram_ptr is created from the owned RAM device and remains valid
                        // for the Interconnect lifetime.
                        unsafe { ram_ptr.as_mut().write_fast(off as usize, size, value)? };
                        if self.stats_enabled {
                            self.stats.record(hart, ram_idx, kind, size as u64);
                        }
                        return Ok(());
                    }
                }
            }
        }
        let dev_idx = self
            .find_device(addr, size)
            .ok_or(Trap::MemoryOutOfBounds {
                addr,
                size: size as u64,
            })?;
        let dev = &mut self.devices[dev_idx];
        dev.dev.write(addr - dev.base, size, value)?;
        if self.stats_enabled {
            self.stats.record(hart, dev_idx, kind, size as u64);
        }
        Ok(())
    }

    pub fn device_by_name_mut<T: 'static>(&mut self, name: &str) -> Option<&mut T> {
        let dev = self.devices.iter_mut().find(|d| d.name == name)?;
        dev.dev.as_any_mut().downcast_mut::<T>()
    }

    #[allow(dead_code)]
    pub fn tick_devices(&mut self) {
        for dev in &mut self.devices {
            dev.dev.tick();
        }
    }

    pub fn tick_devices_n(&mut self, n: u32) {
        if n == 0 {
            return;
        }
        for (idx, dev) in self.devices.iter_mut().enumerate() {
            if Some(idx) == self.uart_idx {
                dev.dev.tick_n(n);
            } else {
                dev.dev.tick();
            }
        }
    }
}

#[allow(dead_code)]
pub trait Bus {
    fn read_u8(&mut self, hart: usize, addr: u64, kind: AccessType) -> Result<u8, Trap>;
    fn read_u16(&mut self, hart: usize, addr: u64, kind: AccessType) -> Result<u16, Trap>;
    fn read_u32(&mut self, hart: usize, addr: u64, kind: AccessType) -> Result<u32, Trap>;
    fn read_u64(&mut self, hart: usize, addr: u64, kind: AccessType) -> Result<u64, Trap>;

    fn write_u8(&mut self, hart: usize, addr: u64, value: u8, kind: AccessType)
        -> Result<(), Trap>;
    fn write_u16(
        &mut self,
        hart: usize,
        addr: u64,
        value: u16,
        kind: AccessType,
    ) -> Result<(), Trap>;
    fn write_u32(
        &mut self,
        hart: usize,
        addr: u64,
        value: u32,
        kind: AccessType,
    ) -> Result<(), Trap>;
    fn write_u64(
        &mut self,
        hart: usize,
        addr: u64,
        value: u64,
        kind: AccessType,
    ) -> Result<(), Trap>;

    fn stats(&self) -> &BusStats;
    fn stats_mut(&mut self) -> &mut BusStats;
}

impl Bus for Interconnect {
    fn read_u8(&mut self, hart: usize, addr: u64, kind: AccessType) -> Result<u8, Trap> {
        Ok(self.read(hart, addr, 1, kind)? as u8)
    }

    fn read_u16(&mut self, hart: usize, addr: u64, kind: AccessType) -> Result<u16, Trap> {
        Ok(self.read(hart, addr, 2, kind)? as u16)
    }

    fn read_u32(&mut self, hart: usize, addr: u64, kind: AccessType) -> Result<u32, Trap> {
        Ok(self.read(hart, addr, 4, kind)? as u32)
    }

    fn read_u64(&mut self, hart: usize, addr: u64, kind: AccessType) -> Result<u64, Trap> {
        self.read(hart, addr, 8, kind)
    }

    fn write_u8(
        &mut self,
        hart: usize,
        addr: u64,
        value: u8,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.write(hart, addr, 1, value as u64, kind)
    }

    fn write_u16(
        &mut self,
        hart: usize,
        addr: u64,
        value: u16,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.write(hart, addr, 2, value as u64, kind)
    }

    fn write_u32(
        &mut self,
        hart: usize,
        addr: u64,
        value: u32,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.write(hart, addr, 4, value as u64, kind)
    }

    fn write_u64(
        &mut self,
        hart: usize,
        addr: u64,
        value: u64,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.write(hart, addr, 8, value, kind)
    }

    fn stats(&self) -> &BusStats {
        &self.stats
    }

    fn stats_mut(&mut self) -> &mut BusStats {
        &mut self.stats
    }
}
