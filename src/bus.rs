use crate::trap::Trap;
use std::any::Any;

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
}

impl Interconnect {
    pub fn new(num_harts: usize) -> Self {
        Self {
            devices: Vec::new(),
            stats: BusStats::new(num_harts),
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
        self.devices.push(DeviceRegion {
            base,
            size,
            name: name.into(),
            dev,
        });
        self.stats.per_device.push(DeviceStats {
            name: self.devices[idx].name.clone(),
            counter: Counter::default(),
        });
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
        let dev_idx = self
            .find_device(addr, size)
            .ok_or(Trap::MemoryOutOfBounds {
                addr,
                size: size as u64,
            })?;
        let dev = &mut self.devices[dev_idx];
        let value = dev.dev.read(addr - dev.base, size)?;
        self.stats.record(hart, dev_idx, kind, size as u64);
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
        let dev_idx = self
            .find_device(addr, size)
            .ok_or(Trap::MemoryOutOfBounds {
                addr,
                size: size as u64,
            })?;
        let dev = &mut self.devices[dev_idx];
        dev.dev.write(addr - dev.base, size, value)?;
        self.stats.record(hart, dev_idx, kind, size as u64);
        Ok(())
    }

    pub fn device_by_name_mut<T: 'static>(&mut self, name: &str) -> Option<&mut T> {
        let dev = self.devices.iter_mut().find(|d| d.name == name)?;
        dev.dev.as_any_mut().downcast_mut::<T>()
    }

    pub fn tick_devices(&mut self) {
        for dev in &mut self.devices {
            dev.dev.tick();
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
