use crate::bus::{AccessType, Bus, Interconnect};
use crate::clint::{ClintDevice, ClintState, CLINT_BASE, CLINT_SIZE};
use crate::dev::{Ram, Uart16550};
use crate::efi::EfiState;
use crate::hart::Hart;
use crate::plic::{PlicDevice, PlicState, PLIC_BASE, PLIC_SIZE};
use crate::sbi::{Sbi, VirtualSbi};
use crate::snapshot::{self, MachineSnapshot};
use crate::trap::Trap;
use std::cell::RefCell;
use std::rc::Rc;
use std::time::{Duration, Instant};

pub const DEFAULT_RAM_BASE: u64 = 0x8000_0000;
pub const DEFAULT_RAM_SIZE: usize = 64 * 1024 * 1024;
pub const UART_BASE: u64 = 0x1000_0000;
pub const UART_SIZE: u64 = 0x100;

pub const DATA_OFFSET: u64 = 0x0001_0000;
pub const BSS_OFFSET: u64 = 0x0002_0000;
pub const HEAP_OFFSET: u64 = 0x0003_0000;
pub const STACK_OFFSET: u64 = 0x0008_0000;
pub const STACK_TOP_OFFSET: u64 = 0x0010_0000;
pub const DUMP_BYTES: usize = 256;

pub struct System {
    pub bus: Interconnect,
    pub harts: Vec<Hart>,
    pub sbi: VirtualSbi,
    clint: Rc<RefCell<ClintState>>,
    plic: Rc<RefCell<PlicState>>,
    ram_base: u64,
    ram_size: usize,
    reset_pc: u64,
    trace_traps: Option<u64>,
    total_steps: u64,
    perf_banner_printed: bool,
    perf_start_at: Option<Instant>,
    perf_last_report_at: Option<Instant>,
    perf_last_report_steps: u64,
    perf_report_count_cfg: u32,
    perf_reports_left: u32,
    perf_report_interval: Duration,
    perf_check_ticks: u32,
    perf_check_countdown: u32,
}

impl System {
    fn env_u32(name: &str, default: u32) -> u32 {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(default)
    }

    fn perf_line(msg: &str) {
        eprintln!("{}", msg);
    }

    fn ensure_perf_tracking_started(&mut self) {
        if self.perf_banner_printed {
            return;
        }
        let now = Instant::now();
        self.perf_banner_printed = true;
        self.perf_start_at = Some(now);
        self.perf_last_report_at = Some(now);
        self.perf_last_report_steps = self.total_steps;
        self.perf_reports_left = self.perf_report_count_cfg;
        self.perf_check_countdown = self.perf_check_ticks;
        if self.perf_reports_left > 0 {
            Self::perf_line(&format!(
                "perf: startup benchmark active (reports={} every {:.2}s)",
                self.perf_reports_left,
                self.perf_report_interval.as_secs_f64()
            ));
        }
    }

    fn maybe_report_perf(&mut self) {
        if self.perf_reports_left == 0 {
            return;
        }
        let Some(last_at) = self.perf_last_report_at else {
            return;
        };
        let now = Instant::now();
        let elapsed = now.duration_since(last_at);
        if elapsed < self.perf_report_interval {
            return;
        }
        let dsteps = self.total_steps.saturating_sub(self.perf_last_report_steps);
        if dsteps == 0 {
            self.perf_last_report_at = Some(now);
            return;
        }
        let cps = dsteps as f64 / elapsed.as_secs_f64();
        let wall = self
            .perf_start_at
            .map(|t| now.duration_since(t).as_secs_f64())
            .unwrap_or(elapsed.as_secs_f64());
        Self::perf_line(&format!(
            "perf: {:.2} Mcycles/s (delta_steps={} dt={:.2}s total_steps={} wall={:.2}s)",
            cps / 1_000_000.0,
            dsteps,
            elapsed.as_secs_f64(),
            self.total_steps,
            wall
        ));
        self.perf_last_report_at = Some(now);
        self.perf_last_report_steps = self.total_steps;
        self.perf_reports_left = self.perf_reports_left.saturating_sub(1);
    }

    fn perf_tick(&mut self) {
        if self.perf_check_countdown <= 1 {
            self.perf_check_countdown = self.perf_check_ticks;
            self.maybe_report_perf();
        } else {
            self.perf_check_countdown -= 1;
        }
    }

    pub fn new(num_harts: usize, ram_base: u64, ram_size: usize, misa_ext: u64) -> Self {
        let mut bus = Interconnect::new(num_harts);
        bus.add_device(
            "ram",
            ram_base,
            ram_size as u64,
            Box::new(Ram::new(ram_size)),
        );
        let clint_state = Rc::new(RefCell::new(ClintState::new(num_harts)));
        bus.add_device(
            "clint",
            CLINT_BASE,
            CLINT_SIZE,
            Box::new(ClintDevice::new(Rc::clone(&clint_state))),
        );
        let plic_state = Rc::new(RefCell::new(PlicState::new(num_harts)));
        bus.add_device(
            "plic",
            PLIC_BASE,
            PLIC_SIZE,
            Box::new(PlicDevice::new(Rc::clone(&plic_state), num_harts)),
        );
        bus.add_device(
            "uart",
            UART_BASE,
            UART_SIZE,
            Box::new(Uart16550::with_irq(Rc::clone(&plic_state), 10)),
        );

        let harts = (0..num_harts).map(|id| Hart::new(id, misa_ext)).collect();
        let perf_check_ticks = Self::env_u32("KOR_PERF_CHECK_TICKS", 100_000).max(1);
        let perf_report_count_cfg = Self::env_u32("KOR_PERF_REPORT_COUNT", 3);
        let perf_report_interval = Duration::from_secs_f64(
            std::env::var("KOR_PERF_REPORT_SECS")
                .ok()
                .and_then(|v| v.parse::<f64>().ok())
                .filter(|v| *v > 0.0)
                .unwrap_or(1.0),
        );

        Self {
            bus,
            harts,
            sbi: VirtualSbi::new(Rc::clone(&clint_state)),
            clint: clint_state,
            plic: plic_state,
            ram_base,
            ram_size,
            reset_pc: ram_base,
            trace_traps: None,
            total_steps: 0,
            perf_banner_printed: false,
            perf_start_at: None,
            perf_last_report_at: None,
            perf_last_report_steps: 0,
            perf_report_count_cfg,
            perf_reports_left: perf_report_count_cfg,
            perf_report_interval,
            perf_check_ticks,
            perf_check_countdown: perf_check_ticks,
        }
    }

    pub fn set_reset_pc(&mut self, pc: u64) {
        self.reset_pc = pc;
    }

    pub fn set_trace_traps(&mut self, limit: Option<u64>) {
        self.trace_traps = limit;
    }

    pub fn set_trace_instr(&mut self, limit: Option<u64>) {
        for hart in &mut self.harts {
            hart.set_trace_instr(limit);
        }
    }

    pub fn configure_perf_reporting(
        &mut self,
        report_count: Option<u32>,
        report_interval: Option<Duration>,
        check_ticks: Option<u32>,
    ) {
        if let Some(v) = report_count {
            self.perf_report_count_cfg = v;
            self.perf_reports_left = v;
        }
        if let Some(v) = report_interval {
            self.perf_report_interval = v;
        }
        if let Some(v) = check_ticks {
            let vv = v.max(1);
            self.perf_check_ticks = vv;
            self.perf_check_countdown = vv;
        }
        // Start fresh at next run() with updated settings.
        self.perf_banner_printed = false;
        self.perf_start_at = None;
        self.perf_last_report_at = None;
        self.perf_last_report_steps = self.total_steps;
    }

    pub fn configure_uart_poll_auto(
        &mut self,
        target_wall: Duration,
        calib_min_wall: Duration,
        check_ticks: u32,
    ) -> Result<(), String> {
        let uart = self
            .bus
            .device_by_name_mut::<Uart16550>("uart")
            .ok_or_else(|| "UART device not found".to_string())?;
        uart.configure_poll_auto(target_wall, calib_min_wall, check_ticks);
        Ok(())
    }

    pub fn configure_uart_poll_fixed(&mut self, ticks: u32) -> Result<(), String> {
        let uart = self
            .bus
            .device_by_name_mut::<Uart16550>("uart")
            .ok_or_else(|| "UART device not found".to_string())?;
        uart.configure_poll_fixed(ticks);
        Ok(())
    }

    pub fn configure_uart_flush_every(&mut self, every: usize) -> Result<(), String> {
        let uart = self
            .bus
            .device_by_name_mut::<Uart16550>("uart")
            .ok_or_else(|| "UART device not found".to_string())?;
        uart.configure_flush_every(every);
        Ok(())
    }

    pub fn configure_linux_boot(&mut self, dtb_addr: u64) {
        for hart in &mut self.harts {
            hart.regs[10] = hart.hart_id as u64; // a0: hartid
            hart.regs[11] = dtb_addr; // a1: dtb
            hart.regs[12] = 0;
            hart.regs[13] = 0;
            hart.regs[4] = hart.hart_id as u64; // tp: some boot flows expect hartid here.
            hart.csrs.write(crate::csr::CSR_SATP, 0);
        }
    }

    pub fn configure_efi_boot(
        &mut self,
        system_table: u64,
        image_handle: u64,
        efi_state: EfiState,
    ) {
        self.sbi.configure_efi(efi_state);
        for hart in &mut self.harts {
            hart.regs[10] = image_handle; // a0: image handle
            hart.regs[11] = system_table; // a1: system table
            hart.regs[12] = 0;
            hart.regs[13] = 0;
            hart.regs[4] = hart.hart_id as u64; // tp
            hart.csrs.write(crate::csr::CSR_SATP, 0);
        }
    }

    pub fn reset(&mut self) {
        let sp = self.ram_base + STACK_TOP_OFFSET;
        let gp = self.ram_base + DATA_OFFSET;
        self.clint.borrow_mut().mtime = 0;
        for cmp in &mut self.clint.borrow_mut().mtimecmp {
            *cmp = u64::MAX;
        }
        for msip in &mut self.clint.borrow_mut().msip {
            *msip = 0;
        }
        for hart in &mut self.harts {
            hart.reset(self.reset_pc, sp, gp);
        }
        self.bus.stats_mut().reset();
        self.total_steps = 0;
        self.perf_banner_printed = false;
        self.perf_start_at = None;
        self.perf_last_report_at = None;
        self.perf_last_report_steps = 0;
        self.perf_reports_left = self.perf_report_count_cfg;
        self.perf_check_countdown = self.perf_check_ticks;
    }

    pub fn load(&mut self, addr: u64, data: &[u8]) -> Result<(), Trap> {
        let end = addr
            .checked_add(data.len() as u64)
            .ok_or(Trap::MemoryOutOfBounds {
                addr,
                size: data.len() as u64,
            })?;
        let ram_end = self.ram_base + self.ram_size as u64;
        if addr < self.ram_base || end > ram_end {
            return Err(Trap::MemoryOutOfBounds {
                addr,
                size: data.len() as u64,
            });
        }
        for (i, byte) in data.iter().enumerate() {
            self.bus
                .write_u8(0, addr + i as u64, *byte, AccessType::Debug)?;
        }
        Ok(())
    }

    pub fn run(&mut self, max_steps: Option<u64>) -> Result<u64, Trap> {
        self.ensure_perf_tracking_started();
        let mut steps = 0u64;
        loop {
            if let Some(limit) = max_steps {
                if steps >= limit {
                    break;
                }
            }
            for hart_idx in 0..self.harts.len() {
                if let Some(limit) = max_steps {
                    if steps >= limit {
                        break;
                    }
                }
                self.bus.tick_devices();
                {
                    let hart = &mut self.harts[hart_idx];
                    if let Err(trap) = hart.step(&mut self.bus, &mut self.sbi) {
                        if let Some(left) = self.trace_traps.as_mut() {
                            if *left > 0 {
                                eprintln!(
                                    "trap hart={} pc=0x{:016x} {:?}",
                                    hart.hart_id, hart.pc, trap
                                );
                                if let Some((kind, addr, size)) = hart.last_access() {
                                    eprintln!(
                                        "  last_access kind={:?} addr=0x{:016x} size={}",
                                        kind, addr, size
                                    );
                                }
                                eprintln!(
                                    "  regs a0=0x{:016x} a1=0x{:016x} a2=0x{:016x} a3=0x{:016x}",
                                    hart.regs[10], hart.regs[11], hart.regs[12], hart.regs[13]
                                );
                                eprintln!(
                                    "  satp=0x{:016x} sstatus=0x{:016x} sepc=0x{:016x} scause=0x{:016x} stval=0x{:016x}",
                                    hart.csrs.read(crate::csr::CSR_SATP),
                                    hart.csrs.read(crate::csr::CSR_SSTATUS),
                                    hart.csrs.read(crate::csr::CSR_SEPC),
                                    hart.csrs.read(crate::csr::CSR_SCAUSE),
                                    hart.csrs.read(crate::csr::CSR_STVAL)
                                );
                                *left -= 1;
                            }
                        }
                        hart.handle_trap(trap);
                    }
                    self.sbi.tick(1);
                    let now = self.sbi.time();
                    hart.csrs.set_time(now);
                    {
                        let due = self.sbi.timer_due(hart.hart_id);
                        let mut sip = hart.csrs.read(crate::csr::CSR_SIP);
                        if due {
                            sip |= crate::csr::SIP_STIP;
                        } else {
                            sip &= !crate::csr::SIP_STIP;
                        }
                        let ssip = self.clint.borrow().software_pending(hart.hart_id);
                        if ssip {
                            sip |= crate::csr::SIP_SSIP;
                        } else {
                            sip &= !crate::csr::SIP_SSIP;
                        }
                        let seip = self.plic.borrow().pending_for_hart(hart.hart_id);
                        if seip {
                            sip |= crate::csr::SIP_SEIP;
                        } else {
                            sip &= !crate::csr::SIP_SEIP;
                        }
                        hart.csrs.write(crate::csr::CSR_SIP, sip);
                    }
                }
                steps += 1;
                self.total_steps = self.total_steps.wrapping_add(1);
                self.perf_tick();
                if self.sbi.shutdown_requested() {
                    self.maybe_report_perf();
                    return Ok(steps);
                }
            }
        }
        self.maybe_report_perf();
        Ok(steps)
    }

    pub fn total_steps(&self) -> u64 {
        self.total_steps
    }

    pub fn save_snapshot(&mut self, path: &str) -> Result<(), String> {
        let ram = self
            .bus
            .device_by_name_mut::<Ram>("ram")
            .ok_or_else(|| "RAM device not found".to_string())?
            .snapshot();
        let uart = self
            .bus
            .device_by_name_mut::<Uart16550>("uart")
            .ok_or_else(|| "UART device not found".to_string())?
            .snapshot();
        let clint = self.clint.borrow().snapshot();
        let plic = self.plic.borrow().snapshot();
        let harts = self.harts.iter().map(|h| h.snapshot()).collect();
        let sbi = self.sbi.snapshot();
        let bus_stats = self.bus.stats().clone();
        let snap = MachineSnapshot {
            ram_base: self.ram_base,
            ram_size: self.ram_size,
            reset_pc: self.reset_pc,
            trace_traps: self.trace_traps,
            total_steps: self.total_steps,
            harts,
            clint,
            plic,
            uart,
            ram,
            sbi,
            bus_stats,
        };
        snapshot::save(path, &snap)
    }

    pub fn load_snapshot(path: &str) -> Result<Self, String> {
        let snap = snapshot::load(path)?;
        if snap.harts.is_empty() {
            return Err("snapshot contains zero harts".to_string());
        }
        let ext = snap.harts[0].misa_ext;
        let mut system = Self::new(snap.harts.len(), snap.ram_base, snap.ram_size, ext);
        system.reset_pc = snap.reset_pc;
        system.trace_traps = snap.trace_traps;
        system.total_steps = snap.total_steps;
        {
            let mut clint = system.clint.borrow_mut();
            clint.restore(&snap.clint);
        }
        {
            let mut plic = system.plic.borrow_mut();
            plic.restore(&snap.plic).map_err(|e| e.to_string())?;
        }
        system.harts.clear();
        for h in &snap.harts {
            system
                .harts
                .push(Hart::from_snapshot(h).map_err(|e| e.to_string())?);
        }
        system.sbi.restore(&snap.sbi);
        system
            .bus
            .device_by_name_mut::<Ram>("ram")
            .ok_or_else(|| "RAM device not found".to_string())?
            .restore(&snap.ram)
            .map_err(|e| e.to_string())?;
        system
            .bus
            .device_by_name_mut::<Uart16550>("uart")
            .ok_or_else(|| "UART device not found".to_string())?
            .restore(snap.uart);
        *system.bus.stats_mut() = snap.bus_stats;
        system.perf_banner_printed = false;
        system.perf_start_at = None;
        system.perf_last_report_at = None;
        system.perf_last_report_steps = system.total_steps;
        system.perf_reports_left = system.perf_report_count_cfg;
        system.perf_check_countdown = system.perf_check_ticks;
        Ok(system)
    }

    pub fn dump_state(&mut self, text_len: usize) {
        if let Some(hart) = self.harts.get(0) {
            println!("== Hart 0 Registers ==");
            println!("pc  = 0x{:016x}", hart.pc);
            for i in 0..32 {
                if i % 4 == 0 {
                    print!("x{:02}:", i);
                }
                print!(" 0x{:016x}", hart.regs[i]);
                if i % 4 == 3 {
                    println!();
                }
            }
            if 32 % 4 != 0 {
                println!();
            }
        }

        println!("== Memory Dump ==");
        let text_dump = text_len.min(DUMP_BYTES);
        let text_base = self.ram_base;
        let data_base = self.ram_base + DATA_OFFSET;
        let bss_base = self.ram_base + BSS_OFFSET;
        let heap_base = self.ram_base + HEAP_OFFSET;
        let stack_base = self.ram_base + STACK_OFFSET;
        let stack_top = self.ram_base + STACK_TOP_OFFSET;
        self.dump_region("text", text_base, text_dump);
        self.dump_region("data", data_base, DUMP_BYTES);
        self.dump_region("bss", bss_base, DUMP_BYTES);
        self.dump_region("heap", heap_base, DUMP_BYTES);
        let stack_start = stack_top.saturating_sub(DUMP_BYTES as u64).max(stack_base);
        self.dump_region("stack", stack_start, DUMP_BYTES);
    }

    fn dump_region(&mut self, label: &str, start: u64, len: usize) {
        println!(
            "-- {} [0x{:016x}..0x{:016x})",
            label,
            start,
            start + len as u64
        );
        let mut addr = start;
        let end = start + len as u64;
        while addr < end {
            print!("0x{:016x}:", addr);
            let line_end = (addr + 16).min(end);
            let mut cur = addr;
            while cur < line_end {
                let byte = match self.bus.read_u8(0, cur, AccessType::Debug) {
                    Ok(b) => b,
                    Err(_) => 0,
                };
                print!(" {:02x}", byte);
                cur += 1;
            }
            println!();
            addr = line_end;
        }
    }

    pub fn dump_bus_stats(&self) {
        let stats = self.bus.stats();
        Self::print_stats("total", &stats.total);
        for (i, counter) in stats.per_hart.iter().enumerate() {
            Self::print_stats(&format!("hart {}", i), counter);
        }
        for dev in &stats.per_device {
            Self::print_stats(&format!("device {}", dev.name), &dev.counter);
        }
    }

    fn print_stats(label: &str, counter: &crate::bus::Counter) {
        println!(
            "bus {}: fetches={} reads={} writes={} bytes={}",
            label, counter.fetches, counter.reads, counter.writes, counter.bytes
        );
    }

    pub fn dump_sbi_stats(&self) {
        self.sbi.dump_stats();
    }

    pub fn dump_hotpcs(&self) {
        for hart in &self.harts {
            hart.dump_hotpcs();
        }
    }
}
