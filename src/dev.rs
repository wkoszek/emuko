use crate::bus::Device;
use crate::plic::PlicState;
use crate::trap::Trap;
use std::any::Any;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::rc::Rc;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

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
    lcr: u8,
    mcr: u8,
    fcr: u8,
    scr: u8,
    dll: u8,
    dlm: u8,
    tx_irq_pending: bool,
    rx_irq_pending: bool,
    rx_fifo: VecDeque<u8>,
    input_rx: Option<Receiver<u8>>,
    irq: Option<(Rc<RefCell<PlicState>>, usize)>,
    color_enabled: bool,
    color_active: bool,
    trace_input: bool,
    irq_line: bool,
    out_esc_state: u8,
    in_esc_state: u8,
    in_esc_buf: Vec<u8>,
    tx_capture: VecDeque<u8>,
    poll_ticks: u32,
    poll_countdown: u32,
    adaptive_poll: bool,
    poll_target_wall: Duration,
    poll_calib_min_wall: Duration,
    poll_calib_steps: u64,
    poll_calib_started: Instant,
    poll_check_ticks: u32,
    poll_check_countdown: u32,
    flush_every: usize,
    flush_count: usize,
}

#[derive(Clone, Debug)]
pub struct UartSnapshot {
    pub ier: u8,
    pub lcr: u8,
    pub mcr: u8,
    pub fcr: u8,
    pub scr: u8,
    pub dll: u8,
    pub dlm: u8,
    pub tx_irq_pending: bool,
    pub rx_irq_pending: bool,
    pub rx_fifo: Vec<u8>,
    pub color_enabled: bool,
    pub color_active: bool,
}

const IER_ERBFI: u8 = 1 << 0;
const IER_ETBEI: u8 = 1 << 1;
const LCR_DLAB: u8 = 1 << 7;
const UART_TX_CAPTURE_MAX: usize = 256 * 1024;
const UART_POLL_TICKS_DEFAULT: u32 = 1024;
const UART_POLL_CHECK_TICKS_DEFAULT: u32 = 2048;
const UART_POLL_WALL_MS_DEFAULT: u64 = 100;
const UART_POLL_CALIB_MS_DEFAULT: u64 = 250;
const UART_FLUSH_EVERY_DEFAULT: usize = 64;

impl Uart16550 {
    fn env_u64(name: &str, default: u64) -> u64 {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(default)
    }

    fn env_u32(name: &str, default: u32) -> u32 {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(default)
    }

    fn env_u32_opt(name: &str) -> Option<u32> {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .filter(|v| *v > 0)
    }

    fn env_usize(name: &str, default: usize) -> usize {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(default)
    }

    fn spawn_stdin_reader() -> Receiver<u8> {
        let (tx, rx) = mpsc::channel::<u8>();
        thread::spawn(move || {
            let stdin = io::stdin();
            let mut locked = stdin.lock();
            let mut buf = [0u8; 1];
            loop {
                match locked.read(&mut buf) {
                    Ok(0) => break,
                    Ok(_) => {
                        if tx.send(buf[0]).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        if e.kind() == io::ErrorKind::Interrupted {
                            continue;
                        }
                        break;
                    }
                }
            }
        });
        rx
    }

    pub fn with_irq(plic: Rc<RefCell<PlicState>>, irq: usize) -> Self {
        let fixed_poll_ticks = Self::env_u32_opt("UART_POLL_TICKS");
        let adaptive_poll = fixed_poll_ticks.is_none();
        let poll_ticks = fixed_poll_ticks.unwrap_or(UART_POLL_TICKS_DEFAULT);
        let poll_target_wall = Duration::from_millis(Self::env_u64(
            "UART_POLL_WALL_MS",
            UART_POLL_WALL_MS_DEFAULT,
        ));
        let poll_calib_min_wall = Duration::from_millis(Self::env_u64(
            "UART_POLL_CALIB_MS",
            UART_POLL_CALIB_MS_DEFAULT,
        ));
        let poll_check_ticks = Self::env_u32("UART_POLL_CHECK_TICKS", UART_POLL_CHECK_TICKS_DEFAULT);
        let flush_every = Self::env_usize("UART_FLUSH_EVERY", UART_FLUSH_EVERY_DEFAULT);
        Self {
            ier: 0,
            lcr: 0,
            mcr: 0,
            fcr: 0,
            scr: 0,
            dll: 0,
            dlm: 0,
            tx_irq_pending: false,
            rx_irq_pending: false,
            rx_fifo: VecDeque::new(),
            input_rx: Some(Self::spawn_stdin_reader()),
            irq: Some((plic, irq)),
            color_enabled: true,
            color_active: false,
            trace_input: std::env::var("UART_TRACE_INPUT").is_ok(),
            irq_line: false,
            out_esc_state: 0,
            in_esc_state: 0,
            in_esc_buf: Vec::new(),
            tx_capture: VecDeque::new(),
            poll_ticks,
            poll_countdown: poll_ticks,
            adaptive_poll,
            poll_target_wall,
            poll_calib_min_wall,
            poll_calib_steps: 0,
            poll_calib_started: Instant::now(),
            poll_check_ticks,
            poll_check_countdown: poll_check_ticks,
            flush_every,
            flush_count: 0,
        }
    }

    fn maybe_recalibrate_poll_ticks(&mut self) {
        if !self.adaptive_poll {
            return;
        }
        let now = Instant::now();
        let elapsed = now.duration_since(self.poll_calib_started);
        if elapsed < self.poll_calib_min_wall {
            return;
        }
        if self.poll_calib_steps == 0 {
            self.poll_calib_started = now;
            return;
        }
        let steps_per_sec = self.poll_calib_steps as f64 / elapsed.as_secs_f64();
        let mut next = (steps_per_sec * self.poll_target_wall.as_secs_f64()).round() as u64;
        next = next.clamp(1, 50_000_000);
        self.poll_ticks = next as u32;
        if self.poll_countdown > self.poll_ticks {
            self.poll_countdown = self.poll_ticks;
        }
        self.poll_calib_steps = 0;
        self.poll_calib_started = now;
    }

    pub fn configure_poll_auto(
        &mut self,
        target_wall: Duration,
        calib_min_wall: Duration,
        check_ticks: u32,
    ) {
        self.adaptive_poll = true;
        self.poll_target_wall = target_wall;
        self.poll_calib_min_wall = calib_min_wall;
        self.poll_check_ticks = check_ticks.max(1);
        self.poll_check_countdown = self.poll_check_ticks;
        self.poll_calib_steps = 0;
        self.poll_calib_started = Instant::now();
    }

    pub fn configure_poll_fixed(&mut self, ticks: u32) {
        let ticks = ticks.max(1);
        self.adaptive_poll = false;
        self.poll_ticks = ticks;
        self.poll_countdown = ticks;
    }

    pub fn configure_flush_every(&mut self, every: usize) {
        self.flush_every = every.max(1);
    }

    fn emit_raw_char(&mut self, ch: u8) {
        if self.tx_capture.len() >= UART_TX_CAPTURE_MAX {
            self.tx_capture.pop_front();
        }
        self.tx_capture.push_back(ch);
        if self.color_enabled && !self.color_active {
            print!("\x1b[38;5;208m");
            self.color_active = true;
        }
        print!("{}", ch as char);
        if self.color_enabled && self.color_active && (ch == b'\n' || ch == b'\r') {
            // Keep non-UART logs uncolored by resetting terminal color at line end.
            print!("\x1b[0m");
            self.color_active = false;
        }
        self.flush_count = self.flush_count.saturating_add(1);
        let should_flush = ch == b'\n' || ch == b'\r' || self.flush_count >= self.flush_every;
        if should_flush {
            let _ = io::stdout().flush();
            self.flush_count = 0;
        }
    }

    fn enqueue_rx(&mut self, ch: u8) {
        self.rx_fifo.push_back(ch);
        self.rx_irq_pending = true;
        if self.trace_input {
            eprintln!("uart: host->rx byte=0x{:02x}", ch);
        }
    }

    fn flush_input_escape_buf(&mut self) {
        let bytes = std::mem::take(&mut self.in_esc_buf);
        for b in bytes {
            self.enqueue_rx(b);
        }
    }

    fn handle_input_byte(&mut self, ch: u8) {
        match self.in_esc_state {
            0 => {
                if ch == 0x1b {
                    self.in_esc_state = 1;
                    self.in_esc_buf.clear();
                    self.in_esc_buf.push(ch);
                } else {
                    self.enqueue_rx(ch);
                }
            }
            1 => {
                self.in_esc_buf.push(ch);
                if ch == b'[' {
                    self.in_esc_state = 2;
                } else {
                    self.in_esc_state = 0;
                    self.flush_input_escape_buf();
                }
            }
            2 => {
                self.in_esc_buf.push(ch);
                if (0x40..=0x7e).contains(&ch) {
                    let params = &self.in_esc_buf[2..self.in_esc_buf.len() - 1];
                    let is_cursor_pos_report = ch == b'R'
                        && !params.is_empty()
                        && params.iter().all(|b| b.is_ascii_digit() || *b == b';');
                    self.in_esc_state = 0;
                    if !is_cursor_pos_report {
                        self.flush_input_escape_buf();
                    } else {
                        self.in_esc_buf.clear();
                    }
                } else if self.in_esc_buf.len() > 32 {
                    self.in_esc_state = 0;
                    self.flush_input_escape_buf();
                }
            }
            _ => {
                self.in_esc_state = 0;
                self.enqueue_rx(ch);
            }
        }
    }

    #[allow(dead_code)]
    pub fn inject_bytes(&mut self, data: &[u8]) {
        for &b in data {
            self.enqueue_rx(b);
        }
        self.update_irq_line();
    }

    #[allow(dead_code)]
    pub fn drain_tx_bytes(&mut self, max: usize) -> Vec<u8> {
        if self.tx_capture.is_empty() {
            return Vec::new();
        }
        let n = if max == 0 {
            self.tx_capture.len()
        } else {
            max.min(self.tx_capture.len())
        };
        self.tx_capture.drain(..n).collect()
    }

    fn emit_char(&mut self, ch: u8) {
        match self.out_esc_state {
            0 => {
                if ch == 0x1b {
                    self.out_esc_state = 1;
                } else {
                    self.emit_raw_char(ch);
                }
            }
            1 => {
                if ch == b'[' {
                    self.out_esc_state = 2;
                } else {
                    self.emit_raw_char(0x1b);
                    self.emit_raw_char(ch);
                    self.out_esc_state = 0;
                }
            }
            2 => {
                if ch == b'6' {
                    self.out_esc_state = 3;
                } else {
                    self.emit_raw_char(0x1b);
                    self.emit_raw_char(b'[');
                    self.emit_raw_char(ch);
                    self.out_esc_state = 0;
                }
            }
            3 => {
                if ch != b'n' {
                    self.emit_raw_char(0x1b);
                    self.emit_raw_char(b'[');
                    self.emit_raw_char(b'6');
                    self.emit_raw_char(ch);
                }
                // Consume ESC[6n cursor query to avoid host terminal response
                // bytes (e.g. ^[[58;5R) polluting guest console interaction.
                self.out_esc_state = 0;
            }
            _ => {
                self.out_esc_state = 0;
            }
        }
    }

    fn set_irq(&mut self, pending: bool) {
        if let Some((plic, irq)) = &self.irq {
            let mut p = plic.borrow_mut();
            if pending {
                p.force_enable_irq_all_contexts(*irq);
            }
            p.set_pending(*irq, pending);
        }
    }

    fn update_irq_line(&mut self) {
        // Be permissive on RX IRQ assertion: some guest paths rely on
        // immediate wakeups while probing UART config, and strict IER gating
        // can leave console input stuck with no prompt.
        let rx = self.rx_irq_pending;
        let tx = self.tx_irq_pending && (self.ier & IER_ETBEI) != 0;
        let asserted = rx || tx;
        if self.trace_input && asserted != self.irq_line {
            let plic_state = self
                .irq
                .as_ref()
                .map(|(plic, irq)| plic.borrow().source_status(0, *irq));
            eprintln!(
                "uart: irq_line {} (rx_pending={} tx_pending={} ier=0x{:02x} lcr=0x{:02x})",
                if asserted { "assert" } else { "deassert" },
                self.rx_irq_pending,
                self.tx_irq_pending,
                self.ier,
                self.lcr
            );
            if let Some((pending, enabled, prio, threshold, deliver)) = plic_state {
                eprintln!(
                    "uart: plic src pending={} enabled={} prio={} threshold={} deliver={}",
                    pending, enabled, prio, threshold, deliver
                );
            }
        }
        self.irq_line = asserted;
        self.set_irq(asserted);
    }

    fn poll_input(&mut self) {
        let mut disconnected = false;
        loop {
            let next = match self.input_rx.as_ref() {
                Some(rx) => rx.try_recv(),
                None => break,
            };
            match next {
                Ok(ch) => {
                    self.handle_input_byte(ch);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    disconnected = true;
                    break;
                }
            }
        }
        if disconnected {
            self.input_rx = None;
        }
        self.update_irq_line();
    }

    pub fn snapshot(&self) -> UartSnapshot {
        UartSnapshot {
            ier: self.ier,
            lcr: self.lcr,
            mcr: self.mcr,
            fcr: self.fcr,
            scr: self.scr,
            dll: self.dll,
            dlm: self.dlm,
            tx_irq_pending: self.tx_irq_pending,
            rx_irq_pending: self.rx_irq_pending,
            rx_fifo: self.rx_fifo.iter().copied().collect(),
            color_enabled: self.color_enabled,
            color_active: self.color_active,
        }
    }

    pub fn restore(&mut self, snap: UartSnapshot) {
        self.ier = snap.ier;
        self.lcr = snap.lcr;
        self.mcr = snap.mcr;
        self.fcr = snap.fcr;
        self.scr = snap.scr;
        self.dll = snap.dll;
        self.dlm = snap.dlm;
        self.tx_irq_pending = snap.tx_irq_pending;
        self.rx_irq_pending = snap.rx_irq_pending;
        self.rx_fifo = snap.rx_fifo.into_iter().collect();
        self.color_enabled = snap.color_enabled;
        self.color_active = snap.color_active;
        self.irq_line = false;
        self.out_esc_state = 0;
        self.in_esc_state = 0;
        self.in_esc_buf.clear();
        self.tx_capture.clear();
        self.poll_countdown = self.poll_ticks;
        self.poll_calib_steps = 0;
        self.poll_calib_started = Instant::now();
        self.poll_check_countdown = self.poll_check_ticks;
        self.flush_count = 0;
        self.update_irq_line();
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
        self.poll_input();
        let val = match addr {
            0 => {
                if (self.lcr & LCR_DLAB) != 0 {
                    self.dll
                } else {
                    let v = self.rx_fifo.pop_front().unwrap_or(0);
                    if self.rx_fifo.is_empty() {
                        self.rx_irq_pending = false;
                    }
                    if self.trace_input {
                        eprintln!("uart: guest read rbr byte=0x{:02x}", v);
                    }
                    v
                }
            }
            1 => {
                if (self.lcr & LCR_DLAB) != 0 {
                    self.dlm
                } else {
                    self.ier
                }
            }
            2 => {
                // IIR: bit0=1 means no pending interrupt.
                if self.rx_irq_pending && (self.ier & IER_ERBFI) != 0 {
                    0x04
                } else if self.tx_irq_pending && (self.ier & IER_ETBEI) != 0 {
                    self.tx_irq_pending = false;
                    0x02
                } else {
                    0x01
                }
            }
            3 => self.lcr,
            4 => self.mcr,
            5 => {
                let mut lsr = 0x60u8; // THR empty + TEMT
                if !self.rx_fifo.is_empty() {
                    lsr |= 0x01; // Data ready
                }
                lsr
            }
            6 => 0xB0, // DCD + DSR + CTS high
            7 => self.scr,
            _ => 0,
        };
        self.update_irq_line();
        Ok(val as u64)
    }

    fn write(&mut self, addr: u64, size: usize, value: u64) -> Result<(), Trap> {
        if size != 1 {
            return Err(Trap::MemoryOutOfBounds {
                addr,
                size: size as u64,
            });
        }
        self.poll_input();
        let val = value as u8;
        match addr {
            0 => {
                if (self.lcr & LCR_DLAB) != 0 {
                    self.dll = val;
                } else {
                    self.emit_char(val);
                    if (self.ier & IER_ETBEI) != 0 {
                        self.tx_irq_pending = true;
                    }
                }
            }
            1 => {
                if (self.lcr & LCR_DLAB) != 0 {
                    self.dlm = val;
                } else {
                    self.ier = val;
                    if self.trace_input {
                        eprintln!("uart: guest write ier=0x{:02x}", self.ier);
                    }
                    if (self.ier & IER_ETBEI) == 0 {
                        self.tx_irq_pending = false;
                    }
                }
            }
            2 => {
                self.fcr = val;
                if (val & 0x02) != 0 {
                    self.rx_fifo.clear();
                    self.rx_irq_pending = false;
                }
                if (val & 0x04) != 0 {
                    self.tx_irq_pending = false;
                }
            }
            3 => {
                self.lcr = val;
            }
            4 => {
                self.mcr = val;
            }
            7 => {
                self.scr = val;
            }
            _ => {}
        }
        self.update_irq_line();
        Ok(())
    }

    fn tick(&mut self) {
        self.poll_calib_steps = self.poll_calib_steps.saturating_add(1);
        if self.poll_check_countdown <= 1 {
            self.poll_check_countdown = self.poll_check_ticks;
            self.maybe_recalibrate_poll_ticks();
        } else {
            self.poll_check_countdown -= 1;
        }
        if self.poll_countdown <= 1 {
            self.poll_input();
            self.poll_countdown = self.poll_ticks;
        } else {
            self.poll_countdown -= 1;
        }
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}
