use crate::bus::{AccessType, BusStats, Counter, DeviceStats};
use crate::clint::ClintSnapshot;
use crate::csr::PrivMode;
use crate::dev::{RamSnapshot, UartSnapshot};
use crate::efi::{EfiMemDesc, EfiSnapshot};
use crate::hart::HartSnapshot;
use crate::plic::PlicSnapshot;
use crate::sbi::SbiSnapshot;
use std::convert::TryFrom;
use std::fs::File;
use std::io::{BufWriter, Cursor, Read, Write};

const MAGIC: &[u8; 8] = b"KRSVSNP1";
const VERSION: u32 = 6;

#[derive(Clone, Debug)]
pub struct MachineSnapshot {
    pub ram_base: u64,
    pub ram_size: usize,
    pub reset_pc: u64,
    pub trace_traps: Option<u64>,
    pub total_steps: u64,
    pub harts: Vec<HartSnapshot>,
    pub clint: ClintSnapshot,
    pub plic: PlicSnapshot,
    pub uart: UartSnapshot,
    pub ram: RamSnapshot,
    pub sbi: SbiSnapshot,
    pub bus_stats: BusStats,
}

struct BinWriter<W: Write> {
    w: W,
}

impl<W: Write> BinWriter<W> {
    fn new(w: W) -> Self {
        Self { w }
    }

    fn write_u8(&mut self, v: u8) -> Result<(), String> {
        self.w.write_all(&[v]).map_err(|e| e.to_string())
    }

    fn write_bool(&mut self, v: bool) -> Result<(), String> {
        self.write_u8(if v { 1 } else { 0 })
    }

    fn write_u32(&mut self, v: u32) -> Result<(), String> {
        self.w
            .write_all(&v.to_le_bytes())
            .map_err(|e| e.to_string())
    }

    fn write_u64(&mut self, v: u64) -> Result<(), String> {
        self.w
            .write_all(&v.to_le_bytes())
            .map_err(|e| e.to_string())
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), String> {
        self.w.write_all(bytes).map_err(|e| e.to_string())
    }

    fn write_len_u32(&mut self, len: usize) -> Result<(), String> {
        let v = u32::try_from(len).map_err(|_| "length exceeds u32".to_string())?;
        self.write_u32(v)
    }

    fn write_opt_u64(&mut self, v: Option<u64>) -> Result<(), String> {
        match v {
            Some(val) => {
                self.write_bool(true)?;
                self.write_u64(val)
            }
            None => self.write_bool(false),
        }
    }

    fn write_string(&mut self, s: &str) -> Result<(), String> {
        self.write_len_u32(s.len())?;
        self.write_bytes(s.as_bytes())
    }
}

struct BinReader<R: Read> {
    r: R,
}

impl<R: Read> BinReader<R> {
    fn new(r: R) -> Self {
        Self { r }
    }

    fn read_exact(&mut self, out: &mut [u8]) -> Result<(), String> {
        self.r.read_exact(out).map_err(|e| e.to_string())
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        let mut b = [0u8; 1];
        self.read_exact(&mut b)?;
        Ok(b[0])
    }

    fn read_bool(&mut self) -> Result<bool, String> {
        let v = self.read_u8()?;
        match v {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err("invalid bool encoding".to_string()),
        }
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        let mut b = [0u8; 4];
        self.read_exact(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        let mut b = [0u8; 8];
        self.read_exact(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, String> {
        let mut data = vec![0u8; len];
        self.read_exact(&mut data)?;
        Ok(data)
    }

    fn read_len_u32(&mut self) -> Result<usize, String> {
        let v = self.read_u32()?;
        usize::try_from(v).map_err(|_| "length conversion failed".to_string())
    }

    fn read_opt_u64(&mut self) -> Result<Option<u64>, String> {
        if self.read_bool()? {
            Ok(Some(self.read_u64()?))
        } else {
            Ok(None)
        }
    }

    fn read_string(&mut self) -> Result<String, String> {
        let len = self.read_len_u32()?;
        let bytes = self.read_vec(len)?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }
}

fn access_to_u8(kind: AccessType) -> u8 {
    match kind {
        AccessType::Fetch => 0,
        AccessType::Load => 1,
        AccessType::Store => 2,
        AccessType::Debug => 3,
    }
}

fn u8_to_access(v: u8) -> Result<AccessType, String> {
    match v {
        0 => Ok(AccessType::Fetch),
        1 => Ok(AccessType::Load),
        2 => Ok(AccessType::Store),
        3 => Ok(AccessType::Debug),
        _ => Err("invalid access type".to_string()),
    }
}

fn priv_to_u8(mode: PrivMode) -> u8 {
    mode as u8
}

fn u8_to_priv(v: u8) -> Result<PrivMode, String> {
    match v {
        0 => Ok(PrivMode::User),
        1 => Ok(PrivMode::Supervisor),
        3 => Ok(PrivMode::Machine),
        _ => Err("invalid privilege mode".to_string()),
    }
}

fn write_counter<W: Write>(w: &mut BinWriter<W>, c: &Counter) -> Result<(), String> {
    w.write_u64(c.reads)?;
    w.write_u64(c.writes)?;
    w.write_u64(c.fetches)?;
    w.write_u64(c.bytes)?;
    Ok(())
}

fn read_counter<R: Read>(r: &mut BinReader<R>) -> Result<Counter, String> {
    Ok(Counter {
        reads: r.read_u64()?,
        writes: r.read_u64()?,
        fetches: r.read_u64()?,
        bytes: r.read_u64()?,
    })
}

fn write_efi<W: Write>(w: &mut BinWriter<W>, efi: &EfiSnapshot) -> Result<(), String> {
    w.write_len_u32(efi.mem_map.len())?;
    for d in &efi.mem_map {
        w.write_u32(d.ty)?;
        w.write_u64(d.phys_start)?;
        w.write_u64(d.num_pages)?;
        w.write_u64(d.attr)?;
    }
    w.write_u64(efi.map_key)?;
    w.write_u64(efi.desc_size)?;
    w.write_u32(efi.desc_version)?;
    w.write_u64(efi.alloc_bottom)?;
    w.write_u64(efi.alloc_top)?;
    w.write_u64(efi.alloc_next)?;
    w.write_u64(efi.pool_next)?;
    w.write_u64(efi.image_handle)?;
    w.write_u64(efi.loaded_image)?;
    w.write_u64(efi.initrd_handle)?;
    w.write_u64(efi.initrd_devpath)?;
    w.write_u64(efi.riscv_boot_proto)?;
    w.write_u64(efi.riscv_fdt_proto)?;
    w.write_u64(efi.load_file_proto)?;
    w.write_u64(efi.load_file2_proto)?;
    w.write_u64(efi.dtb_addr)?;
    w.write_u64(efi.dtb_size)?;
    w.write_u64(efi.initrd_addr)?;
    w.write_u64(efi.initrd_size)?;
    w.write_bool(efi.trace)?;
    Ok(())
}

fn read_efi<R: Read>(r: &mut BinReader<R>) -> Result<EfiSnapshot, String> {
    let mem_len = r.read_len_u32()?;
    let mut mem_map = Vec::with_capacity(mem_len);
    for _ in 0..mem_len {
        mem_map.push(EfiMemDesc {
            ty: r.read_u32()?,
            phys_start: r.read_u64()?,
            num_pages: r.read_u64()?,
            attr: r.read_u64()?,
        });
    }
    Ok(EfiSnapshot {
        mem_map,
        map_key: r.read_u64()?,
        desc_size: r.read_u64()?,
        desc_version: r.read_u32()?,
        alloc_bottom: r.read_u64()?,
        alloc_top: r.read_u64()?,
        alloc_next: r.read_u64()?,
        pool_next: r.read_u64()?,
        image_handle: r.read_u64()?,
        loaded_image: r.read_u64()?,
        initrd_handle: r.read_u64()?,
        initrd_devpath: r.read_u64()?,
        riscv_boot_proto: r.read_u64()?,
        riscv_fdt_proto: r.read_u64()?,
        load_file_proto: r.read_u64()?,
        load_file2_proto: r.read_u64()?,
        dtb_addr: r.read_u64()?,
        dtb_size: r.read_u64()?,
        initrd_addr: r.read_u64()?,
        initrd_size: r.read_u64()?,
        trace: r.read_bool()?,
    })
}

pub fn save(path: &str, snap: &MachineSnapshot) -> Result<(), String> {
    let file = File::create(path).map_err(|e| e.to_string())?;
    let encoder = zstd::stream::write::Encoder::new(file, 3).map_err(|e| e.to_string())?;
    let mut w = BinWriter::new(BufWriter::new(encoder));
    w.write_bytes(MAGIC)?;
    w.write_u32(VERSION)?;

    w.write_u64(snap.ram_base)?;
    w.write_u64(u64::try_from(snap.ram_size).map_err(|_| "ram size too large".to_string())?)?;
    w.write_u64(snap.reset_pc)?;
    w.write_opt_u64(snap.trace_traps)?;
    w.write_u64(snap.total_steps)?;

    w.write_len_u32(snap.harts.len())?;
    for hart in &snap.harts {
        w.write_u64(u64::try_from(hart.hart_id).map_err(|_| "hart id too large".to_string())?)?;
        w.write_u64(hart.misa_ext)?;
        w.write_u64(hart.pc)?;
        w.write_u8(priv_to_u8(hart.priv_mode))?;
        for v in hart.regs {
            w.write_u64(v)?;
        }
        for v in hart.fregs {
            w.write_u64(v)?;
        }
        w.write_opt_u64(hart.reservation)?;
        w.write_u64(hart.instret_pending)?;
        if let Some((kind, addr, size)) = hart.last_access {
            w.write_bool(true)?;
            w.write_u8(access_to_u8(kind))?;
            w.write_u64(addr)?;
            w.write_u64(size)?;
        } else {
            w.write_bool(false)?;
        }
        w.write_opt_u64(hart.trace_instr)?;
        w.write_opt_u64(hart.trace_pc_left)?;
        w.write_u64(hart.watch_left)?;
        w.write_u64(hart.watch_left2)?;
        w.write_u64(hart.mmu_trace_left)?;
        w.write_u32(hart.time_div_accum)?;
        w.write_u64(hart.time_jitter_state)?;
        w.write_len_u32(hart.csrs.regs.len())?;
        for csr in &hart.csrs.regs {
            w.write_u64(*csr)?;
        }
    }

    w.write_u64(snap.clint.mtime)?;
    w.write_len_u32(snap.clint.mtimecmp.len())?;
    for v in &snap.clint.mtimecmp {
        w.write_u64(*v)?;
    }
    w.write_len_u32(snap.clint.msip.len())?;
    for v in &snap.clint.msip {
        w.write_u32(*v)?;
    }

    w.write_len_u32(snap.plic.priority.len())?;
    for v in &snap.plic.priority {
        w.write_u32(*v)?;
    }
    w.write_len_u32(snap.plic.pending.len())?;
    for v in &snap.plic.pending {
        w.write_u32(*v)?;
    }
    w.write_len_u32(snap.plic.enable.len())?;
    for ctx in &snap.plic.enable {
        w.write_len_u32(ctx.len())?;
        for v in ctx {
            w.write_u32(*v)?;
        }
    }
    w.write_len_u32(snap.plic.threshold.len())?;
    for v in &snap.plic.threshold {
        w.write_u32(*v)?;
    }

    w.write_u8(snap.uart.ier)?;
    w.write_u8(snap.uart.lcr)?;
    w.write_u8(snap.uart.mcr)?;
    w.write_u8(snap.uart.fcr)?;
    w.write_u8(snap.uart.scr)?;
    w.write_u8(snap.uart.dll)?;
    w.write_u8(snap.uart.dlm)?;
    w.write_bool(snap.uart.tx_irq_pending)?;
    w.write_bool(snap.uart.rx_irq_pending)?;
    w.write_len_u32(snap.uart.rx_fifo.len())?;
    for b in &snap.uart.rx_fifo {
        w.write_u8(*b)?;
    }
    w.write_bool(snap.uart.color_enabled)?;
    w.write_bool(snap.uart.color_active)?;

    w.write_bool(snap.sbi.shutdown)?;
    w.write_bool(snap.sbi.trace)?;
    w.write_bool(snap.sbi.trace_efi_unsupported)?;
    w.write_bool(snap.sbi.force_stip)?;
    w.write_len_u32(snap.sbi.ecall_counts.len())?;
    for (eid, fid, count) in &snap.sbi.ecall_counts {
        w.write_u64(*eid)?;
        w.write_u64(*fid)?;
        w.write_u64(*count)?;
    }
    if let Some(efi) = &snap.sbi.efi {
        w.write_bool(true)?;
        write_efi(&mut w, efi)?;
    } else {
        w.write_bool(false)?;
    }

    write_counter(&mut w, &snap.bus_stats.total)?;
    w.write_len_u32(snap.bus_stats.per_hart.len())?;
    for c in &snap.bus_stats.per_hart {
        write_counter(&mut w, c)?;
    }
    w.write_len_u32(snap.bus_stats.per_device.len())?;
    for d in &snap.bus_stats.per_device {
        w.write_string(&d.name)?;
        write_counter(&mut w, &d.counter)?;
    }

    w.write_u64(
        u64::try_from(snap.ram.data.len()).map_err(|_| "ram length too large".to_string())?,
    )?;
    w.write_bytes(&snap.ram.data)?;
    w.w.flush().map_err(|e| e.to_string())?;
    let encoder = w.w.into_inner().map_err(|e| e.to_string())?;
    encoder.finish().map_err(|e| e.to_string())?;
    Ok(())
}

pub fn load(path: &str) -> Result<MachineSnapshot, String> {
    let raw = std::fs::read(path).map_err(|e| e.to_string())?;
    let bytes = match zstd::stream::decode_all(raw.as_slice()) {
        Ok(data) => data,
        Err(_) => raw,
    };
    let mut r = BinReader::new(Cursor::new(bytes));
    let mut magic = [0u8; 8];
    r.read_exact(&mut magic)?;
    if &magic != MAGIC {
        return Err("invalid snapshot magic".to_string());
    }
    let ver = r.read_u32()?;
    if ver != 1 && ver != 2 && ver != 3 && ver != 4 && ver != 5 && ver != VERSION {
        return Err(format!("unsupported snapshot version {}", ver));
    }

    let ram_base = r.read_u64()?;
    let ram_size_u64 = r.read_u64()?;
    let ram_size = usize::try_from(ram_size_u64).map_err(|_| "ram size overflow".to_string())?;
    let reset_pc = r.read_u64()?;
    let trace_traps = r.read_opt_u64()?;
    let total_steps = r.read_u64()?;

    let hart_len = r.read_len_u32()?;
    let mut harts = Vec::with_capacity(hart_len);
    for _ in 0..hart_len {
        let hart_id_u64 = r.read_u64()?;
        let hart_id = usize::try_from(hart_id_u64).map_err(|_| "hart id overflow".to_string())?;
        let misa_ext = r.read_u64()?;
        let pc = r.read_u64()?;
        let priv_mode = u8_to_priv(r.read_u8()?)?;
        let mut regs = [0u64; 32];
        for v in &mut regs {
            *v = r.read_u64()?;
        }
        let mut fregs = [0u64; 32];
        for v in &mut fregs {
            *v = r.read_u64()?;
        }
        let reservation = r.read_opt_u64()?;
        let instret_pending = if ver >= 6 { r.read_u64()? } else { 0 };
        let last_access = if r.read_bool()? {
            Some((u8_to_access(r.read_u8()?)?, r.read_u64()?, r.read_u64()?))
        } else {
            None
        };
        let trace_instr = r.read_opt_u64()?;
        let trace_pc_left = r.read_opt_u64()?;
        let watch_left = r.read_u64()?;
        let watch_left2 = r.read_u64()?;
        let mmu_trace_left = r.read_u64()?;
        let time_div_accum = if ver >= 5 { r.read_u32()? } else { 0 };
        let time_jitter_state = if ver >= 4 {
            r.read_u64()?
        } else {
            0x9E37_79B9_7F4A_7C15u64 ^ ((hart_id as u64) << 32)
        };
        let csr_len = r.read_len_u32()?;
        let mut csr_regs = Vec::with_capacity(csr_len);
        for _ in 0..csr_len {
            csr_regs.push(r.read_u64()?);
        }
        harts.push(HartSnapshot {
            regs,
            fregs,
            pc,
            hart_id,
            priv_mode,
            csrs: crate::csr::CsrSnapshot { regs: csr_regs },
            misa_ext,
            reservation,
            instret_pending,
            last_access,
            trace_instr,
            trace_pc_left,
            watch_left,
            watch_left2,
            mmu_trace_left,
            time_div_accum,
            time_jitter_state,
        });
    }

    let mtime = r.read_u64()?;
    let mtimecmp_len = r.read_len_u32()?;
    let mut mtimecmp = Vec::with_capacity(mtimecmp_len);
    for _ in 0..mtimecmp_len {
        mtimecmp.push(r.read_u64()?);
    }
    let msip_len = r.read_len_u32()?;
    let mut msip = Vec::with_capacity(msip_len);
    for _ in 0..msip_len {
        msip.push(r.read_u32()?);
    }
    let clint = ClintSnapshot {
        mtime,
        mtimecmp,
        msip,
    };

    let prio_len = r.read_len_u32()?;
    let mut priority = Vec::with_capacity(prio_len);
    for _ in 0..prio_len {
        priority.push(r.read_u32()?);
    }
    let pending_len = r.read_len_u32()?;
    let mut pending = Vec::with_capacity(pending_len);
    for _ in 0..pending_len {
        pending.push(r.read_u32()?);
    }
    let enable_ctx_len = r.read_len_u32()?;
    let mut enable = Vec::with_capacity(enable_ctx_len);
    for _ in 0..enable_ctx_len {
        let words = r.read_len_u32()?;
        let mut ctx = Vec::with_capacity(words);
        for _ in 0..words {
            ctx.push(r.read_u32()?);
        }
        enable.push(ctx);
    }
    let threshold_len = r.read_len_u32()?;
    let mut threshold = Vec::with_capacity(threshold_len);
    for _ in 0..threshold_len {
        threshold.push(r.read_u32()?);
    }
    let plic = PlicSnapshot {
        priority,
        pending,
        enable,
        threshold,
    };

    let uart = if ver >= 3 {
        let ier = r.read_u8()?;
        let lcr = r.read_u8()?;
        let mcr = r.read_u8()?;
        let fcr = r.read_u8()?;
        let scr = r.read_u8()?;
        let dll = r.read_u8()?;
        let dlm = r.read_u8()?;
        let tx_irq_pending = r.read_bool()?;
        let rx_irq_pending = r.read_bool()?;
        let rx_len = r.read_len_u32()?;
        let mut rx_fifo = Vec::with_capacity(rx_len);
        for _ in 0..rx_len {
            rx_fifo.push(r.read_u8()?);
        }
        UartSnapshot {
            ier,
            lcr,
            mcr,
            fcr,
            scr,
            dll,
            dlm,
            tx_irq_pending,
            rx_irq_pending,
            rx_fifo,
            color_enabled: r.read_bool()?,
            color_active: r.read_bool()?,
        }
    } else {
        UartSnapshot {
            ier: r.read_u8()?,
            lcr: 0,
            mcr: 0,
            fcr: 0,
            scr: 0,
            dll: 0,
            dlm: 0,
            tx_irq_pending: false,
            rx_irq_pending: false,
            rx_fifo: Vec::new(),
            color_enabled: r.read_bool()?,
            color_active: r.read_bool()?,
        }
    };

    let shutdown = r.read_bool()?;
    let trace = r.read_bool()?;
    let trace_efi_unsupported = r.read_bool()?;
    let force_stip = r.read_bool()?;
    let ecall_len = r.read_len_u32()?;
    let mut ecall_counts = Vec::with_capacity(ecall_len);
    for _ in 0..ecall_len {
        ecall_counts.push((r.read_u64()?, r.read_u64()?, r.read_u64()?));
    }
    let efi = if r.read_bool()? {
        Some(read_efi(&mut r)?)
    } else {
        None
    };
    let sbi = SbiSnapshot {
        shutdown,
        efi,
        trace,
        trace_efi_unsupported,
        force_stip,
        ecall_counts,
    };

    let total = read_counter(&mut r)?;
    let per_hart_len = r.read_len_u32()?;
    let mut per_hart = Vec::with_capacity(per_hart_len);
    for _ in 0..per_hart_len {
        per_hart.push(read_counter(&mut r)?);
    }
    let per_dev_len = r.read_len_u32()?;
    let mut per_device = Vec::with_capacity(per_dev_len);
    for _ in 0..per_dev_len {
        per_device.push(DeviceStats {
            name: r.read_string()?,
            counter: read_counter(&mut r)?,
        });
    }
    let bus_stats = BusStats {
        total,
        per_hart,
        per_device,
    };

    let ram_len_u64 = r.read_u64()?;
    let ram_len = usize::try_from(ram_len_u64).map_err(|_| "ram length overflow".to_string())?;
    let ram = RamSnapshot {
        data: r.read_vec(ram_len)?,
    };

    Ok(MachineSnapshot {
        ram_base,
        ram_size,
        reset_pc,
        trace_traps,
        total_steps,
        harts,
        clint,
        plic,
        uart,
        ram,
        sbi,
        bus_stats,
    })
}
