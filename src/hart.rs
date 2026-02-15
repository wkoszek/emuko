use crate::bus::{AccessType, Bus};
use crate::csr::{
    CsrFile, CsrSnapshot, PrivMode, CSR_MEPC, CSR_SATP, CSR_SCAUSE, CSR_SEPC, CSR_SIE, CSR_SIP,
    CSR_SSTATUS, CSR_STVAL, CSR_STVEC, SIP_SEIP, SIP_SSIP, SIP_STIP, SSTATUS_SIE, SSTATUS_SPIE,
    SSTATUS_SPP,
};
use crate::disas;
use crate::isa::*;
use crate::sbi::Sbi;
use crate::trap::Trap;
use std::collections::HashMap;

#[derive(Clone, Copy)]
struct TlbEntry {
    vpage: u64,
    ppage: u64,
    perms: u8,
}

#[derive(Clone, Copy)]
struct FastTlbEntry {
    satp: u64,
    vpage: u64,
    ppage: u64,
}

#[derive(Clone, Copy)]
struct DecodeCacheEntry {
    satp: u64,
    pc: u64,
    instr: u32,
    decoded: Decoded32,
}

#[derive(Clone, Copy, Default)]
struct Decoded32 {
    opcode: u8,
    rd: u8,
    funct3: u8,
    rs1: u8,
    rs2: u8,
    funct7: u8,
    funct5: u8,
    imm12: u16,
    csr_addr: u16,
}

const TLB_CACHE_SIZE: usize = 2_048;
const DECODE_CACHE_SIZE: usize = 8_192;
const TLB_PERM_R: u8 = 1 << 0;
const TLB_PERM_W: u8 = 1 << 1;
const TLB_PERM_X: u8 = 1 << 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NativeBlockResult {
    next_pc: u64,
    executed: u64,
}

#[derive(Clone, Copy)]
struct NativeBlock {
    #[cfg(target_arch = "aarch64")]
    offset: usize,
    instrs: u32,
}

#[cfg(target_arch = "aarch64")]
type NativeBlockFn = unsafe extern "C" fn(*mut u64) -> NativeBlockResult;

#[cfg(target_arch = "aarch64")]
struct NativeCodeCache {
    ptr: *mut u8,
    size: usize,
    used: usize,
}

#[cfg(target_arch = "aarch64")]
impl NativeCodeCache {
    fn new(size: usize) -> Option<Self> {
        use std::ffi::c_void;

        extern "C" {
            fn mmap(
                addr: *mut c_void,
                len: usize,
                prot: i32,
                flags: i32,
                fd: i32,
                offset: isize,
            ) -> *mut c_void;
        }

        const PROT_READ: i32 = 0x1;
        const PROT_WRITE: i32 = 0x2;
        const PROT_EXEC: i32 = 0x4;
        const MAP_PRIVATE: i32 = 0x02;
        #[cfg(target_os = "macos")]
        const MAP_ANON: i32 = 0x1000;
        #[cfg(target_os = "macos")]
        const MAP_JIT: i32 = 0x0800;
        #[cfg(not(target_os = "macos"))]
        const MAP_ANON: i32 = 0x20;

        if size == 0 {
            return None;
        }

        // Keep the first implementation simple: one RWX arena for generated blocks.
        #[cfg(target_os = "macos")]
        let flags = MAP_PRIVATE | MAP_ANON | MAP_JIT;
        #[cfg(not(target_os = "macos"))]
        let flags = MAP_PRIVATE | MAP_ANON;

        let mut p = unsafe {
            mmap(
                std::ptr::null_mut(),
                size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                flags,
                -1,
                0,
            )
        };
        #[cfg(target_os = "macos")]
        if p as isize == -1 {
            // Some environments deny MAP_JIT; try a best-effort fallback.
            p = unsafe {
                mmap(
                    std::ptr::null_mut(),
                    size,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_PRIVATE | MAP_ANON,
                    -1,
                    0,
                )
            };
        }
        if p as isize == -1 {
            return None;
        }
        Some(Self {
            ptr: p as *mut u8,
            size,
            used: 0,
        })
    }

    fn clear(&mut self) {
        self.used = 0;
    }

    fn alloc(&mut self, code: &[u8]) -> Option<usize> {
        let aligned = (self.used + 3) & !3;
        let end = aligned.checked_add(code.len())?;
        if end > self.size {
            return None;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), self.ptr.add(aligned), code.len());
        }
        self.flush_icache(aligned, code.len());
        self.used = end;
        Some(aligned)
    }

    fn ptr_at(&self, off: usize) -> *const u8 {
        unsafe { self.ptr.add(off) as *const u8 }
    }

    fn flush_icache(&self, off: usize, len: usize) {
        #[cfg(target_os = "macos")]
        unsafe {
            use std::ffi::c_void;
            extern "C" {
                fn sys_icache_invalidate(start: *const c_void, len: usize);
            }
            sys_icache_invalidate(self.ptr.add(off) as *const c_void, len);
        }
        #[cfg(not(target_os = "macos"))]
        unsafe {
            extern "C" {
                fn __clear_cache(start: *mut i8, end: *mut i8);
            }
            let start = self.ptr.add(off) as *mut i8;
            let end = self.ptr.add(off + len) as *mut i8;
            __clear_cache(start, end);
        }
    }
}

#[cfg(target_arch = "aarch64")]
impl Drop for NativeCodeCache {
    fn drop(&mut self) {
        use std::ffi::c_void;
        extern "C" {
            fn munmap(addr: *mut c_void, len: usize) -> i32;
        }
        let _ = unsafe { munmap(self.ptr as *mut c_void, self.size) };
    }
}

struct NativeJit {
    enabled: bool,
    blocks: HashMap<(u64, u64), NativeBlock>,
    #[cfg(target_arch = "aarch64")]
    cache: Option<NativeCodeCache>,
}

impl NativeJit {
    fn new(enabled: bool, code_size: usize) -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            let cache = if enabled {
                NativeCodeCache::new(code_size)
            } else {
                None
            };
            let ready = cache.is_some();
            if enabled && !ready {
                eprintln!("jit-a64: disabled (failed to allocate executable code cache)");
            }
            Self {
                enabled: enabled && ready,
                blocks: HashMap::new(),
                cache,
            }
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = code_size;
            Self {
                enabled: false,
                blocks: HashMap::new(),
            }
        }
    }

    fn clear(&mut self) {
        self.blocks.clear();
        #[cfg(target_arch = "aarch64")]
        if let Some(cache) = self.cache.as_mut() {
            cache.clear();
        }
    }

    fn lookup(&self, satp: u64, pc: u64) -> Option<NativeBlock> {
        self.blocks.get(&(satp, pc)).copied()
    }

    fn insert(&mut self, satp: u64, pc: u64, block: NativeBlock) {
        self.blocks.insert((satp, pc), block);
    }
}

#[cfg(target_arch = "aarch64")]
struct A64Emitter {
    words: Vec<u32>,
}

#[cfg(target_arch = "aarch64")]
impl A64Emitter {
    fn new() -> Self {
        Self {
            words: Vec::with_capacity(256),
        }
    }

    #[inline]
    fn emit(&mut self, w: u32) {
        self.words.push(w);
    }

    #[inline]
    fn ldr_x(rt: u8, rn: u8, off_bytes: u16) -> u32 {
        let imm12 = (off_bytes as u32) >> 3;
        0xF940_0000 | (imm12 << 10) | ((rn as u32) << 5) | rt as u32
    }

    #[inline]
    fn str_x(rt: u8, rn: u8, off_bytes: u16) -> u32 {
        let imm12 = (off_bytes as u32) >> 3;
        0xF900_0000 | (imm12 << 10) | ((rn as u32) << 5) | rt as u32
    }

    #[inline]
    fn add_x(rd: u8, rn: u8, rm: u8) -> u32 {
        0x8B00_0000 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }

    #[inline]
    fn sub_x(rd: u8, rn: u8, rm: u8) -> u32 {
        0xCB00_0000 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }

    #[inline]
    fn and_x(rd: u8, rn: u8, rm: u8) -> u32 {
        0x8A00_0000 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }

    #[inline]
    fn orr_x(rd: u8, rn: u8, rm: u8) -> u32 {
        0xAA00_0000 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }

    #[inline]
    fn eor_x(rd: u8, rn: u8, rm: u8) -> u32 {
        0xCA00_0000 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }

    #[inline]
    fn lslv_x(rd: u8, rn: u8, rm: u8) -> u32 {
        0x9AC0_2000 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }

    #[inline]
    fn lsrv_x(rd: u8, rn: u8, rm: u8) -> u32 {
        0x9AC0_2400 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }

    #[inline]
    fn asrv_x(rd: u8, rn: u8, rm: u8) -> u32 {
        0x9AC0_2800 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }

    fn mov_imm64(&mut self, rd: u8, val: u64) {
        let lo = (val & 0xffff) as u32;
        self.emit(0xD280_0000 | (lo << 5) | rd as u32);
        for hw in 1..4u32 {
            let part = ((val >> (hw * 16)) & 0xffff) as u32;
            if part != 0 {
                self.emit(0xF280_0000 | (hw << 21) | (part << 5) | rd as u32);
            }
        }
    }

    fn finish(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.words.len() * 4);
        for w in self.words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }
}

pub struct Hart {
    pub regs: [u64; 32],
    pub fregs: [u64; 32],
    pub pc: u64,
    pub hart_id: usize,
    pub priv_mode: PrivMode,
    pub csrs: CsrFile,
    misa_ext: u64,
    reservation: Option<u64>,
    instret_pending: u64,
    last_access: Option<(AccessType, u64, u64)>,
    trace_instr: Option<u64>,
    trace_disas: bool,
    trace_pc: Option<u64>,
    trace_span: u64,
    trace_pc_left: Option<u64>,
    watch_pc: Option<u64>,
    watch_reg: Option<usize>,
    watch_left: u64,
    watch_pc2: Option<u64>,
    watch_reg2: Option<usize>,
    watch_left2: u64,
    watch_str: bool,
    hotpc_top: usize,
    hotpc_counts: HashMap<u64, u64>,
    trace_pc_zero: bool,
    trace_last: bool,
    trace_last_dumped: bool,
    last_instrs: Vec<(u64, u32, u8)>,
    trace_cjalr: bool,
    ignore_ebreak: bool,
    mmu_trace_addr: Option<u64>,
    mmu_trace_left: u64,
    mmu_idmap_fallback: bool,
    irq_check_stride: u32,
    irq_check_countdown: u32,
    time_divider: u32,
    time_div_accum: u32,
    time_jitter_enabled: bool,
    time_jitter_state: u64,
    satp_cached: u64,
    tlb: [Option<TlbEntry>; TLB_CACHE_SIZE],
    fast_tlb_fetch: Option<FastTlbEntry>,
    fast_tlb_load: Option<FastTlbEntry>,
    fast_tlb_store: Option<FastTlbEntry>,
    decode_jit_enabled: bool,
    native_jit_trace: bool,
    native_jit_probe_printed: bool,
    native_jit: NativeJit,
    decode_cache: [Option<DecodeCacheEntry>; DECODE_CACHE_SIZE],
}

#[derive(Clone, Debug)]
pub struct HartSnapshot {
    pub regs: [u64; 32],
    pub fregs: [u64; 32],
    pub pc: u64,
    pub hart_id: usize,
    pub priv_mode: PrivMode,
    pub csrs: CsrSnapshot,
    pub misa_ext: u64,
    pub reservation: Option<u64>,
    pub instret_pending: u64,
    pub last_access: Option<(AccessType, u64, u64)>,
    pub trace_instr: Option<u64>,
    pub trace_pc_left: Option<u64>,
    pub watch_left: u64,
    pub watch_left2: u64,
    pub mmu_trace_left: u64,
    pub time_div_accum: u32,
    pub time_jitter_state: u64,
}

impl Hart {
    pub fn new(hart_id: usize, misa_ext: u64) -> Self {
        fn parse_env_u64(name: &str) -> Option<u64> {
            std::env::var(name).ok().and_then(|v| {
                if let Some(hex) = v.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    v.parse::<u64>().ok()
                }
            })
        }
        fn parse_env_reg(name: &str) -> Option<usize> {
            std::env::var(name).ok().and_then(|v| {
                let vv = v.trim();
                let n = vv.strip_prefix('x').unwrap_or(vv);
                n.parse::<usize>().ok().filter(|r| *r < 32)
            })
        }
        fn parse_env_bool(name: &str, default: bool) -> bool {
            match std::env::var(name) {
                Ok(v) => match v.trim().to_ascii_lowercase().as_str() {
                    "1" | "true" | "yes" | "on" => true,
                    "0" | "false" | "no" | "off" => false,
                    _ => default,
                },
                Err(_) => default,
            }
        }

        let trace_pc = std::env::var("TRACE_PC").ok().and_then(|v| {
            if let Some(hex) = v.strip_prefix("0x") {
                u64::from_str_radix(hex, 16).ok()
            } else {
                v.parse::<u64>().ok()
            }
        });
        let trace_span = std::env::var("TRACE_SPAN")
            .ok()
            .and_then(|v| {
                if let Some(hex) = v.strip_prefix("0x") {
                    u64::from_str_radix(hex, 16).ok()
                } else {
                    v.parse::<u64>().ok()
                }
            })
            .unwrap_or(0x200);
        let trace_pc_left = parse_env_u64("TRACE_PC_LIMIT");
        let watch_pc = parse_env_u64("WATCH_PC");
        let watch_reg = parse_env_reg("WATCH_REG");
        let watch_left = if watch_pc.is_some() {
            parse_env_u64("WATCH_COUNT").unwrap_or(200)
        } else {
            0
        };
        let watch_pc2 = parse_env_u64("WATCH_PC2");
        let watch_reg2 = parse_env_reg("WATCH_REG2");
        let watch_left2 = if watch_pc2.is_some() {
            parse_env_u64("WATCH_COUNT2")
                .or_else(|| parse_env_u64("WATCH_COUNT"))
                .unwrap_or(200)
        } else {
            0
        };
        let watch_str = std::env::var("WATCH_STR").is_ok();
        let hotpc_top = parse_env_u64("TRACE_HOTPC_TOP").unwrap_or(0) as usize;
        let trace_pc_zero = std::env::var("TRACE_PC_ZERO").is_ok();
        let trace_last = std::env::var("TRACE_LAST").is_ok();
        let trace_cjalr = std::env::var("TRACE_CJALR").is_ok();
        let ignore_ebreak = std::env::var("IGNORE_EBREAK").is_ok();
        let mmu_trace_addr = parse_env_u64("TRACE_MMU_ADDR");
        let mmu_trace_left = if mmu_trace_addr.is_some() {
            parse_env_u64("TRACE_MMU_COUNT").unwrap_or(16)
        } else {
            0
        };
        let mmu_idmap_fallback = std::env::var("MMU_IDMAP_FALLBACK").is_ok();
        let time_divider = parse_env_u64("KOR_TIME_DIVIDER")
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(4)
            .max(1);
        let time_jitter_enabled = parse_env_bool("KOR_TIME_JITTER", false);
        let decode_jit_enabled = parse_env_bool("KOR_JIT_DECODE", true);
        let native_jit_enabled = parse_env_bool("KOR_JIT_NATIVE", false);
        let native_jit_trace = parse_env_bool("KOR_JIT_NATIVE_TRACE", false);
        let native_jit_code_size = parse_env_u64("KOR_JIT_NATIVE_CODE_SIZE")
            .and_then(|v| usize::try_from(v).ok())
            .unwrap_or(32 * 1024 * 1024);
        let mut time_jitter_state = 0x9E37_79B9_7F4A_7C15u64 ^ ((hart_id as u64) << 32);
        if time_jitter_state == 0 {
            time_jitter_state = 1;
        }
        let irq_check_stride = parse_env_u64("KOR_HART_IRQ_CHECK_STRIDE")
            .and_then(|v| u32::try_from(v).ok())
            .unwrap_or(1024)
            .max(1);
        let native_jit = NativeJit::new(native_jit_enabled, native_jit_code_size);
        if native_jit_trace {
            eprintln!(
                "jit-a64: hart={} enabled={} code_size={} decode_cache={}",
                hart_id, native_jit.enabled, native_jit_code_size, decode_jit_enabled
            );
        }
        Self {
            regs: [0; 32],
            fregs: [0; 32],
            pc: 0,
            hart_id,
            priv_mode: PrivMode::Supervisor,
            csrs: CsrFile::new(hart_id, misa_ext),
            misa_ext,
            reservation: None,
            instret_pending: 0,
            last_access: None,
            trace_instr: None,
            trace_disas: std::env::var("TRACE_DISAS").is_ok(),
            trace_pc,
            trace_span,
            trace_pc_left,
            watch_pc,
            watch_reg,
            watch_left,
            watch_pc2,
            watch_reg2,
            watch_left2,
            watch_str,
            hotpc_top,
            hotpc_counts: HashMap::new(),
            trace_pc_zero,
            trace_last,
            trace_last_dumped: false,
            last_instrs: Vec::new(),
            trace_cjalr,
            ignore_ebreak,
            mmu_trace_addr,
            mmu_trace_left,
            mmu_idmap_fallback,
            irq_check_stride,
            irq_check_countdown: irq_check_stride,
            time_divider,
            time_div_accum: 0,
            time_jitter_enabled,
            time_jitter_state,
            satp_cached: 0,
            tlb: [None; TLB_CACHE_SIZE],
            fast_tlb_fetch: None,
            fast_tlb_load: None,
            fast_tlb_store: None,
            decode_jit_enabled,
            native_jit_trace,
            native_jit_probe_printed: false,
            native_jit,
            decode_cache: [None; DECODE_CACHE_SIZE],
        }
    }

    #[inline]
    fn watch_hit_slot(watch_pc: Option<u64>, watch_left: &mut u64, pc: u64) -> bool {
        if *watch_left == 0 {
            return false;
        }
        if watch_pc == Some(pc) {
            *watch_left -= 1;
            return true;
        }
        false
    }

    #[inline]
    fn watch_hit(&mut self, pc: u64) -> bool {
        Self::watch_hit_slot(self.watch_pc, &mut self.watch_left, pc)
    }

    #[inline]
    fn watch_hit2(&mut self, pc: u64) -> bool {
        Self::watch_hit_slot(self.watch_pc2, &mut self.watch_left2, pc)
    }

    #[inline]
    fn watch_field(reg: Option<usize>, before: Option<u64>, after: Option<u64>) -> String {
        if let Some(r) = reg {
            format!(
                " x{}:0x{:016x}->0x{:016x}",
                r,
                before.unwrap_or(0),
                after.unwrap_or(0)
            )
        } else {
            String::new()
        }
    }

    fn read_guest_cstr(&mut self, bus: &mut impl Bus, addr: u64, max_len: usize) -> Option<String> {
        if addr == 0 {
            return None;
        }
        let mut bytes = Vec::new();
        for i in 0..max_len {
            let b = self
                .read_u8(bus, addr.wrapping_add(i as u64), AccessType::Debug)
                .ok()?;
            if b == 0 {
                break;
            }
            bytes.push(if (0x20..=0x7e).contains(&b) { b } else { b'.' });
        }
        if bytes.is_empty() {
            return Some(String::new());
        }
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn watch_cstr_field(
        &mut self,
        bus: &mut impl Bus,
        reg: Option<usize>,
        ptr: Option<u64>,
    ) -> String {
        if !self.watch_str {
            return String::new();
        }
        let (Some(r), Some(addr)) = (reg, ptr) else {
            return String::new();
        };
        if let Some(s) = self.read_guest_cstr(bus, addr, 96) {
            if s.is_empty() {
                String::new()
            } else {
                format!(" x{}@0x{:016x}=\"{}\"", r, addr, s.escape_default())
            }
        } else {
            String::new()
        }
    }

    #[inline]
    fn flush_tlb(&mut self) {
        self.tlb.fill(None);
        self.fast_tlb_fetch = None;
        self.fast_tlb_load = None;
        self.fast_tlb_store = None;
        self.native_jit.clear();
    }

    #[inline]
    fn flush_decode_cache(&mut self) {
        self.decode_cache.fill(None);
    }

    #[inline]
    fn tlb_index(satp: u64, vpage: u64) -> usize {
        let mixed = vpage
            ^ satp
            ^ satp.rotate_right(17)
            ^ vpage.rotate_left(13)
            ^ (vpage >> 7);
        (mixed as usize) & (TLB_CACHE_SIZE - 1)
    }

    #[inline]
    fn decode_cache_index(satp: u64, pc: u64) -> usize {
        let _ = satp;
        ((pc >> 2) as usize) & (DECODE_CACHE_SIZE - 1)
    }

    #[inline]
    fn tlb_allow(kind: AccessType, perms: u8) -> bool {
        match kind {
            AccessType::Fetch => (perms & TLB_PERM_X) != 0,
            AccessType::Load => (perms & TLB_PERM_R) != 0,
            AccessType::Store => (perms & TLB_PERM_W) != 0,
            AccessType::Debug => true,
        }
    }

    #[inline]
    fn tlb_lookup(&self, kind: AccessType, satp: u64, vpage: u64) -> Option<u64> {
        if matches!(kind, AccessType::Debug) {
            return None;
        }
        let idx = Self::tlb_index(satp, vpage);
        let entry = self.tlb[idx]?;
        if entry.vpage == vpage && Self::tlb_allow(kind, entry.perms) {
            Some(entry.ppage)
        } else {
            None
        }
    }

    #[inline]
    fn fast_tlb_lookup(&self, kind: AccessType, satp: u64, vpage: u64) -> Option<u64> {
        let slot = match kind {
            AccessType::Fetch => self.fast_tlb_fetch,
            AccessType::Load => self.fast_tlb_load,
            AccessType::Store => self.fast_tlb_store,
            AccessType::Debug => None,
        }?;
        if slot.satp == satp && slot.vpage == vpage {
            Some(slot.ppage)
        } else {
            None
        }
    }

    #[inline]
    fn fast_tlb_insert(&mut self, kind: AccessType, satp: u64, vpage: u64, ppage: u64) {
        let entry = Some(FastTlbEntry { satp, vpage, ppage });
        match kind {
            AccessType::Fetch => self.fast_tlb_fetch = entry,
            AccessType::Load => self.fast_tlb_load = entry,
            AccessType::Store => self.fast_tlb_store = entry,
            AccessType::Debug => {}
        }
    }

    #[inline]
    fn tlb_insert(&mut self, satp: u64, vpage: u64, ppage: u64, perms: u8) {
        if perms == 0 {
            return;
        }
        let idx = Self::tlb_index(satp, vpage);
        self.tlb[idx] = Some(TlbEntry { vpage, ppage, perms });
    }

    #[inline]
    fn decode32_cached(&mut self, pc: u64, instr: u32) -> Decoded32 {
        if !self.decode_jit_enabled {
            return Self::decode32(instr);
        }
        let satp = self.satp_cached;
        let idx = Self::decode_cache_index(satp, pc);
        if let Some(entry) = self.decode_cache[idx] {
            if entry.satp == satp && entry.pc == pc && entry.instr == instr {
                return entry.decoded;
            }
        }
        let decoded = Self::decode32(instr);
        self.decode_cache[idx] = Some(DecodeCacheEntry {
            satp,
            pc,
            instr,
            decoded,
        });
        decoded
    }

    #[inline]
    fn reg_off(reg: usize) -> u16 {
        (reg as u16) * 8
    }

    #[cfg(target_arch = "aarch64")]
    fn emit_native_instr(&self, em: &mut A64Emitter, pc: u64, instr: u32, d: Decoded32) -> bool {
        let rd = d.rd as usize;
        let rs1 = d.rs1 as usize;
        let rs2 = d.rs2 as usize;
        let funct3 = d.funct3 as u32;
        let funct7 = d.funct7 as u32;
        let imm12 = d.imm12 as u32;
        let imm_hi = (imm12 >> 6) & 0x3f;

        let store_rd = |em: &mut A64Emitter, rd: usize| {
            if rd != 0 {
                em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
            }
        };

        match d.opcode as u32 {
            OPCODE_LUI => {
                if rd != 0 {
                    em.mov_imm64(11, Self::imm_u(instr) as u64);
                    em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
                }
                true
            }
            OPCODE_AUIPC => {
                if rd != 0 {
                    em.mov_imm64(11, pc.wrapping_add(Self::imm_u(instr) as u64));
                    em.emit(A64Emitter::str_x(11, 0, Self::reg_off(rd)));
                }
                true
            }
            OPCODE_OP_IMM => {
                em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1)));
                match funct3 {
                    F3_ADD_SUB => {
                        em.mov_imm64(10, Self::imm_i(instr) as u64);
                        em.emit(A64Emitter::add_x(11, 9, 10));
                    }
                    F3_XOR => {
                        em.mov_imm64(10, Self::imm_i(instr) as u64);
                        em.emit(A64Emitter::eor_x(11, 9, 10));
                    }
                    F3_OR => {
                        em.mov_imm64(10, Self::imm_i(instr) as u64);
                        em.emit(A64Emitter::orr_x(11, 9, 10));
                    }
                    F3_AND => {
                        em.mov_imm64(10, Self::imm_i(instr) as u64);
                        em.emit(A64Emitter::and_x(11, 9, 10));
                    }
                    F3_SLL => {
                        if imm_hi != 0 {
                            return false;
                        }
                        em.mov_imm64(10, (imm12 & 0x3f) as u64);
                        em.emit(A64Emitter::lslv_x(11, 9, 10));
                    }
                    F3_SRL_SRA => {
                        em.mov_imm64(10, (imm12 & 0x3f) as u64);
                        match imm_hi {
                            0x00 => em.emit(A64Emitter::lsrv_x(11, 9, 10)),
                            0x10 => em.emit(A64Emitter::asrv_x(11, 9, 10)),
                            _ => return false,
                        }
                    }
                    _ => return false,
                }
                store_rd(em, rd);
                true
            }
            OPCODE_OP => {
                em.emit(A64Emitter::ldr_x(9, 0, Self::reg_off(rs1)));
                em.emit(A64Emitter::ldr_x(10, 0, Self::reg_off(rs2)));
                match (funct7, funct3) {
                    (F7_BASE, F3_ADD_SUB) => em.emit(A64Emitter::add_x(11, 9, 10)),
                    (F7_SUB_SRA, F3_ADD_SUB) => em.emit(A64Emitter::sub_x(11, 9, 10)),
                    (F7_BASE, F3_AND) => em.emit(A64Emitter::and_x(11, 9, 10)),
                    (F7_BASE, F3_OR) => em.emit(A64Emitter::orr_x(11, 9, 10)),
                    (F7_BASE, F3_XOR) => em.emit(A64Emitter::eor_x(11, 9, 10)),
                    (F7_BASE, F3_SLL) => em.emit(A64Emitter::lslv_x(11, 9, 10)),
                    (F7_BASE, F3_SRL_SRA) => em.emit(A64Emitter::lsrv_x(11, 9, 10)),
                    (F7_SUB_SRA, F3_SRL_SRA) => em.emit(A64Emitter::asrv_x(11, 9, 10)),
                    _ => return false,
                }
                store_rd(em, rd);
                true
            }
            _ => false,
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn emit_native_instr(&self, _em: &mut (), _pc: u64, _instr: u32, _d: Decoded32) -> bool {
        false
    }

    #[cfg(target_arch = "aarch64")]
    fn compile_native_block(
        &mut self,
        bus: &mut impl Bus,
        max_steps: u32,
    ) -> Result<Option<NativeBlock>, Trap> {
        if !self.native_jit.enabled {
            return Ok(None);
        }
        if self.native_jit_trace {
            eprintln!(
                "jit-a64: compile-enter pc=0x{:016x} max_steps={}",
                self.pc, max_steps
            );
        }
        let max_steps = max_steps.min(64);
        if max_steps < 1 {
            return Ok(None);
        }
        let satp = self.satp_cached;
        let start_pc = self.pc;
        let mut pc = start_pc;
        let mut emitted = 0u32;
        let mut em = A64Emitter::new();

        while emitted < max_steps {
            if (pc & 0x3) != 0 {
                if emitted == 0 {
                    self.check_align(pc, 4)?;
                }
                break;
            }
            let instr = match self.read_u32(bus, pc, AccessType::Fetch) {
                Ok(v) => v,
                Err(t) => {
                    if emitted == 0 {
                        if self.native_jit_trace {
                            eprintln!(
                                "jit-a64: skip pc=0x{:016x} fetch-trap={:?}",
                                pc, t
                            );
                        }
                        return Err(t);
                    }
                    break;
                }
            };
            if (instr & 0x3) != 0x3 {
                if emitted == 0 && self.native_jit_trace {
                    eprintln!(
                        "jit-a64: skip pc=0x{:016x} compressed instr16=0x{:04x}",
                        pc,
                        (instr & 0xffff) as u16
                    );
                }
                break;
            }
            let d = Self::decode32(instr);
            if !self.emit_native_instr(&mut em, pc, instr, d) {
                if emitted == 0 && self.native_jit_trace {
                    eprintln!(
                        "jit-a64: skip pc=0x{:016x} unsupported i32=0x{:08x}",
                        pc, instr
                    );
                }
                break;
            }
            pc = pc.wrapping_add(4);
            emitted += 1;
        }

        if emitted < 1 {
            return Ok(None);
        }

        em.mov_imm64(0, pc);
        em.mov_imm64(1, emitted as u64);
        em.emit(0xD65F_03C0); // ret
        let code = em.finish();

        let Some(cache) = self.native_jit.cache.as_mut() else {
            if self.native_jit_trace {
                eprintln!("jit-a64: disable (missing executable cache)");
            }
            self.native_jit.enabled = false;
            return Ok(None);
        };
        let Some(offset) = cache.alloc(&code) else {
            if self.native_jit_trace {
                eprintln!(
                    "jit-a64: disable (code cache full/alloc failed, used={} size={} block_bytes={})",
                    cache.used,
                    cache.size,
                    code.len()
                );
            }
            self.native_jit.enabled = false;
            return Ok(None);
        };
        let block = NativeBlock {
            offset,
            instrs: emitted,
        };
        self.native_jit.insert(satp, start_pc, block);
        if self.native_jit_trace {
            eprintln!(
                "jit-a64: compiled hart={} satp=0x{:016x} pc=0x{:016x} instrs={}",
                self.hart_id, satp, start_pc, emitted
            );
        }
        Ok(Some(block))
    }

    #[cfg(not(target_arch = "aarch64"))]
    fn compile_native_block(
        &mut self,
        _bus: &mut impl Bus,
        _max_steps: u32,
    ) -> Result<Option<NativeBlock>, Trap> {
        Ok(None)
    }

    pub fn try_run_native_jit(
        &mut self,
        bus: &mut impl Bus,
        max_steps: u32,
    ) -> Result<Option<u32>, Trap> {
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _ = (bus, max_steps);
            return Ok(None);
        }
        #[cfg(target_arch = "aarch64")]
        {
            if self.native_jit_trace && !self.native_jit_probe_printed {
                self.native_jit_probe_printed = true;
                eprintln!(
                    "jit-a64: probe pc=0x{:016x} max_steps={} irq_cd={} debug_hooks={} jitter={} enabled={}",
                    self.pc,
                    max_steps,
                    self.irq_check_countdown,
                    self.has_debug_hooks(),
                    self.time_jitter_enabled,
                    self.native_jit.enabled
                );
            }
            if !self.native_jit.enabled || max_steps < 2 || self.has_debug_hooks() {
                return Ok(None);
            }
            if self.time_jitter_enabled {
                return Ok(None);
            }
            if (self.pc & 0x3) != 0 {
                return Ok(None);
            }
            if self.irq_check_countdown <= 1 {
                return Ok(None);
            }
            let budget = max_steps.min(self.irq_check_countdown.saturating_sub(1));
            if budget < 1 {
                return Ok(None);
            }

            let satp = self.satp_cached;
            let start_pc = self.pc;
            let mut block = self.native_jit.lookup(satp, start_pc);
            if block.is_none() {
                block = self.compile_native_block(bus, budget)?;
            }
            let Some(block) = block else {
                return Ok(None);
            };
            if block.instrs < 1 || block.instrs > budget {
                return Ok(None);
            }

            let Some(cache) = self.native_jit.cache.as_ref() else {
                self.native_jit.enabled = false;
                return Ok(None);
            };
            let fn_ptr = cache.ptr_at(block.offset);
            let func: NativeBlockFn = unsafe { std::mem::transmute(fn_ptr) };
            let res = unsafe { func(self.regs.as_mut_ptr()) };
            if res.executed != block.instrs as u64 || res.executed == 0 {
                return Ok(None);
            }

            let done = res.executed as u32;
            self.pc = res.next_pc;
            self.regs[0] = 0;
            self.instret_pending = self.instret_pending.wrapping_add(done as u64);

            let total = self.time_div_accum.saturating_add(done);
            if total >= self.time_divider {
                let ticks = total / self.time_divider;
                self.time_div_accum = total % self.time_divider;
                self.csrs.increment_time(ticks as u64);
            } else {
                self.time_div_accum = total;
            }
            self.irq_check_countdown = self.irq_check_countdown.saturating_sub(done);
            Ok(Some(done))
        }
    }

    #[inline]
    pub fn native_jit_enabled(&self) -> bool {
        self.native_jit.enabled
    }

    pub fn reset(&mut self, pc: u64, sp: u64, gp: u64) {
        self.regs = [0; 32];
        self.fregs = [0; 32];
        self.pc = pc;
        self.reservation = None;
        self.instret_pending = 0;
        self.priv_mode = PrivMode::Supervisor;
        self.csrs.reset(self.hart_id, self.misa_ext);
        self.last_access = None;
        self.hotpc_counts.clear();
        self.flush_tlb();
        self.flush_decode_cache();
        self.irq_check_countdown = self.irq_check_stride;
        self.time_div_accum = 0;
        self.satp_cached = self.csrs.read(CSR_SATP);
        self.regs[2] = sp;
        self.regs[3] = gp;
        self.regs[4] = 0;
    }

    pub fn snapshot(&self) -> HartSnapshot {
        HartSnapshot {
            regs: self.regs,
            fregs: self.fregs,
            pc: self.pc,
            hart_id: self.hart_id,
            priv_mode: self.priv_mode,
            csrs: self.csrs.snapshot(),
            misa_ext: self.misa_ext,
            reservation: self.reservation,
            instret_pending: self.instret_pending,
            last_access: self.last_access,
            trace_instr: self.trace_instr,
            trace_pc_left: self.trace_pc_left,
            watch_left: self.watch_left,
            watch_left2: self.watch_left2,
            mmu_trace_left: self.mmu_trace_left,
            time_div_accum: self.time_div_accum,
            time_jitter_state: self.time_jitter_state,
        }
    }

    pub fn from_snapshot(snap: &HartSnapshot) -> Result<Self, &'static str> {
        let mut hart = Self::new(snap.hart_id, snap.misa_ext);
        hart.restore_from_snapshot(snap)?;
        Ok(hart)
    }

    pub fn restore_from_snapshot(&mut self, snap: &HartSnapshot) -> Result<(), &'static str> {
        self.regs = snap.regs;
        self.fregs = snap.fregs;
        self.pc = snap.pc;
        self.hart_id = snap.hart_id;
        self.priv_mode = snap.priv_mode;
        self.csrs.restore(&snap.csrs)?;
        self.misa_ext = snap.misa_ext;
        self.reservation = snap.reservation;
        self.instret_pending = snap.instret_pending;
        self.last_access = snap.last_access;
        self.trace_instr = snap.trace_instr;
        self.trace_pc_left = snap.trace_pc_left;
        self.watch_left = snap.watch_left;
        self.watch_left2 = snap.watch_left2;
        self.mmu_trace_left = snap.mmu_trace_left;
        self.time_div_accum = snap.time_div_accum % self.time_divider;
        self.time_jitter_state = if snap.time_jitter_state == 0 {
            1
        } else {
            snap.time_jitter_state
        };
        self.hotpc_counts.clear();
        self.last_instrs.clear();
        self.trace_last_dumped = false;
        self.flush_tlb();
        self.flush_decode_cache();
        self.irq_check_countdown = self.irq_check_stride;
        self.satp_cached = self.csrs.read(CSR_SATP);
        Ok(())
    }

    pub fn set_satp(&mut self, val: u64) {
        self.csrs.write(CSR_SATP, val);
        self.satp_cached = self.csrs.read(CSR_SATP);
        self.flush_tlb();
    }

    #[inline]
    fn commit_instret(&mut self) {
        if self.instret_pending != 0 {
            self.csrs.increment_instret_n(self.instret_pending);
            self.instret_pending = 0;
        }
    }

    pub fn dump_hotpcs(&self) {
        if self.hotpc_top == 0 || self.hotpc_counts.is_empty() {
            return;
        }
        let mut entries: Vec<(u64, u64)> = self
            .hotpc_counts
            .iter()
            .map(|(pc, count)| (*pc, *count))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        let top = self.hotpc_top.min(entries.len());
        println!("hotpc hart {} top {}:", self.hart_id, top);
        for (pc, count) in entries.into_iter().take(top) {
            println!("  pc=0x{:016x} count={}", pc, count);
        }
    }

    pub fn set_trace_instr(&mut self, limit: Option<u64>) {
        self.trace_instr = limit;
    }

    pub fn last_access(&self) -> Option<(AccessType, u64, u64)> {
        self.last_access
    }

    #[allow(dead_code)]
    pub fn recent_instrs(&self) -> &[(u64, u32, u8)] {
        &self.last_instrs
    }

    fn record_instr(&mut self, pc: u64, instr: u32, len: u8) {
        if !self.trace_last {
            return;
        }
        const MAX: usize = 64;
        if self.last_instrs.len() >= MAX {
            self.last_instrs.remove(0);
        }
        self.last_instrs.push((pc, instr, len));
    }

    #[inline]
    fn check_align(&self, addr: u64, align: u64) -> Result<(), Trap> {
        if addr & (align - 1) != 0 {
            return Err(Trap::MisalignedAccess { addr, size: align });
        }
        Ok(())
    }

    #[inline]
    fn next_time_delta(&mut self) -> u64 {
        if !self.time_jitter_enabled {
            return 1;
        }
        // Deterministic xorshift64 stream used to introduce tiny timing jitter.
        let mut x = self.time_jitter_state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        if x == 0 {
            x = 1;
        }
        self.time_jitter_state = x;
        match x & 0x7 {
            0 => 2,
            1 => 0,
            _ => 1,
        }
    }

    fn read_phys_u64(&mut self, bus: &mut impl Bus, addr: u64) -> Result<u64, Trap> {
        bus.read_u64(self.hart_id, addr, AccessType::Debug)
    }

    fn write_phys_u64(&mut self, bus: &mut impl Bus, addr: u64, value: u64) -> Result<(), Trap> {
        bus.write_u64(self.hart_id, addr, value, AccessType::Debug)
    }

    #[allow(dead_code)]
    pub fn debug_read_u16_virt(&mut self, bus: &mut impl Bus, addr: u64) -> Result<u16, Trap> {
        self.read_u16(bus, addr, AccessType::Debug)
    }

    #[allow(dead_code)]
    pub fn debug_read_u32_virt(&mut self, bus: &mut impl Bus, addr: u64) -> Result<u32, Trap> {
        self.read_u32(bus, addr, AccessType::Debug)
    }

    fn translate_addr(
        &mut self,
        bus: &mut impl Bus,
        vaddr: u64,
        kind: AccessType,
    ) -> Result<u64, Trap> {
        let mmu_trace = if self.mmu_trace_left > 0 && self.mmu_trace_addr == Some(vaddr) {
            self.mmu_trace_left -= 1;
            true
        } else {
            false
        };
        if mmu_trace {
            eprintln!(
                "mmu: vaddr=0x{:016x} kind={:?} priv={:?} satp=0x{:016x}",
                vaddr,
                kind,
                self.priv_mode,
                self.satp_cached
            );
        }
        if self.priv_mode == PrivMode::Machine {
            if mmu_trace {
                eprintln!("  bypass machine mode -> phys=0x{:016x}", vaddr);
            }
            return Ok(vaddr);
        }

        let satp = self.satp_cached;
        let mode = satp >> 60;
        let vpage = vaddr >> 12;
        let page_offset = vaddr & 0xfff;
        let idmap_fallback =
            self.mmu_idmap_fallback && (0x8000_0000..0x1_0000_0000).contains(&vaddr);
        if mode == 0 {
            if mmu_trace {
                eprintln!("  bare mode -> phys=0x{:016x}", vaddr);
            }
            return Ok(vaddr);
        }

        // Sv39
        if mode != 8 {
            if mmu_trace {
                eprintln!("  unsupported satp mode {}", mode);
            }
            return Err(Trap::PageFault { addr: vaddr, kind });
        }

        if !mmu_trace {
            if let Some(ppage) = self.fast_tlb_lookup(kind, satp, vpage) {
                return Ok((ppage << 12) | page_offset);
            }
            if let Some(ppage) = self.tlb_lookup(kind, satp, vpage) {
                self.fast_tlb_insert(kind, satp, vpage, ppage);
                return Ok((ppage << 12) | page_offset);
            }
        }

        let sign = (vaddr >> 38) & 1;
        let upper = vaddr >> 39;
        if (sign == 0 && upper != 0) || (sign == 1 && upper != ((1u64 << 25) - 1)) {
            if mmu_trace {
                eprintln!("  non-canonical address");
            }
            return Err(Trap::PageFault { addr: vaddr, kind });
        }

        let vpn = [
            (vaddr >> 12) & 0x1ff,
            (vaddr >> 21) & 0x1ff,
            (vaddr >> 30) & 0x1ff,
        ];
        let mut a = (satp & ((1u64 << 44) - 1)) << 12;

        for level in (0..=2).rev() {
            let pte_addr = a + vpn[level] * 8;
            let pte = match self.read_phys_u64(bus, pte_addr) {
                Ok(v) => v,
                Err(_) => {
                    if mmu_trace {
                        eprintln!("  l{} pte@0x{:016x} read failed", level, pte_addr);
                    }
                    if idmap_fallback {
                        if mmu_trace {
                            eprintln!("  fallback idmap -> phys=0x{:016x}", vaddr);
                        }
                        return Ok(vaddr);
                    }
                    return Err(Trap::PageFault { addr: vaddr, kind });
                }
            };
            let v = (pte & 0x1) != 0;
            let r = (pte & 0x2) != 0;
            let w = (pte & 0x4) != 0;
            let x = (pte & 0x8) != 0;
            if mmu_trace {
                eprintln!(
                    "  l{} pte@0x{:016x}=0x{:016x} v={} r={} w={} x={}",
                    level, pte_addr, pte, v, r, w, x
                );
            }

            if !v || (!r && w) {
                if mmu_trace {
                    eprintln!("  invalid leaf/non-leaf encoding");
                }
                if idmap_fallback {
                    if mmu_trace {
                        eprintln!("  fallback idmap -> phys=0x{:016x}", vaddr);
                    }
                    return Ok(vaddr);
                }
                return Err(Trap::PageFault { addr: vaddr, kind });
            }

            if r || x {
                // Leaf PTE.
                let allow = match kind {
                    AccessType::Fetch => x,
                    AccessType::Load => r,
                    AccessType::Store => w,
                    AccessType::Debug => true,
                };
                if !allow {
                    if mmu_trace {
                        eprintln!("  permission denied");
                    }
                    return Err(Trap::PageFault { addr: vaddr, kind });
                }

                // Set A/D bits on access.
                let mut new_pte = pte;
                if (pte & (1 << 6)) == 0 {
                    new_pte |= 1 << 6;
                }
                if kind == AccessType::Store && (pte & (1 << 7)) == 0 {
                    new_pte |= 1 << 7;
                }
                if new_pte != pte {
                    let _ = self.write_phys_u64(bus, pte_addr, new_pte);
                }

                let ppn = pte >> 10;
                let phys = match level {
                    2 => {
                        // 1 GiB superpage: ppn1/ppn0 must be zero.
                        if (ppn & ((1u64 << 18) - 1)) != 0 {
                            if mmu_trace {
                                eprintln!("  bad 1GiB superpage alignment");
                            }
                            return Err(Trap::PageFault { addr: vaddr, kind });
                        }
                        (ppn >> 18) << 30 | (vpn[1] << 21) | (vpn[0] << 12) | page_offset
                    }
                    1 => {
                        // 2 MiB superpage: ppn0 must be zero.
                        if (ppn & ((1u64 << 9) - 1)) != 0 {
                            if mmu_trace {
                                eprintln!("  bad 2MiB superpage alignment");
                            }
                            return Err(Trap::PageFault { addr: vaddr, kind });
                        }
                        (ppn >> 9) << 21 | (vpn[0] << 12) | page_offset
                    }
                    _ => (ppn << 12) | page_offset,
                };
                if mmu_trace {
                    eprintln!("  -> phys=0x{:016x}", phys);
                }
                if !mmu_trace {
                    let mut perms = 0u8;
                    if r {
                        perms |= TLB_PERM_R;
                    }
                    if w {
                        perms |= TLB_PERM_W;
                    }
                    if x {
                        perms |= TLB_PERM_X;
                    }
                    self.tlb_insert(satp, vpage, phys >> 12, perms);
                    self.fast_tlb_insert(kind, satp, vpage, phys >> 12);
                }
                return Ok(phys);
            }

            a = (pte >> 10) << 12;
        }

        if mmu_trace {
            eprintln!("  walk ended without leaf");
        }
        if idmap_fallback {
            if mmu_trace {
                eprintln!("  fallback idmap -> phys=0x{:016x}", vaddr);
            }
            return Ok(vaddr);
        }
        Err(Trap::PageFault { addr: vaddr, kind })
    }

    #[inline]
    fn read_u8(&mut self, bus: &mut impl Bus, addr: u64, kind: AccessType) -> Result<u8, Trap> {
        self.last_access = Some((kind, addr, 1));
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.read_u8(self.hart_id, paddr, kind)
    }

    #[inline]
    fn read_u16(&mut self, bus: &mut impl Bus, addr: u64, kind: AccessType) -> Result<u16, Trap> {
        self.last_access = Some((kind, addr, 2));
        self.check_align(addr, 2)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.read_u16(self.hart_id, paddr, kind)
    }

    #[inline]
    fn read_u32(&mut self, bus: &mut impl Bus, addr: u64, kind: AccessType) -> Result<u32, Trap> {
        self.last_access = Some((kind, addr, 4));
        self.check_align(addr, 4)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.read_u32(self.hart_id, paddr, kind)
    }

    #[inline]
    #[allow(dead_code)]
    fn read_u64(&mut self, bus: &mut impl Bus, addr: u64, kind: AccessType) -> Result<u64, Trap> {
        self.last_access = Some((kind, addr, 8));
        self.check_align(addr, 8)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.read_u64(self.hart_id, paddr, kind)
    }

    #[inline]
    fn write_u8(
        &mut self,
        bus: &mut impl Bus,
        addr: u64,
        val: u8,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.last_access = Some((kind, addr, 1));
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.write_u8(self.hart_id, paddr, val, kind)
    }

    #[inline]
    fn write_u16(
        &mut self,
        bus: &mut impl Bus,
        addr: u64,
        val: u16,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.last_access = Some((kind, addr, 2));
        self.check_align(addr, 2)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.write_u16(self.hart_id, paddr, val, kind)
    }

    #[inline]
    fn write_u32(
        &mut self,
        bus: &mut impl Bus,
        addr: u64,
        val: u32,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.last_access = Some((kind, addr, 4));
        self.check_align(addr, 4)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.write_u32(self.hart_id, paddr, val, kind)
    }

    #[inline]
    #[allow(dead_code)]
    fn write_u64(
        &mut self,
        bus: &mut impl Bus,
        addr: u64,
        val: u64,
        kind: AccessType,
    ) -> Result<(), Trap> {
        self.last_access = Some((kind, addr, 8));
        self.check_align(addr, 8)?;
        let paddr = self.translate_addr(bus, addr, kind)?;
        bus.write_u64(self.hart_id, paddr, val, kind)
    }

    #[inline]
    fn sign_extend(val: u64, bits: u32) -> i64 {
        let shift = 64 - bits;
        ((val << shift) as i64) >> shift
    }

    #[inline]
    fn imm_i(instr: u32) -> i64 {
        Self::sign_extend((instr >> 20) as u64, 12)
    }

    #[inline]
    fn imm_s(instr: u32) -> i64 {
        let imm = ((instr >> 25) << 5) | ((instr >> 7) & 0x1f);
        Self::sign_extend(imm as u64, 12)
    }

    #[inline]
    fn imm_b(instr: u32) -> i64 {
        let bit12 = (instr >> 31) & 0x1;
        let bit11 = (instr >> 7) & 0x1;
        let bits10_5 = (instr >> 25) & 0x3f;
        let bits4_1 = (instr >> 8) & 0x0f;
        let imm = (bit12 << 12) | (bit11 << 11) | (bits10_5 << 5) | (bits4_1 << 1);
        Self::sign_extend(imm as u64, 13)
    }

    #[inline]
    fn imm_u(instr: u32) -> i64 {
        Self::sign_extend((instr & 0xfffff000) as u64, 32)
    }

    #[inline]
    fn imm_j(instr: u32) -> i64 {
        let bit20 = (instr >> 31) & 0x1;
        let bits19_12 = (instr >> 12) & 0xff;
        let bit11 = (instr >> 20) & 0x1;
        let bits10_1 = (instr >> 21) & 0x3ff;
        let imm = (bit20 << 20) | (bits19_12 << 12) | (bit11 << 11) | (bits10_1 << 1);
        Self::sign_extend(imm as u64, 21)
    }

    #[inline]
    fn decode32(instr: u32) -> Decoded32 {
        let rd = ((instr >> 7) & 0x1f) as u8;
        let funct3 = ((instr >> 12) & 0x7) as u8;
        let rs1 = ((instr >> 15) & 0x1f) as u8;
        let rs2 = ((instr >> 20) & 0x1f) as u8;
        let funct7 = ((instr >> 25) & 0x7f) as u8;
        let imm12 = (instr >> 20) & 0xfff;
        Decoded32 {
            opcode: (instr & 0x7f) as u8,
            rd,
            funct3,
            rs1,
            rs2,
            funct7,
            funct5: ((instr >> 27) & 0x1f) as u8,
            imm12: imm12 as u16,
            csr_addr: ((instr >> 20) & 0xfff) as u16,
        }
    }

    fn pending_interrupt(&self) -> Option<u64> {
        let sstatus = self.csrs.read(CSR_SSTATUS);
        if (sstatus & SSTATUS_SIE) == 0 {
            return None;
        }
        let sie = self.csrs.read(CSR_SIE);
        let sip = self.csrs.read(CSR_SIP);
        let pending = sip & sie & (SIP_SSIP | SIP_STIP | SIP_SEIP);
        if (pending & SIP_SSIP) != 0 {
            return Some(1);
        }
        if (pending & SIP_STIP) != 0 {
            return Some(5);
        }
        if (pending & SIP_SEIP) != 0 {
            return Some(9);
        }
        None
    }

    fn take_trap(&mut self, cause: u64, tval: u64) {
        let stvec = self.csrs.read(CSR_STVEC);
        let mode = stvec & 0x3;
        let base = stvec & !0x3;

        let mut sstatus = self.csrs.read(CSR_SSTATUS);
        let sie = sstatus & SSTATUS_SIE;
        if sie != 0 {
            sstatus |= SSTATUS_SPIE;
        } else {
            sstatus &= !SSTATUS_SPIE;
        }
        sstatus &= !SSTATUS_SIE;
        sstatus = (sstatus & !SSTATUS_SPP) | ((self.priv_mode as u64) << 8);
        self.csrs.write(CSR_SSTATUS, sstatus);

        self.csrs.write(CSR_SEPC, self.pc);
        self.csrs.write(CSR_SCAUSE, cause);
        self.csrs.write(CSR_STVAL, tval);
        self.priv_mode = PrivMode::Supervisor;

        let next_pc = if mode == 1 {
            base.wrapping_add(4 * (cause & 0xfff))
        } else {
            base
        };
        if self.trace_pc_zero && next_pc == 0 {
            eprintln!(
                "pc->0 via trap: pc=0x{:016x} cause=0x{:x} tval=0x{:016x} stvec=0x{:016x}",
                self.pc, cause, tval, stvec
            );
        }
        self.pc = next_pc;
        self.last_access = None;
    }

    pub fn handle_trap(&mut self, trap: Trap) {
        if self.trace_last && !self.trace_last_dumped {
            eprintln!("last instrs:");
            for (pc, instr, len) in &self.last_instrs {
                if *len == 2 {
                    eprintln!("  pc=0x{:016x} c16=0x{:04x}", pc, instr & 0xffff);
                } else {
                    eprintln!("  pc=0x{:016x} i32=0x{:08x}", pc, instr);
                }
            }
            self.trace_last_dumped = true;
        }
        let (kind, _addr, _size) = self.last_access.unwrap_or((AccessType::Fetch, self.pc, 4));
        match trap {
            Trap::IllegalInstruction(instr) => {
                self.take_trap(2, instr as u64);
            }
            Trap::Ebreak => {
                self.take_trap(3, self.pc);
            }
            Trap::Ecall => {
                let cause = match self.priv_mode {
                    PrivMode::User => 8,
                    PrivMode::Supervisor => 9,
                    PrivMode::Machine => 11,
                };
                self.take_trap(cause, 0);
            }
            Trap::PageFault { addr, kind } => {
                let cause = match kind {
                    AccessType::Fetch => 12,
                    AccessType::Load => 13,
                    AccessType::Store => 15,
                    AccessType::Debug => 13,
                };
                self.take_trap(cause, addr);
            }
            Trap::MisalignedAccess { addr, .. } => {
                let cause = match kind {
                    AccessType::Fetch => 0,
                    AccessType::Load => 4,
                    AccessType::Store => 6,
                    AccessType::Debug => 0,
                };
                self.take_trap(cause, addr);
            }
            Trap::MemoryOutOfBounds { addr, .. } => {
                let cause = match kind {
                    AccessType::Fetch => 1,
                    AccessType::Load => 5,
                    AccessType::Store => 7,
                    AccessType::Debug => 1,
                };
                self.take_trap(cause, addr);
            }
        }
    }

    #[inline]
    fn has_debug_hooks(&self) -> bool {
        self.hotpc_top != 0
            || self.trace_pc_zero
            || self.trace_last
            || self.trace_pc.is_some()
            || self.trace_instr.is_some()
            || self.watch_left > 0
            || self.watch_left2 > 0
    }

    fn exec32_decoded(
        &mut self,
        bus: &mut impl Bus,
        sbi: &mut impl Sbi,
        instr: u32,
        d: Decoded32,
    ) -> Result<u64, Trap> {
        let opcode = d.opcode as u32;
        let rd = d.rd as usize;
        let funct3 = d.funct3 as u32;
        let rs1 = d.rs1 as usize;
        let rs2 = d.rs2 as usize;
        let funct7 = d.funct7 as u32;
        let funct5 = d.funct5 as u32;
        let imm12 = d.imm12 as u32;
        let shamt = (imm12 & 0x3f) as u32;
        let imm_hi = (imm12 >> 6) & 0x3f;
        let csr_addr = d.csr_addr;
        let zimm = rs1 as u64;

        let mut next_pc = self.pc.wrapping_add(4);
        match opcode {
            OPCODE_LUI => {
                self.regs[rd] = Self::imm_u(instr) as u64;
            }
            OPCODE_AUIPC => {
                self.regs[rd] = self.pc.wrapping_add(Self::imm_u(instr) as u64);
            }
            OPCODE_JAL => {
                let imm_j = Self::imm_j(instr) as u64;
                self.regs[rd] = next_pc;
                next_pc = self.pc.wrapping_add(imm_j);
            }
            OPCODE_JALR => {
                let imm_i = Self::imm_i(instr) as u64;
                let target = self.regs[rs1].wrapping_add(imm_i) & !1;
                self.regs[rd] = next_pc;
                next_pc = target;
            }
            OPCODE_BRANCH => {
                let imm_b = Self::imm_b(instr) as u64;
                let a = self.regs[rs1];
                let b = self.regs[rs2];
                let take = match funct3 {
                    F3_BEQ => a == b,
                    F3_BNE => a != b,
                    F3_BLT => (a as i64) < (b as i64),
                    F3_BGE => (a as i64) >= (b as i64),
                    F3_BLTU => a < b,
                    F3_BGEU => a >= b,
                    _ => return Err(Trap::IllegalInstruction(instr)),
                };
                if take {
                    next_pc = self.pc.wrapping_add(imm_b);
                }
            }
            OPCODE_LOAD => {
                let imm_i = Self::imm_i(instr) as u64;
                let addr = self.regs[rs1].wrapping_add(imm_i);
                let val = match funct3 {
                    F3_LB => self.read_u8(bus, addr, AccessType::Load)? as i8 as i64 as u64,
                    F3_LH => self.read_u16(bus, addr, AccessType::Load)? as i16 as i64 as u64,
                    F3_LW => self.read_u32(bus, addr, AccessType::Load)? as i32 as i64 as u64,
                    F3_LD => self.read_u64(bus, addr, AccessType::Load)?,
                    F3_LBU => self.read_u8(bus, addr, AccessType::Load)? as u64,
                    F3_LHU => self.read_u16(bus, addr, AccessType::Load)? as u64,
                    F3_LWU => self.read_u32(bus, addr, AccessType::Load)? as u64,
                    _ => return Err(Trap::IllegalInstruction(instr)),
                };
                self.regs[rd] = val;
            }
            OPCODE_LOAD_FP => {
                let imm_i = Self::imm_i(instr) as u64;
                let addr = self.regs[rs1].wrapping_add(imm_i);
                match funct3 {
                    2 => {
                        let val = self.read_u32(bus, addr, AccessType::Load)?;
                        self.fregs[rd] = val as u64;
                    }
                    3 => {
                        let val = self.read_u64(bus, addr, AccessType::Load)?;
                        self.fregs[rd] = val;
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                }
            }
            OPCODE_STORE => {
                let imm_s = Self::imm_s(instr) as u64;
                let addr = self.regs[rs1].wrapping_add(imm_s);
                let val = self.regs[rs2];
                match funct3 {
                    F3_SB => self.write_u8(bus, addr, val as u8, AccessType::Store)?,
                    F3_SH => self.write_u16(bus, addr, val as u16, AccessType::Store)?,
                    F3_SW => self.write_u32(bus, addr, val as u32, AccessType::Store)?,
                    F3_SD => self.write_u64(bus, addr, val, AccessType::Store)?,
                    _ => return Err(Trap::IllegalInstruction(instr)),
                }
            }
            OPCODE_STORE_FP => {
                let imm_s = Self::imm_s(instr) as u64;
                let addr = self.regs[rs1].wrapping_add(imm_s);
                match funct3 {
                    2 => {
                        let val = self.fregs[rs2] as u32;
                        self.write_u32(bus, addr, val, AccessType::Store)?;
                    }
                    3 => {
                        let val = self.fregs[rs2];
                        self.write_u64(bus, addr, val, AccessType::Store)?;
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                }
            }
            OPCODE_OP_IMM => {
                let imm_i = Self::imm_i(instr) as u64;
                let a = self.regs[rs1];
                let res = match funct3 {
                    F3_ADD_SUB => a.wrapping_add(imm_i),
                    F3_SLL => {
                        if imm_hi != 0 {
                            return Err(Trap::IllegalInstruction(instr));
                        }
                        a << shamt
                    }
                    F3_SLT => ((a as i64) < (imm_i as i64)) as u64,
                    F3_SLTU => (a < imm_i) as u64,
                    F3_XOR => a ^ imm_i,
                    F3_SRL_SRA => match imm_hi {
                        0x00 => a >> shamt,
                        0x10 => ((a as i64) >> shamt) as u64,
                        _ => return Err(Trap::IllegalInstruction(instr)),
                    },
                    F3_OR => a | imm_i,
                    F3_AND => a & imm_i,
                    _ => return Err(Trap::IllegalInstruction(instr)),
                };
                self.regs[rd] = res;
            }
            OPCODE_OP => {
                let a = self.regs[rs1];
                let b = self.regs[rs2];
                let res = match (funct7, funct3) {
                    (F7_BASE, F3_ADD_SUB) => a.wrapping_add(b),
                    (F7_SUB_SRA, F3_ADD_SUB) => a.wrapping_sub(b),
                    (F7_BASE, F3_SLL) => a << (b & 0x3f),
                    (F7_BASE, F3_SLT) => ((a as i64) < (b as i64)) as u64,
                    (F7_BASE, F3_SLTU) => (a < b) as u64,
                    (F7_BASE, F3_XOR) => a ^ b,
                    (F7_BASE, F3_SRL_SRA) => a >> (b & 0x3f),
                    (F7_SUB_SRA, F3_SRL_SRA) => ((a as i64) >> (b & 0x3f)) as u64,
                    (F7_BASE, F3_OR) => a | b,
                    (F7_BASE, F3_AND) => a & b,
                    (F7_MULDIV, F3_ADD_SUB) => a.wrapping_mul(b),
                    (F7_MULDIV, F3_SLL) => {
                        let prod = (a as i64 as i128).wrapping_mul(b as i64 as i128);
                        (prod >> 64) as u64
                    }
                    (F7_MULDIV, F3_SLT) => {
                        let prod = (a as i64 as i128).wrapping_mul(b as u128 as i128);
                        (prod >> 64) as u64
                    }
                    (F7_MULDIV, F3_SLTU) => {
                        let prod = (a as u128).wrapping_mul(b as u128);
                        (prod >> 64) as u64
                    }
                    (F7_MULDIV, F3_XOR) => {
                        let dividend = a as i64;
                        let divisor = b as i64;
                        if divisor == 0 {
                            u64::MAX
                        } else if dividend == i64::MIN && divisor == -1 {
                            dividend as u64
                        } else {
                            (dividend / divisor) as u64
                        }
                    }
                    (F7_MULDIV, F3_SRL_SRA) => {
                        if b == 0 {
                            u64::MAX
                        } else {
                            a / b
                        }
                    }
                    (F7_MULDIV, F3_OR) => {
                        let dividend = a as i64;
                        let divisor = b as i64;
                        if divisor == 0 {
                            a
                        } else if dividend == i64::MIN && divisor == -1 {
                            0
                        } else {
                            (dividend % divisor) as u64
                        }
                    }
                    (F7_MULDIV, F3_AND) => {
                        if b == 0 {
                            a
                        } else {
                            a % b
                        }
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                };
                self.regs[rd] = res;
            }
            OPCODE_OP_IMM_32 => {
                let imm = Self::imm_i(instr);
                let shamt = (imm12 & 0x1f) as u32;
                let a = self.regs[rs1] as i64;
                let res32 = match funct3 {
                    F3_ADD_SUB => (a.wrapping_add(imm)) as i32,
                    F3_SLL => {
                        if funct7 != F7_BASE {
                            return Err(Trap::IllegalInstruction(instr));
                        }
                        ((a as i32) << shamt) as i32
                    }
                    F3_SRL_SRA => {
                        if funct7 == F7_SUB_SRA {
                            ((a as i32) >> shamt) as i32
                        } else if funct7 == F7_BASE {
                            ((a as u32) >> shamt) as i32
                        } else {
                            return Err(Trap::IllegalInstruction(instr));
                        }
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                };
                self.regs[rd] = res32 as i64 as u64;
            }
            OPCODE_OP_32 => {
                let a = self.regs[rs1] as i64;
                let b = self.regs[rs2] as i64;
                let res32 = match (funct7, funct3) {
                    (F7_BASE, F3_ADD_SUB) => (a.wrapping_add(b)) as i32,
                    (F7_SUB_SRA, F3_ADD_SUB) => (a.wrapping_sub(b)) as i32,
                    (F7_BASE, F3_SLL) => ((a as i32) << (b as u32 & 0x1f)) as i32,
                    (F7_BASE, F3_SRL_SRA) => ((a as u32) >> (b as u32 & 0x1f)) as i32,
                    (F7_SUB_SRA, F3_SRL_SRA) => ((a as i32) >> (b as u32 & 0x1f)) as i32,
                    (F7_MULDIV, F3_ADD_SUB) => ((a as i32).wrapping_mul(b as i32)) as i32,
                    (F7_MULDIV, F3_XOR) => {
                        let dividend = a as i32;
                        let divisor = b as i32;
                        if divisor == 0 {
                            -1i32
                        } else if dividend == i32::MIN && divisor == -1 {
                            dividend
                        } else {
                            dividend / divisor
                        }
                    }
                    (F7_MULDIV, F3_SRL_SRA) => {
                        let dividend = a as u32;
                        let divisor = b as u32;
                        if divisor == 0 {
                            u32::MAX as i32
                        } else {
                            (dividend / divisor) as i32
                        }
                    }
                    (F7_MULDIV, F3_OR) => {
                        let dividend = a as i32;
                        let divisor = b as i32;
                        if divisor == 0 {
                            dividend
                        } else if dividend == i32::MIN && divisor == -1 {
                            0
                        } else {
                            dividend % divisor
                        }
                    }
                    (F7_MULDIV, F3_AND) => {
                        let dividend = a as u32;
                        let divisor = b as u32;
                        if divisor == 0 {
                            dividend as i32
                        } else {
                            (dividend % divisor) as i32
                        }
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                };
                self.regs[rd] = res32 as i64 as u64;
            }
            OPCODE_SYSTEM => match funct3 {
                F3_SYSTEM => match imm12 {
                    IMM_ECALL => {
                        if self.priv_mode == PrivMode::Supervisor {
                            if !sbi.handle_ecall(self, bus)? {
                                return Err(Trap::Ecall);
                            }
                        } else {
                            return Err(Trap::Ecall);
                        }
                    }
                    IMM_EBREAK => {
                        if !self.ignore_ebreak {
                            return Err(Trap::Ebreak);
                        }
                    }
                    IMM_SRET => {
                        let mut sstatus = self.csrs.read(CSR_SSTATUS);
                        let spie = (sstatus & SSTATUS_SPIE) != 0;
                        if spie {
                            sstatus |= SSTATUS_SIE;
                        } else {
                            sstatus &= !SSTATUS_SIE;
                        }
                        sstatus |= SSTATUS_SPIE;
                        let spp = (sstatus & SSTATUS_SPP) != 0;
                        sstatus &= !SSTATUS_SPP;
                        self.csrs.write(CSR_SSTATUS, sstatus);
                        self.priv_mode = if spp {
                            PrivMode::Supervisor
                        } else {
                            PrivMode::User
                        };
                        next_pc = self.csrs.read(CSR_SEPC);
                    }
                    IMM_MRET => {
                        next_pc = self.csrs.read(CSR_MEPC);
                    }
                    IMM_WFI => {}
                    _ => {
                        if (instr >> 25) == 0x09 {
                            self.flush_tlb();
                        }
                    }
                },
                F3_CSRRW | F3_CSRRS | F3_CSRRC | F3_CSRRWI | F3_CSRRSI | F3_CSRRCI => {
                    if csr_addr == crate::csr::CSR_INSTRET {
                        self.commit_instret();
                    }
                    let old = self.csrs.read(csr_addr);
                    let mut new_val = old;
                    let mut do_write = true;
                    match funct3 {
                        F3_CSRRW => new_val = self.regs[rs1],
                        F3_CSRRS => {
                            if rs1 == 0 {
                                do_write = false;
                            } else {
                                new_val = old | self.regs[rs1];
                            }
                        }
                        F3_CSRRC => {
                            if rs1 == 0 {
                                do_write = false;
                            } else {
                                new_val = old & !self.regs[rs1];
                            }
                        }
                        F3_CSRRWI => new_val = zimm,
                        F3_CSRRSI => {
                            if zimm == 0 {
                                do_write = false;
                            } else {
                                new_val = old | zimm;
                            }
                        }
                        F3_CSRRCI => {
                            if zimm == 0 {
                                do_write = false;
                            } else {
                                new_val = old & !zimm;
                            }
                        }
                        _ => {}
                    }
                    if rd != 0 {
                        self.regs[rd] = old;
                    }
                    if do_write {
                        self.csrs.write(csr_addr, new_val);
                        if csr_addr == CSR_SATP {
                            self.satp_cached = self.csrs.read(CSR_SATP);
                            self.flush_tlb();
                        }
                    }
                }
                _ => return Err(Trap::IllegalInstruction(instr)),
            },
            OPCODE_AMO => {
                let addr = self.regs[rs1];
                match funct3 {
                    F3_AMO_W => {
                        let rs2_val = self.regs[rs2] as u32;
                        match funct5 {
                            F5_LR => {
                                let val = self.read_u32(bus, addr, AccessType::Load)?;
                                self.regs[rd] = (val as i32) as i64 as u64;
                                self.reservation = Some(addr);
                            }
                            F5_SC => {
                                let success = self.reservation == Some(addr);
                                if success {
                                    self.write_u32(bus, addr, rs2_val, AccessType::Store)?;
                                    self.regs[rd] = 0;
                                } else {
                                    self.regs[rd] = 1;
                                }
                                self.reservation = None;
                            }
                            F5_AMOSWAP => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                self.write_u32(bus, addr, rs2_val, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOADD => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = old.wrapping_add(rs2_val);
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOAND => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = old & rs2_val;
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOOR => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = old | rs2_val;
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOXOR => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = old ^ rs2_val;
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOMAX => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = if (old as i32) > (rs2_val as i32) { old } else { rs2_val };
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOMIN => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = if (old as i32) < (rs2_val as i32) { old } else { rs2_val };
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOMAXU => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = if old > rs2_val { old } else { rs2_val };
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            F5_AMOMINU => {
                                let old = self.read_u32(bus, addr, AccessType::Load)?;
                                let newv = if old < rs2_val { old } else { rs2_val };
                                self.write_u32(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = (old as i32) as i64 as u64;
                            }
                            _ => return Err(Trap::IllegalInstruction(instr)),
                        }
                    }
                    F3_AMO_D => {
                        let rs2_val = self.regs[rs2];
                        match funct5 {
                            F5_LR => {
                                let val = self.read_u64(bus, addr, AccessType::Load)?;
                                self.regs[rd] = val;
                                self.reservation = Some(addr);
                            }
                            F5_SC => {
                                let success = self.reservation == Some(addr);
                                if success {
                                    self.write_u64(bus, addr, rs2_val, AccessType::Store)?;
                                    self.regs[rd] = 0;
                                } else {
                                    self.regs[rd] = 1;
                                }
                                self.reservation = None;
                            }
                            F5_AMOSWAP => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                self.write_u64(bus, addr, rs2_val, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOADD => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = old.wrapping_add(rs2_val);
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOAND => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = old & rs2_val;
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOOR => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = old | rs2_val;
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOXOR => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = old ^ rs2_val;
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOMAX => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = if (old as i64) > (rs2_val as i64) { old } else { rs2_val };
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOMIN => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = if (old as i64) < (rs2_val as i64) { old } else { rs2_val };
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOMAXU => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = if old > rs2_val { old } else { rs2_val };
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            F5_AMOMINU => {
                                let old = self.read_u64(bus, addr, AccessType::Load)?;
                                let newv = if old < rs2_val { old } else { rs2_val };
                                self.write_u64(bus, addr, newv, AccessType::Store)?;
                                self.regs[rd] = old;
                            }
                            _ => return Err(Trap::IllegalInstruction(instr)),
                        }
                    }
                    _ => return Err(Trap::IllegalInstruction(instr)),
                }
            }
            OPCODE_MISC_MEM => match funct3 {
                F3_FENCE | F3_FENCE_I => {}
                _ => return Err(Trap::IllegalInstruction(instr)),
            },
            _ => return Err(Trap::IllegalInstruction(instr)),
        }
        Ok(next_pc)
    }

    pub fn step(&mut self, bus: &mut impl Bus, sbi: &mut impl Sbi) -> Result<(), Trap> {
        // Keep rdtime/cycle moving each simulated step even when runtime
        // housekeeping is batched in System::run.
        let dt = self.next_time_delta() as u32;
        let total = self.time_div_accum.saturating_add(dt);
        if total >= self.time_divider {
            let ticks = total / self.time_divider;
            self.time_div_accum = total % self.time_divider;
            self.csrs.increment_time(ticks as u64);
        } else {
            self.time_div_accum = total;
        }
        if self.hotpc_top != 0 {
            *self.hotpc_counts.entry(self.pc).or_insert(0) += 1;
        }
        if self.irq_check_countdown <= 1 {
            self.irq_check_countdown = self.irq_check_stride;
            if let Some(code) = self.pending_interrupt() {
                let cause = (1u64 << 63) | code;
                self.take_trap(cause, 0);
                return Ok(());
            }
        } else {
            self.irq_check_countdown -= 1;
        }

        self.check_align(self.pc, 2)?;
        let (instr16, instr32_cached) = if (self.pc & 0x3) == 0 {
            let word = self.read_u32(bus, self.pc, AccessType::Fetch)?;
            ((word & 0xffff) as u16, Some(word))
        } else {
            (self.read_u16(bus, self.pc, AccessType::Fetch)?, None)
        };
        let debug_hooks = self.has_debug_hooks();
        if (instr16 & 0x3) != 0x3 {
            if !debug_hooks {
                return self.exec_compressed(bus, instr16);
            }
            self.record_instr(self.pc, instr16 as u32, 2);
            let pc_before = self.pc;
            let watch_hit = self.watch_hit(self.pc);
            let watch_reg = self.watch_reg;
            let watch_before = if watch_hit {
                watch_reg.map(|r| self.regs[r])
            } else {
                None
            };
            let watch_hit2 = self.watch_hit2(self.pc);
            let watch_reg2 = self.watch_reg2;
            let watch_before2 = if watch_hit2 {
                watch_reg2.map(|r| self.regs[r])
            } else {
                None
            };
            let trace_window = self.trace_pc.map_or(false, |start| {
                self.pc >= start && self.pc < start.saturating_add(self.trace_span)
            });
            if trace_window {
                let should_print = match self.trace_pc_left.as_mut() {
                    Some(left) => {
                        if *left == 0 {
                            false
                        } else {
                            *left -= 1;
                            true
                        }
                    }
                    None => true,
                };
                if should_print {
                    if self.trace_disas {
                        eprintln!(
                            "instr pc=0x{:016x} c16=0x{:04x} {}",
                            self.pc,
                            instr16,
                            disas::disas16(instr16)
                        );
                    } else {
                        eprintln!("instr pc=0x{:016x} c16=0x{:04x}", self.pc, instr16);
                    }
                }
            } else if let Some(left) = self.trace_instr.as_mut() {
                if *left > 0 {
                    if self.trace_disas {
                        eprintln!(
                            "instr pc=0x{:016x} c16=0x{:04x} {}",
                            self.pc,
                            instr16,
                            disas::disas16(instr16)
                        );
                    } else {
                        eprintln!("instr pc=0x{:016x} c16=0x{:04x}", self.pc, instr16);
                    }
                    *left -= 1;
                }
            }
            let res = self.exec_compressed(bus, instr16);
            if watch_hit {
                let watch_after = watch_reg.map(|r| self.regs[r]);
                let watch_field = Self::watch_field(watch_reg, watch_before, watch_after);
                let watch_cstr = self.watch_cstr_field(bus, watch_reg, watch_after);
                match res {
                    Ok(()) => {
                        eprintln!(
                            "watch1 pc=0x{:016x} c16=0x{:04x} {} ra=0x{:016x} sp=0x{:016x} -> next_pc=0x{:016x}{}{}",
                            pc_before,
                            instr16,
                            disas::disas16(instr16),
                            self.regs[1],
                            self.regs[2],
                            self.pc,
                            watch_field,
                            watch_cstr
                        );
                    }
                    Err(ref trap) => {
                        eprintln!(
                            "watch1 pc=0x{:016x} c16=0x{:04x} {} trap={:?}{}{}",
                            pc_before,
                            instr16,
                            disas::disas16(instr16),
                            trap,
                            watch_field,
                            watch_cstr
                        );
                    }
                }
            }
            if watch_hit2 {
                let watch_after2 = watch_reg2.map(|r| self.regs[r]);
                let watch_field2 = Self::watch_field(watch_reg2, watch_before2, watch_after2);
                let watch_cstr2 = self.watch_cstr_field(bus, watch_reg2, watch_after2);
                match res {
                    Ok(()) => {
                        eprintln!(
                            "watch2 pc=0x{:016x} c16=0x{:04x} {} ra=0x{:016x} sp=0x{:016x} -> next_pc=0x{:016x}{}{}",
                            pc_before,
                            instr16,
                            disas::disas16(instr16),
                            self.regs[1],
                            self.regs[2],
                            self.pc,
                            watch_field2,
                            watch_cstr2
                        );
                    }
                    Err(ref trap) => {
                        eprintln!(
                            "watch2 pc=0x{:016x} c16=0x{:04x} {} trap={:?}{}{}",
                            pc_before,
                            instr16,
                            disas::disas16(instr16),
                            trap,
                            watch_field2,
                            watch_cstr2
                        );
                    }
                }
            }
            return res;
        }
        let instr = if let Some(word) = instr32_cached {
            word
        } else {
            let upper = self.read_u16(bus, self.pc.wrapping_add(2), AccessType::Fetch)? as u32;
            (upper << 16) | (instr16 as u32)
        };
        if !debug_hooks {
            let d = self.decode32_cached(self.pc, instr);
            let next_pc = self.exec32_decoded(bus, sbi, instr, d)?;
            self.pc = next_pc;
            self.regs[0] = 0;
            self.instret_pending = self.instret_pending.wrapping_add(1);
            return Ok(());
        }
        self.record_instr(self.pc, instr, 4);
        let trace_window = self.trace_pc.map_or(false, |start| {
            self.pc >= start && self.pc < start.saturating_add(self.trace_span)
        });
        if trace_window {
            let should_print = match self.trace_pc_left.as_mut() {
                Some(left) => {
                    if *left == 0 {
                        false
                    } else {
                        *left -= 1;
                        true
                    }
                }
                None => true,
            };
            if should_print {
                if self.trace_disas {
                    eprintln!(
                        "instr pc=0x{:016x} i32=0x{:08x} {}",
                        self.pc,
                        instr,
                        disas::disas32(instr)
                    );
                } else {
                    eprintln!("instr pc=0x{:016x} i32=0x{:08x}", self.pc, instr);
                }
            }
        } else if let Some(left) = self.trace_instr.as_mut() {
            if *left > 0 {
                if self.trace_disas {
                    eprintln!(
                        "instr pc=0x{:016x} i32=0x{:08x} {}",
                        self.pc,
                        instr,
                        disas::disas32(instr)
                    );
                } else {
                    eprintln!("instr pc=0x{:016x} i32=0x{:08x}", self.pc, instr);
                }
                *left -= 1;
            }
        }
        let d = self.decode32_cached(self.pc, instr);
        let rd = d.rd as usize;
        let rs1 = d.rs1 as usize;
        let rs2 = d.rs2 as usize;
        let pc_before = self.pc;
        let watch_hit = self.watch_hit(self.pc);
        let watch_reg = self.watch_reg;
        let watch_before = if watch_hit {
            watch_reg.map(|r| self.regs[r])
        } else {
            None
        };
        let watch_hit2 = self.watch_hit2(self.pc);
        let watch_reg2 = self.watch_reg2;
        let watch_before2 = if watch_hit2 {
            watch_reg2.map(|r| self.regs[r])
        } else {
            None
        };
        let (rs1_before, rs2_before, rd_before) = if watch_hit || watch_hit2 {
            (self.regs[rs1], self.regs[rs2], self.regs[rd])
        } else {
            (0, 0, 0)
        };
        let next_pc = self.exec32_decoded(bus, sbi, instr, d)?;

        if self.trace_pc_zero && next_pc == 0 {
            eprintln!(
                "pc->0: pc=0x{:016x} instr=0x{:08x} ra=0x{:016x}",
                self.pc, instr, self.regs[1]
            );
        }
        if watch_hit {
            let rd_after = if rd == 0 { 0 } else { self.regs[rd] };
            let watch_after = watch_reg.map(|r| if r == 0 { 0 } else { self.regs[r] });
            let watch_field = Self::watch_field(watch_reg, watch_before, watch_after);
            let watch_cstr = self.watch_cstr_field(bus, watch_reg, watch_after);
            eprintln!(
                "watch1 pc=0x{:016x} i32=0x{:08x} {} rs1=x{}:0x{:016x} rs2=x{}:0x{:016x} rd=x{}:0x{:016x}->0x{:016x} next_pc=0x{:016x}{}{}",
                pc_before,
                instr,
                disas::disas32(instr),
                rs1,
                rs1_before,
                rs2,
                rs2_before,
                rd,
                rd_before,
                rd_after,
                next_pc,
                watch_field,
                watch_cstr
            );
        }
        if watch_hit2 {
            let rd_after = if rd == 0 { 0 } else { self.regs[rd] };
            let watch_after2 = watch_reg2.map(|r| if r == 0 { 0 } else { self.regs[r] });
            let watch_field2 = Self::watch_field(watch_reg2, watch_before2, watch_after2);
            let watch_cstr2 = self.watch_cstr_field(bus, watch_reg2, watch_after2);
            eprintln!(
                "watch2 pc=0x{:016x} i32=0x{:08x} {} rs1=x{}:0x{:016x} rs2=x{}:0x{:016x} rd=x{}:0x{:016x}->0x{:016x} next_pc=0x{:016x}{}{}",
                pc_before,
                instr,
                disas::disas32(instr),
                rs1,
                rs1_before,
                rs2,
                rs2_before,
                rd,
                rd_before,
                rd_after,
                next_pc,
                watch_field2,
                watch_cstr2
            );
        }
        self.pc = next_pc;
        self.regs[0] = 0;
        self.instret_pending = self.instret_pending.wrapping_add(1);
        Ok(())
    }

    fn exec_compressed(&mut self, bus: &mut impl Bus, instr: u16) -> Result<(), Trap> {
        let funct3 = (instr >> 13) & 0x7;
        let op = instr & 0x3;
        let mut next_pc = self.pc.wrapping_add(2);

        let rd = ((instr >> 7) & 0x1f) as usize;
        let rs2 = ((instr >> 2) & 0x1f) as usize;
        let rd_prime = (((instr >> 2) & 0x7) + 8) as usize;
        let rs1_prime = (((instr >> 7) & 0x7) + 8) as usize;
        let rs2_prime = (((instr >> 2) & 0x7) + 8) as usize;

        let imm_ci = || {
            let imm = (((instr >> 12) & 0x1) << 5) | ((instr >> 2) & 0x1f);
            Self::sign_extend(imm as u64, 6) as u64
        };

        match op {
            0b00 => {
                match funct3 {
                    0b000 => {
                        // C.ADDI4SPN
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 9)
                            | (((instr >> 9) & 0x1) << 8)
                            | (((instr >> 8) & 0x1) << 7)
                            | (((instr >> 7) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 2)
                            | (((instr >> 5) & 0x1) << 3);
                        if imm == 0 {
                            return Err(Trap::IllegalInstruction(instr as u32));
                        }
                        self.regs[rd_prime] = self.regs[2].wrapping_add(imm as u64);
                    }
                    0b001 => {
                        // C.FLD (RV64)
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 5) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 7);
                        let addr = self.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = self.read_u64(bus, addr, AccessType::Load)?;
                        self.fregs[rd_prime] = val;
                    }
                    0b010 => {
                        // C.LW
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 6) & 0x1) << 2)
                            | (((instr >> 5) & 0x1) << 6);
                        let addr = self.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = self.read_u32(bus, addr, AccessType::Load)? as i32 as i64 as u64;
                        self.regs[rd_prime] = val;
                    }
                    0b011 => {
                        // C.LD (RV64)
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 5) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 7);
                        let addr = self.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = self.read_u64(bus, addr, AccessType::Load)?;
                        self.regs[rd_prime] = val;
                    }
                    0b101 => {
                        // C.FSD (RV64)
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 5) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 7);
                        let addr = self.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = self.fregs[rs2_prime];
                        self.write_u64(bus, addr, val, AccessType::Store)?;
                    }
                    0b110 => {
                        // C.SW
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 6) & 0x1) << 2)
                            | (((instr >> 5) & 0x1) << 6);
                        let addr = self.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = self.regs[rs2_prime] as u32;
                        self.write_u32(bus, addr, val, AccessType::Store)?;
                    }
                    0b111 => {
                        // C.SD (RV64)
                        let imm = (((instr >> 10) & 0x7) << 3)
                            | (((instr >> 5) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 7);
                        let addr = self.regs[rs1_prime].wrapping_add(imm as u64);
                        let val = self.regs[rs2_prime];
                        self.write_u64(bus, addr, val, AccessType::Store)?;
                    }
                    _ => return Err(Trap::IllegalInstruction(instr as u32)),
                }
            }
            0b01 => {
                match funct3 {
                    0b000 => {
                        // C.ADDI / C.NOP
                        if rd != 0 {
                            let imm = imm_ci();
                            self.regs[rd] = self.regs[rd].wrapping_add(imm);
                        }
                    }
                    0b001 => {
                        // C.ADDIW (RV64)
                        if rd == 0 {
                            return Err(Trap::IllegalInstruction(instr as u32));
                        }
                        let imm = imm_ci() as i64;
                        let res = (self.regs[rd] as i64).wrapping_add(imm) as i32;
                        self.regs[rd] = res as i64 as u64;
                    }
                    0b010 => {
                        // C.LI
                        if rd != 0 {
                            self.regs[rd] = imm_ci();
                        }
                    }
                    0b011 => {
                        if rd == 2 {
                            // C.ADDI16SP
                            let imm = (((instr >> 12) & 0x1) << 9)
                                | (((instr >> 6) & 0x1) << 4)
                                | (((instr >> 5) & 0x1) << 6)
                                | (((instr >> 4) & 0x1) << 8)
                                | (((instr >> 3) & 0x1) << 7)
                                | (((instr >> 2) & 0x1) << 5);
                            let imm = Self::sign_extend(imm as u64, 10) as u64;
                            if imm == 0 {
                                return Err(Trap::IllegalInstruction(instr as u32));
                            }
                            self.regs[2] = self.regs[2].wrapping_add(imm);
                        } else {
                            // C.LUI
                            if rd == 0 {
                                return Err(Trap::IllegalInstruction(instr as u32));
                            }
                            let imm = imm_ci();
                            if imm == 0 {
                                return Err(Trap::IllegalInstruction(instr as u32));
                            }
                            self.regs[rd] = ((imm as i64) << 12) as u64;
                        }
                    }
                    0b100 => {
                        let funct2 = (instr >> 10) & 0x3;
                        match funct2 {
                            0b00 => {
                                // C.SRLI
                                let shamt = (((instr >> 12) & 0x1) << 5) | ((instr >> 2) & 0x1f);
                                let rd = rs1_prime;
                                self.regs[rd] >>= shamt;
                            }
                            0b01 => {
                                // C.SRAI
                                let shamt = (((instr >> 12) & 0x1) << 5) | ((instr >> 2) & 0x1f);
                                let rd = rs1_prime;
                                self.regs[rd] = ((self.regs[rd] as i64) >> shamt) as u64;
                            }
                            0b10 => {
                                // C.ANDI
                                let imm = imm_ci() as i64 as u64;
                                let rd = rs1_prime;
                                self.regs[rd] &= imm;
                            }
                            0b11 => {
                                let rd = rs1_prime;
                                let rs2 = rs2_prime;
                                let subop = (instr >> 12) & 0x1;
                                let funct2 = (instr >> 5) & 0x3;
                                match (subop, funct2) {
                                    (0, 0b00) => {
                                        self.regs[rd] = self.regs[rd].wrapping_sub(self.regs[rs2])
                                    } // C.SUB
                                    (0, 0b01) => self.regs[rd] ^= self.regs[rs2], // C.XOR
                                    (0, 0b10) => self.regs[rd] |= self.regs[rs2], // C.OR
                                    (0, 0b11) => self.regs[rd] &= self.regs[rs2], // C.AND
                                    (1, 0b00) => {
                                        // C.SUBW
                                        let a = self.regs[rd] as i64;
                                        let b = self.regs[rs2] as i64;
                                        self.regs[rd] = (a.wrapping_sub(b) as i32) as i64 as u64;
                                    }
                                    (1, 0b01) => {
                                        // C.ADDW
                                        let a = self.regs[rd] as i64;
                                        let b = self.regs[rs2] as i64;
                                        self.regs[rd] = (a.wrapping_add(b) as i32) as i64 as u64;
                                    }
                                    _ => return Err(Trap::IllegalInstruction(instr as u32)),
                                }
                            }
                            _ => return Err(Trap::IllegalInstruction(instr as u32)),
                        }
                    }
                    0b101 => {
                        // C.J
                        let imm = (((instr >> 12) & 0x1) << 11)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 9)
                            | (((instr >> 9) & 0x1) << 8)
                            | (((instr >> 8) & 0x1) << 10)
                            | (((instr >> 7) & 0x1) << 6)
                            | (((instr >> 6) & 0x1) << 7)
                            | (((instr >> 5) & 0x1) << 3)
                            | (((instr >> 4) & 0x1) << 2)
                            | (((instr >> 3) & 0x1) << 1)
                            | (((instr >> 2) & 0x1) << 5);
                        let imm = Self::sign_extend(imm as u64, 12) as u64;
                        next_pc = self.pc.wrapping_add(imm);
                    }
                    0b110 | 0b111 => {
                        // C.BEQZ / C.BNEZ
                        let imm = (((instr >> 12) & 0x1) << 8)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 3)
                            | (((instr >> 6) & 0x1) << 7)
                            | (((instr >> 5) & 0x1) << 6)
                            | (((instr >> 4) & 0x1) << 2)
                            | (((instr >> 3) & 0x1) << 1)
                            | (((instr >> 2) & 0x1) << 5);
                        let imm = Self::sign_extend(imm as u64, 9) as u64;
                        let rs1 = rs1_prime;
                        let take = if funct3 == 0b110 {
                            self.regs[rs1] == 0
                        } else {
                            self.regs[rs1] != 0
                        };
                        if take {
                            next_pc = self.pc.wrapping_add(imm);
                        }
                    }
                    _ => return Err(Trap::IllegalInstruction(instr as u32)),
                }
            }
            0b10 => {
                match funct3 {
                    0b000 => {
                        // C.SLLI
                        if rd == 0 {
                            return Err(Trap::IllegalInstruction(instr as u32));
                        }
                        let shamt = (((instr >> 12) & 0x1) << 5) | ((instr >> 2) & 0x1f);
                        self.regs[rd] = self.regs[rd] << shamt;
                    }
                    0b001 => {
                        // C.FLDSP (RV64)
                        if rd == 0 {
                            return Err(Trap::IllegalInstruction(instr as u32));
                        }
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 6) & 0x1) << 4)
                            | (((instr >> 5) & 0x1) << 3)
                            | (((instr >> 4) & 0x1) << 8)
                            | (((instr >> 3) & 0x1) << 7)
                            | (((instr >> 2) & 0x1) << 6);
                        let addr = self.regs[2].wrapping_add(imm as u64);
                        let val = self.read_u64(bus, addr, AccessType::Load)?;
                        self.fregs[rd] = val;
                    }
                    0b010 => {
                        // C.LWSP
                        if rd == 0 {
                            return Err(Trap::IllegalInstruction(instr as u32));
                        }
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 6) & 0x1) << 4)
                            | (((instr >> 5) & 0x1) << 3)
                            | (((instr >> 4) & 0x1) << 2)
                            | (((instr >> 3) & 0x1) << 7)
                            | (((instr >> 2) & 0x1) << 6);
                        let addr = self.regs[2].wrapping_add(imm as u64);
                        let val = self.read_u32(bus, addr, AccessType::Load)? as i32 as i64 as u64;
                        self.regs[rd] = val;
                    }
                    0b011 => {
                        // C.LDSP
                        if rd == 0 {
                            return Err(Trap::IllegalInstruction(instr as u32));
                        }
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 6) & 0x1) << 4)
                            | (((instr >> 5) & 0x1) << 3)
                            | (((instr >> 4) & 0x1) << 8)
                            | (((instr >> 3) & 0x1) << 7)
                            | (((instr >> 2) & 0x1) << 6);
                        let addr = self.regs[2].wrapping_add(imm as u64);
                        let val = self.read_u64(bus, addr, AccessType::Load)?;
                        self.regs[rd] = val;
                    }
                    0b100 => {
                        let bit12 = (instr >> 12) & 0x1;
                        if bit12 == 0 {
                            if rs2 == 0 {
                                // C.JR
                                if rd == 0 {
                                    return Err(Trap::IllegalInstruction(instr as u32));
                                }
                                next_pc = self.regs[rd] & !1;
                            } else {
                                // C.MV
                                if rd == 0 {
                                    return Err(Trap::IllegalInstruction(instr as u32));
                                }
                                self.regs[rd] = self.regs[rs2];
                            }
                        } else {
                            if rs2 == 0 {
                                if rd == 0 {
                                    // C.EBREAK
                                    if !self.ignore_ebreak {
                                        return Err(Trap::Ebreak);
                                    }
                                }
                                // C.JALR
                                let target = self.regs[rd] & !1;
                                if self.trace_cjalr {
                                    eprintln!(
                                        "c.jalr pc=0x{:016x} rd={} target=0x{:016x} a0=0x{:016x} a1=0x{:016x} a2=0x{:016x} a3=0x{:016x} a4=0x{:016x}",
                                        self.pc,
                                        rd,
                                        target,
                                        self.regs[10],
                                        self.regs[11],
                                        self.regs[12],
                                        self.regs[13],
                                        self.regs[14]
                                    );
                                }
                                self.regs[1] = self.pc.wrapping_add(2);
                                next_pc = target;
                            } else {
                                // C.ADD
                                if rd == 0 {
                                    return Err(Trap::IllegalInstruction(instr as u32));
                                }
                                self.regs[rd] = self.regs[rd].wrapping_add(self.regs[rs2]);
                            }
                        }
                    }
                    0b110 => {
                        // C.SWSP
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 3)
                            | (((instr >> 9) & 0x1) << 2)
                            | (((instr >> 8) & 0x1) << 7)
                            | (((instr >> 7) & 0x1) << 6);
                        let addr = self.regs[2].wrapping_add(imm as u64);
                        let val = self.regs[rs2] as u32;
                        self.write_u32(bus, addr, val, AccessType::Store)?;
                    }
                    0b111 => {
                        // C.SDSP
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 3)
                            | (((instr >> 9) & 0x1) << 8)
                            | (((instr >> 8) & 0x1) << 7)
                            | (((instr >> 7) & 0x1) << 6);
                        let addr = self.regs[2].wrapping_add(imm as u64);
                        let val = self.regs[rs2];
                        self.write_u64(bus, addr, val, AccessType::Store)?;
                    }
                    0b101 => {
                        // C.FSDSP (RV64)
                        let imm = (((instr >> 12) & 0x1) << 5)
                            | (((instr >> 11) & 0x1) << 4)
                            | (((instr >> 10) & 0x1) << 3)
                            | (((instr >> 9) & 0x1) << 8)
                            | (((instr >> 8) & 0x1) << 7)
                            | (((instr >> 7) & 0x1) << 6);
                        let addr = self.regs[2].wrapping_add(imm as u64);
                        let val = self.fregs[rs2];
                        self.write_u64(bus, addr, val, AccessType::Store)?;
                    }
                    _ => return Err(Trap::IllegalInstruction(instr as u32)),
                }
            }
            _ => return Err(Trap::IllegalInstruction(instr as u32)),
        }

        self.pc = next_pc;
        self.regs[0] = 0;
        self.instret_pending = self.instret_pending.wrapping_add(1);
        Ok(())
    }
}
