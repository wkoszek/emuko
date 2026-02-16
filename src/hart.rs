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
use std::collections::{HashMap, HashSet};

#[path = "hart/cache_mmu.rs"]
mod cache_mmu;
#[path = "hart/decode.rs"]
mod decode;
#[path = "hart/exec_core.rs"]
mod exec_core;
#[path = "hart/jit_a64.rs"]
mod jit_a64;
#[path = "hart/jit_x64.rs"]
mod jit_x64;
#[path = "hart/memory.rs"]
mod memory;
#[path = "hart/state.rs"]
mod state;
#[path = "hart/trap_handlers.rs"]
mod trap_handlers;
#[path = "hart/watch.rs"]
mod watch;

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

const TLB_CACHE_SIZE: usize = 8_192;
const DECODE_CACHE_SIZE: usize = 65_536;
const TLB_PERM_R: u8 = 1 << 0;
const TLB_PERM_W: u8 = 1 << 1;
const TLB_PERM_X: u8 = 1 << 2;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct NativeBlockResult {
    next_pc: u64,
    executed: u64,
}

const NATIVE_EXEC_FLAG_LAST_TRAP: u64 = 1u64 << 63;

#[derive(Clone, Copy)]
struct NativeBlock {
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    offset: usize,
    instrs: u32,
}

#[cfg(target_arch = "aarch64")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum EmitFlow {
    Continue,
    Terminate,
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
type NativeBlockFn = unsafe extern "C" fn(
    *mut u64,
    *mut Hart,
    *mut (),
    *mut (),
    *mut (),
    *mut (),
) -> NativeBlockResult;

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
struct NativeCodeCache {
    ptr: *mut u8,
    size: usize,
    used: usize,
    #[cfg(target_os = "macos")]
    use_map_jit: bool,
}

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
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

        #[cfg(target_os = "macos")]
        let mut use_map_jit = true;
        #[cfg(target_os = "macos")]
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
        #[cfg(not(target_os = "macos"))]
        let p = unsafe {
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
            use_map_jit = false;
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
            #[cfg(target_os = "macos")]
            use_map_jit,
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
        #[cfg(target_os = "macos")]
        self.set_writable(true);
        unsafe {
            std::ptr::copy_nonoverlapping(code.as_ptr(), self.ptr.add(aligned), code.len());
        }
        #[cfg(target_os = "macos")]
        self.set_writable(false);
        self.flush_icache(aligned, code.len());
        self.used = end;
        Some(aligned)
    }

    fn ptr_at(&self, off: usize) -> *const u8 {
        unsafe { self.ptr.add(off) as *const u8 }
    }

    #[cfg(target_os = "macos")]
    fn set_writable(&self, writable: bool) {
        if !self.use_map_jit {
            return;
        }
        extern "C" {
            fn pthread_jit_write_protect_np(enabled: i32);
        }
        // enabled=1 means write-protected/executable; enabled=0 means writable.
        unsafe { pthread_jit_write_protect_np(if writable { 0 } else { 1 }) };
    }

    fn prepare_execute(&self) {
        #[cfg(target_os = "macos")]
        self.set_writable(false);
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

#[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
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
    #[cfg(target_arch = "x86_64")]
    links: HashMap<(u64, usize, u64), NativeBlock>,
    failed: HashSet<(u64, u64)>,
    hot: HashMap<(u64, u64), u16>,
    #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
    cache: Option<NativeCodeCache>,
}

impl NativeJit {
    fn new(enabled: bool, code_size: usize) -> Self {
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
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
                #[cfg(target_arch = "x86_64")]
                links: HashMap::new(),
                failed: HashSet::new(),
                hot: HashMap::new(),
                cache,
            }
        }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        {
            let _ = (enabled, code_size);
            Self {
                enabled: false,
                blocks: HashMap::new(),
                #[cfg(target_arch = "x86_64")]
                links: HashMap::new(),
                failed: HashSet::new(),
                hot: HashMap::new(),
            }
        }
    }

    fn clear(&mut self) {
        self.blocks.clear();
        #[cfg(target_arch = "x86_64")]
        self.links.clear();
        self.failed.clear();
        self.hot.clear();
        #[cfg(any(target_arch = "aarch64", target_arch = "x86_64"))]
        if let Some(cache) = self.cache.as_mut() {
            cache.clear();
        }
    }

    fn lookup(&self, satp: u64, pc: u64) -> Option<NativeBlock> {
        self.blocks.get(&(satp, pc)).copied()
    }

    fn insert(&mut self, satp: u64, pc: u64, block: NativeBlock) {
        self.failed.remove(&(satp, pc));
        self.hot.remove(&(satp, pc));
        self.blocks.insert((satp, pc), block);
    }

    #[cfg(target_arch = "x86_64")]
    fn lookup_link(&self, satp: u64, from_off: usize, next_pc: u64) -> Option<NativeBlock> {
        self.links.get(&(satp, from_off, next_pc)).copied()
    }

    #[cfg(target_arch = "x86_64")]
    fn insert_link(&mut self, satp: u64, from_off: usize, next_pc: u64, block: NativeBlock) {
        self.links.insert((satp, from_off, next_pc), block);
    }

    fn is_failed(&self, satp: u64, pc: u64) -> bool {
        self.failed.contains(&(satp, pc))
    }

    fn mark_failed(&mut self, satp: u64, pc: u64) {
        self.hot.remove(&(satp, pc));
        self.failed.insert((satp, pc));
    }

    fn bump_hot(&mut self, satp: u64, pc: u64) -> u16 {
        let e = self.hot.entry((satp, pc)).or_insert(0);
        *e = e.saturating_add(1);
        *e
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

    #[inline]
    fn mul_x(rd: u8, rn: u8, rm: u8) -> u32 {
        0x9B00_7C00 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }

    #[inline]
    fn smulh_x(rd: u8, rn: u8, rm: u8) -> u32 {
        0x9B40_7C00 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }

    #[inline]
    fn umulh_x(rd: u8, rn: u8, rm: u8) -> u32 {
        0x9BC0_7C00 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }

    #[inline]
    fn udiv_x(rd: u8, rn: u8, rm: u8) -> u32 {
        0x9AC0_0800 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }

    #[inline]
    fn sdiv_x(rd: u8, rn: u8, rm: u8) -> u32 {
        0x9AC0_0C00 | ((rm as u32) << 16) | ((rn as u32) << 5) | rd as u32
    }

    #[inline]
    fn mov_x(rd: u8, rn: u8) -> u32 {
        Self::orr_x(rd, rn, 31)
    }

    #[inline]
    fn sub_sp_imm(imm: u16) -> u32 {
        let imm12 = (imm as u32) & 0xfff;
        0xD100_03FF | (imm12 << 10)
    }

    #[inline]
    fn add_sp_imm(imm: u16) -> u32 {
        let imm12 = (imm as u32) & 0xfff;
        0x9100_03FF | (imm12 << 10)
    }

    #[inline]
    fn blr(rn: u8) -> u32 {
        0xD63F_0000 | ((rn as u32) << 5)
    }

    #[inline]
    fn cmp_x(rn: u8, rm: u8) -> u32 {
        0xEB00_001F | ((rm as u32) << 16) | ((rn as u32) << 5)
    }

    #[inline]
    fn csel_x(rd: u8, rn: u8, rm: u8, cond: u8) -> u32 {
        0x9A80_0000
            | ((rm as u32) << 16)
            | (((cond as u32) & 0xf) << 12)
            | ((rn as u32) << 5)
            | rd as u32
    }

    #[inline]
    fn sxtw_x(rd: u8, rn: u8) -> u32 {
        0x9340_7C00 | ((rn as u32) << 5) | rd as u32
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
    tlb: Box<[Option<TlbEntry>]>,
    fast_tlb_fetch: Option<FastTlbEntry>,
    fast_tlb_load: Option<FastTlbEntry>,
    fast_tlb_store: Option<FastTlbEntry>,
    decode_jit_enabled: bool,
    native_jit_trace: bool,
    native_jit_probe_printed: bool,
    native_jit_hot_threshold: u16,
    native_jit: NativeJit,
    decode_cache: Box<[Option<DecodeCacheEntry>]>,
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

#[cfg(target_arch = "aarch64")]
impl Hart {
    const MEM_OP_LB: u64 = 0;
    const MEM_OP_LH: u64 = 1;
    const MEM_OP_LW: u64 = 2;
    const MEM_OP_LD: u64 = 3;
    const MEM_OP_LBU: u64 = 4;
    const MEM_OP_LHU: u64 = 5;
    const MEM_OP_LWU: u64 = 6;
    const MEM_OP_SB: u64 = 16;
    const MEM_OP_SH: u64 = 17;
    const MEM_OP_SW: u64 = 18;
    const MEM_OP_SD: u64 = 19;
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
        let native_jit_hot_threshold = parse_env_u64("KOR_JIT_NATIVE_HOT_THRESHOLD")
            .and_then(|v| u16::try_from(v).ok())
            .unwrap_or(8)
            .max(1);
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
            tlb: vec![None; TLB_CACHE_SIZE].into_boxed_slice(),
            fast_tlb_fetch: None,
            fast_tlb_load: None,
            fast_tlb_store: None,
            decode_jit_enabled,
            native_jit_trace,
            native_jit_probe_printed: false,
            native_jit_hot_threshold,
            native_jit,
            decode_cache: vec![None; DECODE_CACHE_SIZE].into_boxed_slice(),
        }
    }
}
