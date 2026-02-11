use crate::bus::{AccessType, Bus};
use crate::hart::Hart;
use crate::trap::Trap;
use std::env;

pub const EFI_EID: u64 = 0x0045_4649; // "EFI"
pub const EFI_REGION_SIZE: u64 = 0x0002_0000;

const EFI_TABLE_HEADER_SIZE: u32 = 24;
const EFI_SYSTEM_TABLE_SIZE: u32 = 0x78;
const EFI_BOOT_SERVICES_SIZE: u32 = 0x178;
const EFI_RUNTIME_SERVICES_SIZE: u32 = 0x88;
const EFI_MEMORY_DESCRIPTOR_SIZE: u64 = 48;
const EFI_MEMORY_DESCRIPTOR_VERSION: u32 = 1;

const EFI_SIG_SYSTEM_TABLE: u64 = 0x5453_5953_2049_4249;
const EFI_SIG_BOOT_SERVICES: u64 = 0x5652_4553_544f_4f42;
const EFI_SIG_RUNTIME_SERVICES: u64 = 0x5652_4553_544e_5552;

const EFI_STATUS_SUCCESS: u64 = 0;
const EFI_STATUS_ERROR_MASK: u64 = 1u64 << 63;
const EFI_STATUS_INVALID_PARAMETER: u64 = EFI_STATUS_ERROR_MASK | 2;
const EFI_STATUS_UNSUPPORTED: u64 = EFI_STATUS_ERROR_MASK | 3;
const EFI_STATUS_BUFFER_TOO_SMALL: u64 = EFI_STATUS_ERROR_MASK | 5;
const EFI_STATUS_OUT_OF_RESOURCES: u64 = EFI_STATUS_ERROR_MASK | 9;
const EFI_STATUS_NOT_FOUND: u64 = EFI_STATUS_ERROR_MASK | 14;

const EFI_MEMORY_LOADER_CODE: u32 = 1;
const EFI_MEMORY_LOADER_DATA: u32 = 2;
const EFI_MEMORY_BOOT_SERVICES_DATA: u32 = 4;
const EFI_MEMORY_CONVENTIONAL: u32 = 7;

const EFI_LOCATE_SEARCH_ALL_HANDLES: u64 = 0;
const EFI_LOCATE_SEARCH_BY_REGISTER_NOTIFY: u64 = 1;
const EFI_LOCATE_SEARCH_BY_PROTOCOL: u64 = 2;

const EFI_OPEN_PROTOCOL_TEST_PROTOCOL: u64 = 0x0000_0004;

const EFI_FID_ALLOCATE_PAGES: u64 = 0;
const EFI_FID_FREE_PAGES: u64 = 1;
const EFI_FID_GET_MEMORY_MAP: u64 = 2;
const EFI_FID_ALLOCATE_POOL: u64 = 3;
const EFI_FID_FREE_POOL: u64 = 4;
const EFI_FID_EXIT_BOOT_SERVICES: u64 = 5;
const EFI_FID_HANDLE_PROTOCOL: u64 = 6;
const EFI_FID_LOCATE_PROTOCOL: u64 = 7;
const EFI_FID_SET_WATCHDOG_TIMER: u64 = 8;
const EFI_FID_COPY_MEM: u64 = 9;
const EFI_FID_SET_MEM: u64 = 10;
const EFI_FID_CALC_CRC32: u64 = 11;
const EFI_FID_INSTALL_CONFIG_TABLE: u64 = 12;
const EFI_FID_CONOUT_OUTPUT_STRING: u64 = 13;
const EFI_FID_GET_BOOT_HARTID: u64 = 14;
const EFI_FID_GET_FDT: u64 = 15;
const EFI_FID_LOAD_FILE: u64 = 16;
const EFI_FID_OPEN_PROTOCOL: u64 = 20;
const EFI_FID_CLOSE_PROTOCOL: u64 = 21;
const EFI_FID_LOCATE_HANDLE_BUFFER: u64 = 22;
const EFI_FID_LOCATE_HANDLE: u64 = 23;
const EFI_FID_LOCATE_DEVICE_PATH: u64 = 24;
const EFI_FID_UNSUPPORTED: u64 = 0x7ff;

const EFI_GUID_FDT: [u8; 16] = [
    0xd5, 0x21, 0xb6, 0xb1,
    0x9c, 0xf1,
    0xa5, 0x41,
    0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0,
];
const EFI_GUID_LOADED_IMAGE: [u8; 16] = [
    0xa1, 0x31, 0x1b, 0x5b,
    0x62, 0x95,
    0xd2, 0x11,
    0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
];
const EFI_GUID_RISCV_BOOT_PROTOCOL: [u8; 16] = [
    0xf6, 0x0c, 0x56, 0xf4,
    0xec, 0x40,
    0x4a, 0x4b,
    0xa1, 0x92, 0xbf, 0x1d, 0x57, 0xd0, 0xb1, 0x89,
];
const EFI_GUID_RISCV_FDT_PROTOCOL: [u8; 16] = [
    0xec, 0x5f, 0xd1, 0xcc,
    0x73, 0x6f,
    0xec, 0x4e,
    0x83, 0x95, 0x3e, 0x69, 0xe4, 0xb9, 0x40, 0xbf,
];
const EFI_GUID_LOAD_FILE_PROTOCOL: [u8; 16] = [
    0x91, 0x30, 0xec, 0x56,
    0x4c, 0x95,
    0xd2, 0x11,
    0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
];
const EFI_GUID_LOAD_FILE2_PROTOCOL: [u8; 16] = [
    0xc1, 0xc0, 0x06, 0x40,
    0xb3, 0xfc,
    0x3e, 0x40,
    0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d,
];
const LINUX_EFI_INITRD_MEDIA_GUID: [u8; 16] = [
    0x27, 0xe4, 0x68, 0x55,
    0xfc, 0x68,
    0x3d, 0x4f,
    0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68,
];

#[derive(Clone, Copy, Debug)]
pub struct EfiMemDesc {
    pub ty: u32,
    pub phys_start: u64,
    pub num_pages: u64,
    pub attr: u64,
}

pub struct EfiBuild {
    pub blob: Vec<u8>,
    pub image_handle: u64,
    pub system_table: u64,
    pub loaded_image: u64,
    pub initrd_handle: u64,
    pub initrd_devpath: u64,
    pub riscv_boot_proto: u64,
    pub riscv_fdt_proto: u64,
    pub load_file_proto: u64,
    pub load_file2_proto: u64,
    pub dtb_addr: u64,
    pub dtb_size: u64,
    pub initrd_addr: u64,
    pub initrd_size: u64,
    pub mem_map: Vec<EfiMemDesc>,
    pub alloc_bottom: u64,
    pub alloc_top: u64,
}

pub struct EfiState {
    mem_map: Vec<EfiMemDesc>,
    map_key: u64,
    desc_size: u64,
    desc_version: u32,
    alloc_bottom: u64,
    alloc_top: u64,
    alloc_next: u64,
    pool_next: u64,
    image_handle: u64,
    loaded_image: u64,
    initrd_handle: u64,
    initrd_devpath: u64,
    riscv_boot_proto: u64,
    riscv_fdt_proto: u64,
    load_file_proto: u64,
    load_file2_proto: u64,
    dtb_addr: u64,
    dtb_size: u64,
    initrd_addr: u64,
    initrd_size: u64,
    trace: bool,
}

impl EfiState {
    pub fn new(build: EfiBuild) -> Self {
        let alloc_next = align_down(build.alloc_top, 0x1000);
        let pool_next = align_up(build.alloc_bottom, 8);
        Self {
            mem_map: build.mem_map,
            map_key: 1,
            desc_size: EFI_MEMORY_DESCRIPTOR_SIZE,
            desc_version: EFI_MEMORY_DESCRIPTOR_VERSION,
            alloc_bottom: align_up(build.alloc_bottom, 0x1000),
            alloc_top: align_down(build.alloc_top, 0x1000),
            alloc_next,
            pool_next,
            image_handle: build.image_handle,
            loaded_image: build.loaded_image,
            initrd_handle: build.initrd_handle,
            initrd_devpath: build.initrd_devpath,
            riscv_boot_proto: build.riscv_boot_proto,
            riscv_fdt_proto: build.riscv_fdt_proto,
            load_file_proto: build.load_file_proto,
            load_file2_proto: build.load_file2_proto,
            dtb_addr: build.dtb_addr,
            dtb_size: build.dtb_size,
            initrd_addr: build.initrd_addr,
            initrd_size: build.initrd_size,
            trace: env_flag("EFI_TRACE", false),
        }
    }

    pub fn handle_ecall(&mut self, fid: u64, hart: &mut Hart, bus: &mut dyn Bus) -> Result<(), Trap> {
        if self.trace {
            eprintln!(
                "EFI call {} fid={} a0=0x{:016x} a1=0x{:016x} a2=0x{:016x} a3=0x{:016x} a4=0x{:016x}",
                fid_name(fid),
                fid,
                hart.regs[10],
                hart.regs[11],
                hart.regs[12],
                hart.regs[13],
                hart.regs[14]
            );
        }
        let status = match fid {
            EFI_FID_ALLOCATE_PAGES => self.handle_allocate_pages(hart, bus)?,
            EFI_FID_FREE_PAGES => self.handle_free_pages(hart)?,
            EFI_FID_GET_MEMORY_MAP => self.handle_get_memory_map(hart, bus)?,
            EFI_FID_ALLOCATE_POOL => self.handle_allocate_pool(hart, bus)?,
            EFI_FID_FREE_POOL => EFI_STATUS_SUCCESS,
            EFI_FID_EXIT_BOOT_SERVICES => self.handle_exit_boot_services(hart, bus)?,
            EFI_FID_HANDLE_PROTOCOL => self.handle_handle_protocol(hart, bus)?,
            EFI_FID_LOCATE_PROTOCOL => self.handle_locate_protocol(hart, bus)?,
            EFI_FID_SET_WATCHDOG_TIMER => EFI_STATUS_SUCCESS,
            EFI_FID_COPY_MEM => self.handle_copy_mem(hart, bus)?,
            EFI_FID_SET_MEM => self.handle_set_mem(hart, bus)?,
            EFI_FID_CALC_CRC32 => self.handle_calc_crc32(hart, bus)?,
            EFI_FID_INSTALL_CONFIG_TABLE => EFI_STATUS_SUCCESS,
            EFI_FID_CONOUT_OUTPUT_STRING => self.handle_conout_output_string(hart, bus)?,
            EFI_FID_GET_BOOT_HARTID => self.handle_get_boot_hartid(hart, bus)?,
            EFI_FID_GET_FDT => self.handle_get_fdt(hart, bus)?,
            EFI_FID_LOAD_FILE => self.handle_load_file(hart, bus)?,
            EFI_FID_OPEN_PROTOCOL => self.handle_open_protocol(hart, bus)?,
            EFI_FID_CLOSE_PROTOCOL => self.handle_close_protocol()?,
            EFI_FID_LOCATE_HANDLE_BUFFER => self.handle_locate_handle_buffer(hart, bus)?,
            EFI_FID_LOCATE_HANDLE => self.handle_locate_handle(hart, bus)?,
            EFI_FID_LOCATE_DEVICE_PATH => self.handle_locate_device_path(hart, bus)?,
            EFI_FID_UNSUPPORTED => EFI_STATUS_UNSUPPORTED,
            _ => EFI_STATUS_UNSUPPORTED,
        };
        hart.regs[10] = status;
        if self.trace {
            eprintln!("EFI return {} status=0x{:x}", fid_name(fid), status);
        }
        Ok(())
    }

    fn handle_allocate_pages(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let alloc_type = hart.regs[10];
        let mem_type = hart.regs[11] as u32;
        let pages = hart.regs[12];
        let mem_ptr = hart.regs[13];
        if mem_ptr == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        let size = pages.saturating_mul(4096);
        let addr = match alloc_type {
            0 => {
                // AllocateAnyPages: top-down from alloc_next.
                let new_next = self.alloc_next.saturating_sub(size);
                if new_next < self.alloc_bottom || new_next >= self.alloc_top {
                    return Ok(EFI_STATUS_OUT_OF_RESOURCES);
                }
                let addr = align_down(new_next, 4096);
                self.alloc_next = addr;
                addr
            }
            1 => {
                // AllocateMaxAddress: allocate below or at the requested max.
                let max_addr = read_u64(bus, mem_ptr)?;
                let mut top = self.alloc_next;
                if max_addr.saturating_add(1) < top {
                    top = align_down(max_addr.saturating_add(1), 4096);
                }
                let new_next = top.saturating_sub(size);
                if new_next < self.alloc_bottom || new_next >= self.alloc_top {
                    return Ok(EFI_STATUS_OUT_OF_RESOURCES);
                }
                let addr = align_down(new_next, 4096);
                self.alloc_next = addr;
                addr
            }
            2 => {
                // AllocateAddress: allocate at the requested address.
                let req = read_u64(bus, mem_ptr)?;
                let addr = align_down(req, 4096);
                let end = addr.saturating_add(size);
                if addr < self.alloc_bottom || end > self.alloc_top {
                    return Ok(EFI_STATUS_OUT_OF_RESOURCES);
                }
                addr
            }
            _ => return Ok(EFI_STATUS_INVALID_PARAMETER),
        };
        write_u64(bus, mem_ptr, addr)?;
        self.update_mem_map(addr, size, mem_type);
        self.map_key = self.map_key.wrapping_add(1);
        if self.trace {
            eprintln!("EFI AllocatePages: pages={} -> 0x{:016x}", pages, addr);
        }
        Ok(EFI_STATUS_SUCCESS)
    }

    fn handle_allocate_pool(&mut self, _hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let pool_type = _hart.regs[10] as u32;
        let size = _hart.regs[11];
        let mem_ptr = _hart.regs[12];
        if mem_ptr == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        let size_aligned = align_up(size, 8);
        let next = align_up(self.pool_next, 8);
        let end = next.saturating_add(size_aligned);
        if end >= self.alloc_next {
            return Ok(EFI_STATUS_OUT_OF_RESOURCES);
        }
        self.pool_next = end;
        write_u64(bus, mem_ptr, next)?;
        self.update_mem_map(next, size_aligned, pool_type);
        self.map_key = self.map_key.wrapping_add(1);
        if self.trace {
            eprintln!("EFI AllocatePool: size={} -> 0x{:016x}", size, next);
        }
        Ok(EFI_STATUS_SUCCESS)
    }

    fn handle_get_memory_map(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let size_ptr = hart.regs[10];
        let map_ptr = hart.regs[11];
        let key_ptr = hart.regs[12];
        let desc_size_ptr = hart.regs[13];
        let desc_ver_ptr = hart.regs[14];

        if size_ptr == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        let required = (self.mem_map.len() as u64).saturating_mul(self.desc_size);
        let provided = read_u64(bus, size_ptr)?;
        if map_ptr == 0 || provided < required {
            write_u64(bus, size_ptr, required)?;
            if desc_size_ptr != 0 {
                write_u64(bus, desc_size_ptr, self.desc_size)?;
            }
            if desc_ver_ptr != 0 {
                write_u32(bus, desc_ver_ptr, self.desc_version)?;
            }
            if self.trace {
                let read_back = read_u64(bus, size_ptr).unwrap_or(0);
                eprintln!(
                    "EFI GetMemoryMap: buffer too small (have {}, need {}) size_ptr=0x{:016x} read_back={}",
                    provided,
                    required,
                    size_ptr,
                    read_back
                );
            }
            return Ok(EFI_STATUS_BUFFER_TOO_SMALL);
        }

        let mut offset = 0u64;
        for desc in &self.mem_map {
            write_u32(bus, map_ptr + offset, desc.ty)?;
            write_u32(bus, map_ptr + offset + 4, 0)?;
            write_u64(bus, map_ptr + offset + 8, desc.phys_start)?;
            write_u64(bus, map_ptr + offset + 16, 0)?;
            write_u64(bus, map_ptr + offset + 24, desc.num_pages)?;
            write_u64(bus, map_ptr + offset + 32, desc.attr)?;
            offset += self.desc_size;
        }

        write_u64(bus, size_ptr, required)?;
        if key_ptr != 0 {
            write_u64(bus, key_ptr, self.map_key)?;
        }
        if desc_size_ptr != 0 {
            write_u64(bus, desc_size_ptr, self.desc_size)?;
        }
        if desc_ver_ptr != 0 {
            write_u32(bus, desc_ver_ptr, self.desc_version)?;
        }
        if self.trace {
            eprintln!("EFI GetMemoryMap: entries={} key={}", self.mem_map.len(), self.map_key);
        }
        Ok(EFI_STATUS_SUCCESS)
    }

    fn handle_exit_boot_services(&mut self, hart: &mut Hart, _bus: &mut dyn Bus) -> Result<u64, Trap> {
        let map_key = hart.regs[11];
        if self.trace {
            eprintln!("EFI ExitBootServices: key={} expected={}", map_key, self.map_key);
        }
        if map_key != self.map_key {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        Ok(EFI_STATUS_SUCCESS)
    }

    fn handle_free_pages(&mut self, hart: &mut Hart) -> Result<u64, Trap> {
        let addr = hart.regs[10];
        let pages = hart.regs[11];
        if addr == 0 || pages == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        self.update_mem_map(addr, pages.saturating_mul(4096), EFI_MEMORY_CONVENTIONAL);
        self.map_key = self.map_key.wrapping_add(1);
        if self.trace {
            eprintln!("EFI FreePages: pages={} addr=0x{:016x}", pages, addr);
        }
        Ok(EFI_STATUS_SUCCESS)
    }

    fn update_mem_map(&mut self, start: u64, len: u64, ty: u32) {
        let start = align_down(start, 4096);
        let end = align_up(start.saturating_add(len), 4096);
        if start >= end {
            return;
        }

        let mut touched = false;
        let mut next_map: Vec<EfiMemDesc> = Vec::with_capacity(self.mem_map.len() + 4);
        for desc in &self.mem_map {
            let desc_start = desc.phys_start;
            let desc_end = desc_start.saturating_add(desc.num_pages.saturating_mul(4096));
            if end <= desc_start || start >= desc_end {
                next_map.push(*desc);
                continue;
            }

            touched = true;
            if start > desc_start {
                let left_pages = (start - desc_start) / 4096;
                if left_pages != 0 {
                    next_map.push(EfiMemDesc {
                        ty: desc.ty,
                        phys_start: desc_start,
                        num_pages: left_pages,
                        attr: desc.attr,
                    });
                }
            }

            let ovl_start = start.max(desc_start);
            let ovl_end = end.min(desc_end);
            let ovl_pages = (ovl_end.saturating_sub(ovl_start)) / 4096;
            if ovl_pages != 0 {
                next_map.push(EfiMemDesc {
                    ty,
                    phys_start: ovl_start,
                    num_pages: ovl_pages,
                    attr: desc.attr,
                });
            }

            if end < desc_end {
                let right_pages = (desc_end - end) / 4096;
                if right_pages != 0 {
                    next_map.push(EfiMemDesc {
                        ty: desc.ty,
                        phys_start: end,
                        num_pages: right_pages,
                        attr: desc.attr,
                    });
                }
            }
        }
        if !touched {
            next_map.push(EfiMemDesc {
                ty,
                phys_start: start,
                num_pages: (end - start) / 4096,
                attr: 0,
            });
        }
        next_map.sort_by_key(|d| d.phys_start);

        let mut merged: Vec<EfiMemDesc> = Vec::with_capacity(next_map.len());
        for desc in next_map {
            if desc.num_pages == 0 {
                continue;
            }
            if let Some(last) = merged.last_mut() {
                let last_end = last
                    .phys_start
                    .saturating_add(last.num_pages.saturating_mul(4096));
                if last.ty == desc.ty && last.attr == desc.attr && last_end == desc.phys_start {
                    last.num_pages = last.num_pages.saturating_add(desc.num_pages);
                    continue;
                }
            }
            merged.push(desc);
        }
        self.mem_map = merged;
    }

    fn handle_copy_mem(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let dst = hart.regs[10];
        let src = hart.regs[11];
        let len = hart.regs[12];
        if dst == 0 || src == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        if len == 0 {
            return Ok(EFI_STATUS_SUCCESS);
        }
        let src_end = src.saturating_add(len);
        if dst > src && dst < src_end {
            // Overlapping regions: copy backwards to preserve data.
            let mut i = len;
            while i > 0 {
                i -= 1;
                let b = bus.read_u8(0, src + i, AccessType::Debug)?;
                bus.write_u8(0, dst + i, b, AccessType::Debug)?;
            }
        } else {
            for i in 0..len {
                let b = bus.read_u8(0, src + i, AccessType::Debug)?;
                bus.write_u8(0, dst + i, b, AccessType::Debug)?;
            }
        }
        Ok(EFI_STATUS_SUCCESS)
    }

    fn handle_set_mem(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let dst = hart.regs[10];
        let len = hart.regs[11];
        let val = hart.regs[12] as u8;
        if dst == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        for i in 0..len {
            bus.write_u8(0, dst + i, val, AccessType::Debug)?;
        }
        Ok(EFI_STATUS_SUCCESS)
    }

    fn handle_calc_crc32(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let data = hart.regs[10];
        let len = hart.regs[11];
        let out = hart.regs[12];
        if data == 0 || out == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        let mut crc = 0xffff_ffffu32;
        for i in 0..len {
            let b = bus.read_u8(0, data + i, AccessType::Debug)? as u32;
            crc ^= b;
            for _ in 0..8 {
                if (crc & 1) != 0 {
                    crc = (crc >> 1) ^ 0xedb8_8320;
                } else {
                    crc >>= 1;
                }
            }
        }
        crc ^= 0xffff_ffff;
        bus.write_u32(0, out, crc, AccessType::Debug)?;
        Ok(EFI_STATUS_SUCCESS)
    }

    fn handle_conout_output_string(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let str_ptr = hart.regs[11];
        if str_ptr == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        // Render EFI SimpleTextOutput strings in orange so they are visually
        // distinct from emulated UART output.
        const EFI_ORANGE: &str = "\x1b[38;5;214m";
        const ANSI_RESET: &str = "\x1b[0m";
        print!("{EFI_ORANGE}");
        let mut addr = str_ptr;
        loop {
            let ch = bus.read_u16(0, addr, AccessType::Debug)?;
            if ch == 0 {
                break;
            }
            let byte = if ch < 0x80 { ch as u8 } else { b'?' };
            print!("{}", byte as char);
            addr = addr.wrapping_add(2);
        }
        print!("{ANSI_RESET}");
        Ok(EFI_STATUS_SUCCESS)
    }

    fn handle_get_boot_hartid(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let out_ptr = hart.regs[11];
        if out_ptr == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        write_u64(bus, out_ptr, 0)?;
        Ok(EFI_STATUS_SUCCESS)
    }

    fn handle_get_fdt(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let out_ptr = hart.regs[11];
        let size_ptr = hart.regs[12];
        if out_ptr == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        if self.dtb_addr == 0 {
            return Ok(EFI_STATUS_NOT_FOUND);
        }
        write_u64(bus, out_ptr, self.dtb_addr)?;
        if size_ptr != 0 {
            write_u64(bus, size_ptr, self.dtb_size)?;
        }
        Ok(EFI_STATUS_SUCCESS)
    }

    fn handle_load_file(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let buf_size_ptr = hart.regs[13];
        let buf_ptr = hart.regs[14];
        if buf_size_ptr == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        if self.initrd_addr == 0 || self.initrd_size == 0 {
            return Ok(EFI_STATUS_NOT_FOUND);
        }
        let mut provided = read_u64(bus, buf_size_ptr)?;
        if buf_ptr == 0 || provided < self.initrd_size {
            write_u64(bus, buf_size_ptr, self.initrd_size)?;
            return Ok(EFI_STATUS_BUFFER_TOO_SMALL);
        }
        // Copy initrd into provided buffer.
        for i in 0..self.initrd_size {
            let b = bus.read_u8(0, self.initrd_addr + i, AccessType::Debug)?;
            bus.write_u8(0, buf_ptr + i, b, AccessType::Debug)?;
        }
        provided = self.initrd_size;
        write_u64(bus, buf_size_ptr, provided)?;
        Ok(EFI_STATUS_SUCCESS)
    }

    fn protocol_interface(&self, handle: u64, guid: [u8; 16]) -> Option<u64> {
        if handle == self.image_handle && guid == EFI_GUID_LOADED_IMAGE {
            return Some(self.loaded_image);
        }
        if handle == self.image_handle && guid == EFI_GUID_RISCV_BOOT_PROTOCOL {
            return Some(self.riscv_boot_proto);
        }
        if handle == self.image_handle && guid == EFI_GUID_RISCV_FDT_PROTOCOL {
            return Some(self.riscv_fdt_proto);
        }
        if (handle == self.image_handle || handle == self.initrd_handle) && guid == EFI_GUID_LOAD_FILE_PROTOCOL {
            return Some(self.load_file_proto);
        }
        if (handle == self.image_handle || handle == self.initrd_handle) && guid == EFI_GUID_LOAD_FILE2_PROTOCOL {
            return Some(self.load_file2_proto);
        }
        if handle == self.initrd_handle && guid == EFI_GUID_DEVICE_PATH_PROTOCOL {
            return Some(self.initrd_devpath);
        }
        None
    }

    fn handles_for_protocol(&self, guid: Option<[u8; 16]>) -> Vec<u64> {
        let mut handles = Vec::new();
        match guid {
            None => {
                handles.push(self.image_handle);
                if self.initrd_size != 0 {
                    handles.push(self.initrd_handle);
                }
            }
            Some(g) => {
                if g == EFI_GUID_LOAD_FILE_PROTOCOL || g == EFI_GUID_LOAD_FILE2_PROTOCOL || g == EFI_GUID_DEVICE_PATH_PROTOCOL {
                    if self.initrd_size != 0 {
                        handles.push(self.initrd_handle);
                    }
                } else if self.protocol_interface(self.image_handle, g).is_some() {
                    handles.push(self.image_handle);
                } else if self.initrd_size != 0 && self.protocol_interface(self.initrd_handle, g).is_some() {
                    handles.push(self.initrd_handle);
                }
            }
        }
        handles
    }

    fn handle_open_protocol(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let handle = hart.regs[10];
        let guid_ptr = hart.regs[11];
        let iface_ptr = hart.regs[12];
        let attrs = hart.regs[15];
        if guid_ptr == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        let guid = read_guid(bus, guid_ptr)?;
        if let Some(iface) = self.protocol_interface(handle, guid) {
            if iface_ptr != 0 {
                write_u64(bus, iface_ptr, iface)?;
                return Ok(EFI_STATUS_SUCCESS);
            }
            if (attrs & EFI_OPEN_PROTOCOL_TEST_PROTOCOL) != 0 {
                return Ok(EFI_STATUS_SUCCESS);
            }
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        Ok(EFI_STATUS_NOT_FOUND)
    }

    fn handle_close_protocol(&mut self) -> Result<u64, Trap> {
        Ok(EFI_STATUS_SUCCESS)
    }

    fn handle_locate_handle_buffer(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let search_type = hart.regs[10];
        let guid_ptr = hart.regs[11];
        let _search_key = hart.regs[12];
        let no_handles_ptr = hart.regs[13];
        let buffer_ptr_ptr = hart.regs[14];
        if no_handles_ptr == 0 || buffer_ptr_ptr == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        if search_type != EFI_LOCATE_SEARCH_ALL_HANDLES
            && search_type != EFI_LOCATE_SEARCH_BY_PROTOCOL
            && search_type != EFI_LOCATE_SEARCH_BY_REGISTER_NOTIFY
        {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        if search_type == EFI_LOCATE_SEARCH_BY_REGISTER_NOTIFY {
            return Ok(EFI_STATUS_UNSUPPORTED);
        }
        let guid = if search_type == EFI_LOCATE_SEARCH_BY_PROTOCOL {
            if guid_ptr == 0 {
                return Ok(EFI_STATUS_INVALID_PARAMETER);
            }
            Some(read_guid(bus, guid_ptr)?)
        } else {
            None
        };
        if self.trace {
            if let Some(g) = guid {
                eprintln!("EFI LocateHandleBuffer: search_type={} guid={:02x?}", search_type, g);
            } else {
                eprintln!("EFI LocateHandleBuffer: search_type={} guid=<none>", search_type);
            }
        }
        let handles = self.handles_for_protocol(guid);
        if handles.is_empty() {
            write_u64(bus, no_handles_ptr, 0)?;
            write_u64(bus, buffer_ptr_ptr, 0)?;
            return Ok(EFI_STATUS_NOT_FOUND);
        }
        let total_bytes = (handles.len() as u64).saturating_mul(8);
        let size_aligned = align_up(total_bytes, 8);
        let next = align_up(self.pool_next, 8);
        let end = next.saturating_add(size_aligned);
        if end >= self.alloc_next {
            return Ok(EFI_STATUS_OUT_OF_RESOURCES);
        }
        self.pool_next = end;
        self.update_mem_map(next, size_aligned, EFI_MEMORY_BOOT_SERVICES_DATA);
        self.map_key = self.map_key.wrapping_add(1);
        for (idx, handle) in handles.iter().enumerate() {
            write_u64(bus, next + (idx as u64) * 8, *handle)?;
        }
        write_u64(bus, no_handles_ptr, handles.len() as u64)?;
        write_u64(bus, buffer_ptr_ptr, next)?;
        Ok(EFI_STATUS_SUCCESS)
    }

    fn handle_locate_handle(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let search_type = hart.regs[10];
        let guid_ptr = hart.regs[11];
        let _search_key = hart.regs[12];
        let buffer_size_ptr = hart.regs[13];
        let buffer_ptr = hart.regs[14];
        if buffer_size_ptr == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        if search_type != EFI_LOCATE_SEARCH_ALL_HANDLES
            && search_type != EFI_LOCATE_SEARCH_BY_PROTOCOL
            && search_type != EFI_LOCATE_SEARCH_BY_REGISTER_NOTIFY
        {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        if search_type == EFI_LOCATE_SEARCH_BY_REGISTER_NOTIFY {
            return Ok(EFI_STATUS_UNSUPPORTED);
        }
        let guid = if search_type == EFI_LOCATE_SEARCH_BY_PROTOCOL {
            if guid_ptr == 0 {
                return Ok(EFI_STATUS_INVALID_PARAMETER);
            }
            Some(read_guid(bus, guid_ptr)?)
        } else {
            None
        };
        let handles = self.handles_for_protocol(guid);
        if handles.is_empty() {
            write_u64(bus, buffer_size_ptr, 0)?;
            return Ok(EFI_STATUS_NOT_FOUND);
        }
        let required = (handles.len() as u64).saturating_mul(8);
        let provided = read_u64(bus, buffer_size_ptr)?;
        if buffer_ptr == 0 || provided < required {
            write_u64(bus, buffer_size_ptr, required)?;
            return Ok(EFI_STATUS_BUFFER_TOO_SMALL);
        }
        for (idx, handle) in handles.iter().enumerate() {
            write_u64(bus, buffer_ptr + (idx as u64) * 8, *handle)?;
        }
        write_u64(bus, buffer_size_ptr, required)?;
        Ok(EFI_STATUS_SUCCESS)
    }

    fn handle_locate_device_path(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let guid_ptr = hart.regs[10];
        let device_path_ptr_ptr = hart.regs[11];
        let handle_ptr = hart.regs[12];
        if guid_ptr == 0 || device_path_ptr_ptr == 0 || handle_ptr == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        let guid = read_guid(bus, guid_ptr)?;
        if self.trace {
            eprintln!("EFI LocateDevicePath: guid={:02x?}", guid);
        }
        if guid == EFI_GUID_DEVICE_PATH_PROTOCOL {
            write_u64(bus, handle_ptr, self.initrd_handle)?;
            write_u64(bus, device_path_ptr_ptr, self.initrd_devpath)?;
            return Ok(EFI_STATUS_SUCCESS);
        }
        if guid == EFI_GUID_LOAD_FILE_PROTOCOL || guid == EFI_GUID_LOAD_FILE2_PROTOCOL {
            if self.initrd_size == 0 {
                return Ok(EFI_STATUS_NOT_FOUND);
            }
            write_u64(bus, handle_ptr, self.initrd_handle)?;
            // Advance the device path to the end node if provided.
            let current = read_u64(bus, device_path_ptr_ptr)?;
            if current != 0 {
                write_u64(bus, device_path_ptr_ptr, self.initrd_devpath)?;
            }
            return Ok(EFI_STATUS_SUCCESS);
        }
        Ok(EFI_STATUS_NOT_FOUND)
    }

    fn handle_handle_protocol(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let handle = hart.regs[10];
        let guid_ptr = hart.regs[11];
        let iface_ptr = hart.regs[12];
        if guid_ptr == 0 || iface_ptr == 0 {
            return Ok(EFI_STATUS_NOT_FOUND);
        }
        let guid = read_guid(bus, guid_ptr)?;
        if self.trace {
            eprintln!("EFI HandleProtocol: handle=0x{:016x} guid={:02x?}", handle, guid);
        }
        if handle == self.image_handle && guid == EFI_GUID_LOADED_IMAGE {
            write_u64(bus, iface_ptr, self.loaded_image)?;
            Ok(EFI_STATUS_SUCCESS)
        } else if handle == self.image_handle && guid == EFI_GUID_RISCV_BOOT_PROTOCOL {
            write_u64(bus, iface_ptr, self.riscv_boot_proto)?;
            Ok(EFI_STATUS_SUCCESS)
        } else if handle == self.image_handle && guid == EFI_GUID_RISCV_FDT_PROTOCOL {
            write_u64(bus, iface_ptr, self.riscv_fdt_proto)?;
            Ok(EFI_STATUS_SUCCESS)
        } else if (handle == self.initrd_handle || handle == self.image_handle)
            && guid == EFI_GUID_LOAD_FILE_PROTOCOL
        {
            write_u64(bus, iface_ptr, self.load_file_proto)?;
            Ok(EFI_STATUS_SUCCESS)
        } else if (handle == self.initrd_handle || handle == self.image_handle)
            && guid == EFI_GUID_LOAD_FILE2_PROTOCOL
        {
            write_u64(bus, iface_ptr, self.load_file2_proto)?;
            Ok(EFI_STATUS_SUCCESS)
        } else if handle == self.initrd_handle && guid == EFI_GUID_DEVICE_PATH_PROTOCOL {
            write_u64(bus, iface_ptr, self.initrd_devpath)?;
            Ok(EFI_STATUS_SUCCESS)
        } else {
            Ok(EFI_STATUS_NOT_FOUND)
        }
    }

    fn handle_locate_protocol(&mut self, hart: &mut Hart, bus: &mut dyn Bus) -> Result<u64, Trap> {
        let guid_ptr = hart.regs[10];
        let iface_ptr = hart.regs[12];
        if guid_ptr == 0 || iface_ptr == 0 {
            return Ok(EFI_STATUS_INVALID_PARAMETER);
        }
        let guid = read_guid(bus, guid_ptr)?;
        if self.trace {
            eprintln!("EFI LocateProtocol: guid={:02x?}", guid);
        }
        if guid == EFI_GUID_LOADED_IMAGE {
            write_u64(bus, iface_ptr, self.loaded_image)?;
            Ok(EFI_STATUS_SUCCESS)
        } else if guid == EFI_GUID_RISCV_BOOT_PROTOCOL {
            write_u64(bus, iface_ptr, self.riscv_boot_proto)?;
            Ok(EFI_STATUS_SUCCESS)
        } else if guid == EFI_GUID_RISCV_FDT_PROTOCOL {
            write_u64(bus, iface_ptr, self.riscv_fdt_proto)?;
            Ok(EFI_STATUS_SUCCESS)
        } else if guid == EFI_GUID_LOAD_FILE_PROTOCOL {
            write_u64(bus, iface_ptr, self.load_file_proto)?;
            Ok(EFI_STATUS_SUCCESS)
        } else if guid == EFI_GUID_LOAD_FILE2_PROTOCOL {
            write_u64(bus, iface_ptr, self.load_file2_proto)?;
            Ok(EFI_STATUS_SUCCESS)
        } else if guid == EFI_GUID_DEVICE_PATH_PROTOCOL {
            write_u64(bus, iface_ptr, self.initrd_devpath)?;
            Ok(EFI_STATUS_SUCCESS)
        } else {
            Ok(EFI_STATUS_NOT_FOUND)
        }
    }
}

pub fn build_efi_blob(
    base: u64,
    ram_base: u64,
    ram_size: u64,
    kernel_range: (u64, u64),
    kernel_data_start: Option<u64>,
    bootargs: Option<&str>,
    initrd_range: Option<(u64, u64)>,
    dtb_range: Option<(u64, u64)>,
    alloc_bottom: u64,
    alloc_top: u64,
) -> EfiBuild {
    let mut blob = vec![0u8; EFI_REGION_SIZE as usize];

    const OFF_IMAGE_HANDLE: u64 = 0x0000;
    const OFF_SYSTEM_TABLE: u64 = 0x0100;
    const OFF_BOOT_SERVICES: u64 = 0x0200;
    const OFF_RUNTIME_SERVICES: u64 = 0x0380;
    const OFF_CONOUT: u64 = 0x0410;
    const OFF_RISCV_BOOT: u64 = 0x0460;
    const OFF_RISCV_FDT: u64 = 0x0470;
    const OFF_LOAD_FILE: u64 = 0x0480;
    const OFF_LOAD_FILE2: u64 = 0x0490;
    const OFF_CONFIG_TABLE: u64 = 0x0500;
    const OFF_LOADED_IMAGE: u64 = 0x0600;
    const OFF_VENDOR_STR: u64 = 0x0700;
    const OFF_INITRD_HANDLE: u64 = 0x0800;
    const OFF_INITRD_DEVPATH: u64 = 0x0810;
    const OFF_LOAD_OPTIONS: u64 = 0x0900;
    const OFF_CODE: u64 = 0x1000;

    let image_handle = base + OFF_IMAGE_HANDLE;
    let system_table = base + OFF_SYSTEM_TABLE;
    let boot_services = base + OFF_BOOT_SERVICES;
    let runtime_services = base + OFF_RUNTIME_SERVICES;
    let conout = base + OFF_CONOUT;
    let conout_handle = image_handle;
    let riscv_boot_proto = base + OFF_RISCV_BOOT;
    let riscv_fdt_proto = base + OFF_RISCV_FDT;
    let load_file_proto = base + OFF_LOAD_FILE;
    let load_file2_proto = base + OFF_LOAD_FILE2;
    let config_table = base + OFF_CONFIG_TABLE;
    let loaded_image = base + OFF_LOADED_IMAGE;
    let vendor_str = base + OFF_VENDOR_STR;
    let initrd_handle = base + OFF_INITRD_HANDLE;
    let initrd_devpath = base + OFF_INITRD_DEVPATH;
    let load_options = base + OFF_LOAD_OPTIONS;
    let code_base = base + OFF_CODE;

    write_u64_to(&mut blob, OFF_IMAGE_HANDLE, image_handle);

    let vendor_utf16: [u16; 7] = [b'K' as u16, b'R' as u16, b'I' as u16, b'S' as u16, b'C' as u16, b'V' as u16, 0];
    for (i, ch) in vendor_utf16.iter().enumerate() {
        write_u16_to(&mut blob, OFF_VENDOR_STR + (i as u64) * 2, *ch);
    }

    // Build a simple initrd vendor device path: MEDIA_VENDOR + END.
    write_u8_to(&mut blob, OFF_INITRD_DEVPATH + 0, 0x04); // MEDIA_DEVICE_PATH
    write_u8_to(&mut blob, OFF_INITRD_DEVPATH + 1, 0x03); // MEDIA_VENDOR_DP
    write_u16_to(&mut blob, OFF_INITRD_DEVPATH + 2, 0x0014); // length
    write_guid_to(&mut blob, OFF_INITRD_DEVPATH + 4, LINUX_EFI_INITRD_MEDIA_GUID);
    write_u8_to(&mut blob, OFF_INITRD_DEVPATH + 20, 0x7f); // END_DEVICE_PATH
    write_u8_to(&mut blob, OFF_INITRD_DEVPATH + 21, 0xff);
    write_u16_to(&mut blob, OFF_INITRD_DEVPATH + 22, 0x0004);

    let mut load_options_size = 0u32;
    if let Some(args) = bootargs {
        let mut utf16: Vec<u16> = args.encode_utf16().collect();
        utf16.push(0);
        let bytes_len = utf16.len().saturating_mul(2);
        if OFF_LOAD_OPTIONS as usize + bytes_len <= OFF_CODE as usize {
            for (i, ch) in utf16.iter().enumerate() {
                write_u16_to(&mut blob, OFF_LOAD_OPTIONS + (i as u64) * 2, *ch);
            }
            load_options_size = bytes_len as u32;
        }
    }

    let mut code = Vec::new();
    let stub_unsupported = emit_stub(&mut code, code_base, EFI_FID_UNSUPPORTED);
    let stub_alloc_pages = emit_stub(&mut code, code_base, EFI_FID_ALLOCATE_PAGES);
    let stub_free_pages = emit_stub(&mut code, code_base, EFI_FID_FREE_PAGES);
    let stub_get_memory_map = emit_stub(&mut code, code_base, EFI_FID_GET_MEMORY_MAP);
    let stub_alloc_pool = emit_stub(&mut code, code_base, EFI_FID_ALLOCATE_POOL);
    let stub_free_pool = emit_stub(&mut code, code_base, EFI_FID_FREE_POOL);
    let stub_exit_boot_services = emit_stub(&mut code, code_base, EFI_FID_EXIT_BOOT_SERVICES);
    let stub_handle_protocol = emit_stub(&mut code, code_base, EFI_FID_HANDLE_PROTOCOL);
    let stub_locate_protocol = emit_stub(&mut code, code_base, EFI_FID_LOCATE_PROTOCOL);
    let stub_set_watchdog = emit_stub(&mut code, code_base, EFI_FID_SET_WATCHDOG_TIMER);
    let stub_copy_mem = emit_stub(&mut code, code_base, EFI_FID_COPY_MEM);
    let stub_set_mem = emit_stub(&mut code, code_base, EFI_FID_SET_MEM);
    let stub_crc32 = emit_stub(&mut code, code_base, EFI_FID_CALC_CRC32);
    let stub_install_config = emit_stub(&mut code, code_base, EFI_FID_INSTALL_CONFIG_TABLE);
    let stub_conout_output = emit_stub(&mut code, code_base, EFI_FID_CONOUT_OUTPUT_STRING);
    let stub_boot_hartid = emit_stub(&mut code, code_base, EFI_FID_GET_BOOT_HARTID);
    let stub_get_fdt = emit_stub(&mut code, code_base, EFI_FID_GET_FDT);
    let stub_load_file = emit_stub(&mut code, code_base, EFI_FID_LOAD_FILE);
    let stub_open_protocol = emit_stub(&mut code, code_base, EFI_FID_OPEN_PROTOCOL);
    let stub_close_protocol = emit_stub(&mut code, code_base, EFI_FID_CLOSE_PROTOCOL);
    let stub_locate_handle_buffer = emit_stub(&mut code, code_base, EFI_FID_LOCATE_HANDLE_BUFFER);
    let stub_locate_handle = emit_stub(&mut code, code_base, EFI_FID_LOCATE_HANDLE);
    let stub_locate_device_path = emit_stub(&mut code, code_base, EFI_FID_LOCATE_DEVICE_PATH);

    let mut bs_funcs = Vec::with_capacity(44);
    bs_funcs.push(stub_unsupported); // RaiseTPL
    bs_funcs.push(stub_unsupported); // RestoreTPL
    bs_funcs.push(stub_alloc_pages); // AllocatePages
    bs_funcs.push(stub_free_pages); // FreePages
    bs_funcs.push(stub_get_memory_map); // GetMemoryMap
    bs_funcs.push(stub_alloc_pool); // AllocatePool
    bs_funcs.push(stub_free_pool); // FreePool
    bs_funcs.push(stub_unsupported); // CreateEvent
    bs_funcs.push(stub_unsupported); // SetTimer
    bs_funcs.push(stub_unsupported); // WaitForEvent
    bs_funcs.push(stub_unsupported); // SignalEvent
    bs_funcs.push(stub_unsupported); // CloseEvent
    bs_funcs.push(stub_unsupported); // CheckEvent
    bs_funcs.push(stub_unsupported); // InstallProtocolInterface
    bs_funcs.push(stub_unsupported); // ReinstallProtocolInterface
    bs_funcs.push(stub_unsupported); // UninstallProtocolInterface
    bs_funcs.push(stub_handle_protocol); // HandleProtocol
    bs_funcs.push(0); // Reserved
    bs_funcs.push(stub_unsupported); // RegisterProtocolNotify
    bs_funcs.push(stub_locate_handle); // LocateHandle
    bs_funcs.push(stub_locate_device_path); // LocateDevicePath
    bs_funcs.push(stub_install_config); // InstallConfigurationTable
    bs_funcs.push(stub_unsupported); // LoadImage
    bs_funcs.push(stub_unsupported); // StartImage
    bs_funcs.push(stub_unsupported); // Exit
    bs_funcs.push(stub_unsupported); // UnloadImage
    bs_funcs.push(stub_exit_boot_services); // ExitBootServices
    bs_funcs.push(stub_unsupported); // GetNextMonotonicCount
    bs_funcs.push(stub_unsupported); // Stall
    bs_funcs.push(stub_set_watchdog); // SetWatchdogTimer
    bs_funcs.push(stub_unsupported); // ConnectController
    bs_funcs.push(stub_unsupported); // DisconnectController
    bs_funcs.push(stub_open_protocol); // OpenProtocol
    bs_funcs.push(stub_close_protocol); // CloseProtocol
    bs_funcs.push(stub_unsupported); // OpenProtocolInformation
    bs_funcs.push(stub_unsupported); // ProtocolsPerHandle
    bs_funcs.push(stub_locate_handle_buffer); // LocateHandleBuffer
    bs_funcs.push(stub_locate_protocol); // LocateProtocol
    bs_funcs.push(stub_unsupported); // InstallMultipleProtocolInterfaces
    bs_funcs.push(stub_unsupported); // UninstallMultipleProtocolInterfaces
    bs_funcs.push(stub_crc32); // CalculateCrc32
    bs_funcs.push(stub_copy_mem); // CopyMem
    bs_funcs.push(stub_set_mem); // SetMem
    bs_funcs.push(stub_unsupported); // CreateEventEx

    write_u64_to(&mut blob, OFF_BOOT_SERVICES, EFI_SIG_BOOT_SERVICES);
    write_u32_to(&mut blob, OFF_BOOT_SERVICES + 8, 2);
    write_u32_to(&mut blob, OFF_BOOT_SERVICES + 12, EFI_BOOT_SERVICES_SIZE);
    write_u32_to(&mut blob, OFF_BOOT_SERVICES + 16, 0);
    write_u32_to(&mut blob, OFF_BOOT_SERVICES + 20, 0);

    let mut bs_off = OFF_BOOT_SERVICES + EFI_TABLE_HEADER_SIZE as u64;
    for func in bs_funcs {
        write_u64_to(&mut blob, bs_off, func);
        bs_off += 8;
    }

    write_u64_to(&mut blob, OFF_RUNTIME_SERVICES, EFI_SIG_RUNTIME_SERVICES);
    write_u32_to(&mut blob, OFF_RUNTIME_SERVICES + 8, 2);
    write_u32_to(&mut blob, OFF_RUNTIME_SERVICES + 12, EFI_RUNTIME_SERVICES_SIZE);
    write_u32_to(&mut blob, OFF_RUNTIME_SERVICES + 16, 0);
    write_u32_to(&mut blob, OFF_RUNTIME_SERVICES + 20, 0);
    let mut rt_off = OFF_RUNTIME_SERVICES + EFI_TABLE_HEADER_SIZE as u64;
    for _ in 0..14 {
        write_u64_to(&mut blob, rt_off, stub_unsupported);
        rt_off += 8;
    }

    let mut conout_off = OFF_CONOUT;
    write_u64_to(&mut blob, conout_off, stub_unsupported); // Reset
    conout_off += 8;
    write_u64_to(&mut blob, conout_off, stub_conout_output); // OutputString
    conout_off += 8;
    write_u64_to(&mut blob, conout_off, stub_unsupported); // TestString
    conout_off += 8;
    write_u64_to(&mut blob, conout_off, stub_unsupported); // QueryMode
    conout_off += 8;
    write_u64_to(&mut blob, conout_off, stub_unsupported); // SetMode
    conout_off += 8;
    write_u64_to(&mut blob, conout_off, stub_unsupported); // SetAttribute
    conout_off += 8;
    write_u64_to(&mut blob, conout_off, stub_unsupported); // ClearScreen
    conout_off += 8;
    write_u64_to(&mut blob, conout_off, stub_unsupported); // SetCursorPosition
    conout_off += 8;
    write_u64_to(&mut blob, conout_off, stub_unsupported); // EnableCursor
    conout_off += 8;
    write_u64_to(&mut blob, conout_off, 0); // Mode

    // RISC-V boot protocol: store GetBootHartId at both offset 0 and 8
    // to tolerate different struct layouts used by EFI stubs.
    write_u64_to(&mut blob, OFF_RISCV_BOOT, stub_boot_hartid);
    write_u64_to(&mut blob, OFF_RISCV_BOOT + 8, stub_boot_hartid);
    // RISC-V FDT protocol: store GetFdt at both offset 0 and 8.
    write_u64_to(&mut blob, OFF_RISCV_FDT, stub_get_fdt);
    write_u64_to(&mut blob, OFF_RISCV_FDT + 8, stub_get_fdt);
    // LoadFile protocols: store LoadFile at both offset 0 and 8.
    write_u64_to(&mut blob, OFF_LOAD_FILE, stub_load_file);
    write_u64_to(&mut blob, OFF_LOAD_FILE + 8, stub_load_file);
    write_u64_to(&mut blob, OFF_LOAD_FILE2, stub_load_file);
    write_u64_to(&mut blob, OFF_LOAD_FILE2 + 8, stub_load_file);

    write_u64_to(&mut blob, OFF_SYSTEM_TABLE, EFI_SIG_SYSTEM_TABLE);
    write_u32_to(&mut blob, OFF_SYSTEM_TABLE + 8, 2);
    write_u32_to(&mut blob, OFF_SYSTEM_TABLE + 12, EFI_SYSTEM_TABLE_SIZE);
    write_u32_to(&mut blob, OFF_SYSTEM_TABLE + 16, 0);
    write_u32_to(&mut blob, OFF_SYSTEM_TABLE + 20, 0);
    write_u64_to(&mut blob, OFF_SYSTEM_TABLE + 24, vendor_str);
    write_u32_to(&mut blob, OFF_SYSTEM_TABLE + 32, 1);
    write_u32_to(&mut blob, OFF_SYSTEM_TABLE + 36, 0);
    write_u64_to(&mut blob, OFF_SYSTEM_TABLE + 40, 0);
    write_u64_to(&mut blob, OFF_SYSTEM_TABLE + 48, 0);
    write_u64_to(&mut blob, OFF_SYSTEM_TABLE + 56, conout_handle);
    write_u64_to(&mut blob, OFF_SYSTEM_TABLE + 64, conout);
    write_u64_to(&mut blob, OFF_SYSTEM_TABLE + 72, conout_handle);
    write_u64_to(&mut blob, OFF_SYSTEM_TABLE + 80, conout);
    write_u64_to(&mut blob, OFF_SYSTEM_TABLE + 88, runtime_services);
    write_u64_to(&mut blob, OFF_SYSTEM_TABLE + 96, boot_services);
    write_u64_to(&mut blob, OFF_SYSTEM_TABLE + 104, 1);
    write_u64_to(&mut blob, OFF_SYSTEM_TABLE + 112, config_table);

    let mut dtb_addr = 0u64;
    let mut dtb_size = 0u64;
    if let Some(dtb_range) = dtb_range {
        write_guid_to(&mut blob, OFF_CONFIG_TABLE, EFI_GUID_FDT);
        write_u64_to(&mut blob, OFF_CONFIG_TABLE + 16, dtb_range.0);
        dtb_addr = dtb_range.0;
        dtb_size = dtb_range.1.saturating_sub(dtb_range.0);
    }

    let mut initrd_addr = 0u64;
    let mut initrd_size = 0u64;
    if let Some(range) = initrd_range {
        initrd_addr = range.0;
        initrd_size = range.1.saturating_sub(range.0);
    }

    write_u32_to(&mut blob, OFF_LOADED_IMAGE + 0, 0x0001_0000);
    write_u32_to(&mut blob, OFF_LOADED_IMAGE + 4, 0);
    write_u64_to(&mut blob, OFF_LOADED_IMAGE + 8, 0);
    write_u64_to(&mut blob, OFF_LOADED_IMAGE + 16, system_table);
    write_u64_to(&mut blob, OFF_LOADED_IMAGE + 24, 0);
    write_u64_to(&mut blob, OFF_LOADED_IMAGE + 32, 0);
    write_u64_to(&mut blob, OFF_LOADED_IMAGE + 40, 0);
    write_u32_to(&mut blob, OFF_LOADED_IMAGE + 48, load_options_size);
    write_u32_to(&mut blob, OFF_LOADED_IMAGE + 52, 0);
    write_u64_to(
        &mut blob,
        OFF_LOADED_IMAGE + 56,
        if load_options_size != 0 { load_options } else { 0 },
    );
    write_u64_to(&mut blob, OFF_LOADED_IMAGE + 64, kernel_range.0);
    write_u64_to(&mut blob, OFF_LOADED_IMAGE + 72, kernel_range.1.saturating_sub(kernel_range.0));
    write_u32_to(&mut blob, OFF_LOADED_IMAGE + 80, EFI_MEMORY_LOADER_CODE);
    write_u32_to(&mut blob, OFF_LOADED_IMAGE + 84, EFI_MEMORY_LOADER_DATA);
    write_u64_to(&mut blob, OFF_LOADED_IMAGE + 88, 0);

    let code_off = OFF_CODE as usize;
    let end_off = code_off + code.len();
    if end_off <= blob.len() {
        blob[code_off..end_off].copy_from_slice(&code);
    }

    let mem_map = build_memory_map(
        ram_base,
        ram_size,
        kernel_range,
        kernel_data_start,
        initrd_range,
        dtb_range,
        (base, base + EFI_REGION_SIZE),
    );
    if env_flag("EFI_MEMMAP_TRACE", false) {
        eprintln!(
            "EFI memmap: ram=[0x{:016x}..0x{:016x}) kernel=[0x{:016x}..0x{:016x})",
            ram_base,
            ram_base + ram_size,
            kernel_range.0,
            kernel_range.1
        );
        for desc in &mem_map {
            eprintln!(
                "  type={} start=0x{:016x} pages={} attr=0x{:x}",
                desc.ty, desc.phys_start, desc.num_pages, desc.attr
            );
        }
    }

    EfiBuild {
        blob,
        image_handle,
        system_table,
        loaded_image,
        initrd_handle,
        initrd_devpath,
        riscv_boot_proto,
        riscv_fdt_proto,
        load_file_proto,
        load_file2_proto,
        dtb_addr,
        dtb_size,
        initrd_addr,
        initrd_size,
        mem_map,
        alloc_bottom,
        alloc_top,
    }
}

fn build_memory_map(
    ram_base: u64,
    ram_size: u64,
    kernel_range: (u64, u64),
    kernel_data_start: Option<u64>,
    initrd_range: Option<(u64, u64)>,
    dtb_range: Option<(u64, u64)>,
    efi_range: (u64, u64),
) -> Vec<EfiMemDesc> {
    let mut reserved: Vec<(u64, u64, u32)> = Vec::new();
    if let Some(mut data_start) = kernel_data_start {
        if data_start < kernel_range.0 {
            data_start = kernel_range.0;
        }
        if data_start > kernel_range.1 {
            data_start = kernel_range.1;
        }
        if data_start > kernel_range.0 && data_start < kernel_range.1 {
            reserved.push((kernel_range.0, data_start, EFI_MEMORY_LOADER_CODE));
            reserved.push((data_start, kernel_range.1, EFI_MEMORY_LOADER_DATA));
        } else {
            reserved.push((kernel_range.0, kernel_range.1, EFI_MEMORY_LOADER_CODE));
        }
    } else {
        reserved.push((kernel_range.0, kernel_range.1, EFI_MEMORY_LOADER_CODE));
    }
    if let Some(range) = initrd_range {
        reserved.push((range.0, range.1, EFI_MEMORY_BOOT_SERVICES_DATA));
    }
    if let Some(range) = dtb_range {
        reserved.push((range.0, range.1, EFI_MEMORY_BOOT_SERVICES_DATA));
    }
    reserved.push((efi_range.0, efi_range.1, EFI_MEMORY_BOOT_SERVICES_DATA));
    reserved.sort_by_key(|r| r.0);

    let mut entries = Vec::new();
    let ram_end = ram_base + ram_size;
    let mut cursor = ram_base;
    for (start, end, ty) in reserved {
        let start = align_down(start, 0x1000);
        let end = align_up(end, 0x1000);
        if start > cursor {
            entries.push(EfiMemDesc {
                ty: EFI_MEMORY_CONVENTIONAL,
                phys_start: cursor,
                num_pages: (start - cursor) / 4096,
                attr: 0,
            });
        }
        if end > start {
            entries.push(EfiMemDesc {
                ty,
                phys_start: start,
                num_pages: (end - start) / 4096,
                attr: 0,
            });
        }
        cursor = end.max(cursor);
    }
    if cursor < ram_end {
        entries.push(EfiMemDesc {
            ty: EFI_MEMORY_CONVENTIONAL,
            phys_start: cursor,
            num_pages: (ram_end - cursor) / 4096,
            attr: 0,
        });
    }
    entries
}

fn emit_stub(code: &mut Vec<u8>, base: u64, fid: u64) -> u64 {
    let addr = base + code.len() as u64;
    let (eid_hi, eid_lo) = split_imm(EFI_EID as u32);
    emit_u32(code, encode_lui(17, eid_hi));
    emit_u32(code, encode_addi(17, 17, eid_lo));
    emit_u32(code, encode_addi(16, 0, fid as i32));
    emit_u32(code, 0x0000_0073); // ECALL
    emit_u32(code, encode_jalr(0, 1, 0)); // RET
    addr
}

fn split_imm(val: u32) -> (i32, i32) {
    let hi = ((val as i64 + 0x800) >> 12) as i32;
    let lo = (val as i32) - (hi << 12);
    (hi, lo)
}

fn encode_lui(rd: u32, imm20: i32) -> u32 {
    ((imm20 as u32) << 12) | (rd << 7) | 0x37
}

fn encode_addi(rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32) << 20) | (rs1 << 15) | (0 << 12) | (rd << 7) | 0x13
}

fn encode_jalr(rd: u32, rs1: u32, imm: i32) -> u32 {
    ((imm as u32) << 20) | (rs1 << 15) | (0 << 12) | (rd << 7) | 0x67
}

fn write_u16_to(buf: &mut [u8], off: u64, val: u16) {
    let off = off as usize;
    buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
}

fn write_u8_to(buf: &mut [u8], off: u64, val: u8) {
    let off = off as usize;
    buf[off] = val;
}

fn write_u32_to(buf: &mut [u8], off: u64, val: u32) {
    let off = off as usize;
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn write_u64_to(buf: &mut [u8], off: u64, val: u64) {
    let off = off as usize;
    buf[off..off + 8].copy_from_slice(&val.to_le_bytes());
}

fn write_guid_to(buf: &mut [u8], off: u64, guid: [u8; 16]) {
    let off = off as usize;
    buf[off..off + 16].copy_from_slice(&guid);
}

fn emit_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn align_up(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    (val + align - 1) & !(align - 1)
}

fn align_down(val: u64, align: u64) -> u64 {
    if align == 0 {
        return val;
    }
    val & !(align - 1)
}

fn env_flag(name: &str, default: bool) -> bool {
    match env::var(name) {
        Ok(val) => {
            let v = val.trim().to_ascii_lowercase();
            !(v == "0" || v == "false" || v == "no")
        }
        Err(_) => default,
    }
}

fn fid_name(fid: u64) -> &'static str {
    match fid {
        EFI_FID_ALLOCATE_PAGES => "AllocatePages",
        EFI_FID_FREE_PAGES => "FreePages",
        EFI_FID_GET_MEMORY_MAP => "GetMemoryMap",
        EFI_FID_ALLOCATE_POOL => "AllocatePool",
        EFI_FID_FREE_POOL => "FreePool",
        EFI_FID_EXIT_BOOT_SERVICES => "ExitBootServices",
        EFI_FID_HANDLE_PROTOCOL => "HandleProtocol",
        EFI_FID_LOCATE_PROTOCOL => "LocateProtocol",
        EFI_FID_SET_WATCHDOG_TIMER => "SetWatchdogTimer",
        EFI_FID_COPY_MEM => "CopyMem",
        EFI_FID_SET_MEM => "SetMem",
        EFI_FID_CALC_CRC32 => "CalculateCrc32",
        EFI_FID_INSTALL_CONFIG_TABLE => "InstallConfigurationTable",
        EFI_FID_CONOUT_OUTPUT_STRING => "OutputString",
        EFI_FID_GET_BOOT_HARTID => "GetBootHartId",
        EFI_FID_GET_FDT => "GetFdt",
        EFI_FID_LOAD_FILE => "LoadFile",
        EFI_FID_OPEN_PROTOCOL => "OpenProtocol",
        EFI_FID_CLOSE_PROTOCOL => "CloseProtocol",
        EFI_FID_LOCATE_HANDLE_BUFFER => "LocateHandleBuffer",
        EFI_FID_LOCATE_HANDLE => "LocateHandle",
        EFI_FID_LOCATE_DEVICE_PATH => "LocateDevicePath",
        EFI_FID_UNSUPPORTED => "Unsupported",
        _ => "Unknown",
    }
}

fn read_u64(bus: &mut dyn Bus, addr: u64) -> Result<u64, Trap> {
    bus.read_u64(0, addr, AccessType::Debug)
}

fn write_u64(bus: &mut dyn Bus, addr: u64, val: u64) -> Result<(), Trap> {
    bus.write_u64(0, addr, val, AccessType::Debug)
}

fn write_u32(bus: &mut dyn Bus, addr: u64, val: u32) -> Result<(), Trap> {
    bus.write_u32(0, addr, val, AccessType::Debug)
}

fn read_guid(bus: &mut dyn Bus, addr: u64) -> Result<[u8; 16], Trap> {
    let mut guid = [0u8; 16];
    for i in 0..16 {
        guid[i] = bus.read_u8(0, addr + i as u64, AccessType::Debug)?;
    }
    Ok(guid)
}
const EFI_GUID_DEVICE_PATH_PROTOCOL: [u8; 16] = [
    0x91, 0x6e, 0x57, 0x09,
    0x3f, 0x6d,
    0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
];
