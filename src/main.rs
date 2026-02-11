mod bus;
mod clint;
mod dev;
mod disas;
mod efi;
mod fdt;
mod hart;
mod csr;
mod isa;
mod pe;
mod sbi;
mod plic;
mod system;
mod trap;

use system::{System, DEFAULT_RAM_BASE, DEFAULT_RAM_SIZE};
use crate::bus::Bus;
use trap::Trap;
use std::env;
use std::fs;

fn print_usage() {
    eprintln!(
        "Usage: riscv_sim <binary> [--steps N] [--load-addr ADDR] [--entry-addr ADDR] [--ram-base ADDR] [--ram-size BYTES] [--dtb FILE] [--dtb-addr ADDR] [--initrd FILE] [--initrd-addr ADDR] [--linux] [--ext EXT] [--bootargs STR] [--trace-traps N] [--trace-instr N] [--no-dump]"
    );
}

fn parse_u64(arg: &str) -> Option<u64> {
    if let Some(hex) = arg.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).ok()
    } else {
        arg.parse::<u64>().ok()
    }
}

fn ext_mask_from_str(arg: &str) -> Option<u64> {
    let mut mask = 0u64;
    for ch in arg.chars() {
        if ch == ',' || ch == ' ' {
            continue;
        }
        let bit = match ch.to_ascii_uppercase() {
            'A' => 0,
            'C' => 2,
            'D' => 3,
            'F' => 5,
            'I' => 8,
            'M' => 12,
            'S' => 18,
            'U' => 20,
            _ => return None,
        };
        mask |= 1u64 << bit;
    }
    if mask == 0 {
        None
    } else {
        Some(mask)
    }
}

fn isa_string_from_mask(mask: u64) -> String {
    let mut s = String::from("rv64i");
    let has = |bit: u64| (mask & (1u64 << bit)) != 0;
    if has(12) {
        s.push('m');
    }
    if has(0) {
        s.push('a');
    }
    if has(5) {
        s.push('f');
    }
    if has(3) {
        s.push('d');
    }
    if has(2) {
        s.push('c');
    }
    s
}

fn align_up(val: u64, align: u64) -> u64 {
    (val + align - 1) & !(align - 1)
}

fn align_down(val: u64, align: u64) -> u64 {
    val & !(align - 1)
}

fn main() {
    let mut args = env::args().skip(1);
    let Some(path) = args.next() else {
        print_usage();
        std::process::exit(1);
    };

    let mut max_steps: Option<u64> = None;
    let mut load_addr: Option<u64> = None;
    let mut entry_addr: Option<u64> = None;
    let mut ram_base: u64 = DEFAULT_RAM_BASE;
    let mut ram_size: usize = DEFAULT_RAM_SIZE;
    let mut dtb_path: Option<String> = None;
    let mut dtb_addr: Option<u64> = None;
    let mut initrd_path: Option<String> = None;
    let mut initrd_addr: Option<u64> = None;
    let mut linux_boot = false;
    let mut ext_mask: Option<u64> = None;
    let mut bootargs: Option<String> = None;
    let mut trace_traps: Option<u64> = None;
    let mut trace_instr: Option<u64> = None;
    let mut dump_state = true;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--steps" => {
                let Some(n) = args.next() else {
                    eprintln!("Missing value for --steps");
                    std::process::exit(1);
                };
                max_steps = n.parse::<u64>().ok();
                if max_steps.is_none() {
                    eprintln!("Invalid --steps value: {n}");
                    std::process::exit(1);
                }
            }
            "--load-addr" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --load-addr");
                    std::process::exit(1);
                };
                load_addr = parse_u64(&val);
                if load_addr.is_none() {
                    eprintln!("Invalid --load-addr value: {val}");
                    std::process::exit(1);
                }
            }
            "--entry-addr" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --entry-addr");
                    std::process::exit(1);
                };
                entry_addr = parse_u64(&val);
                if entry_addr.is_none() {
                    eprintln!("Invalid --entry-addr value: {val}");
                    std::process::exit(1);
                }
            }
            "--ram-base" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --ram-base");
                    std::process::exit(1);
                };
                ram_base = match parse_u64(&val) {
                    Some(v) => v,
                    None => {
                        eprintln!("Invalid --ram-base value: {val}");
                        std::process::exit(1);
                    }
                };
            }
            "--ram-size" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --ram-size");
                    std::process::exit(1);
                };
                ram_size = match parse_u64(&val) {
                    Some(v) => v as usize,
                    None => {
                        eprintln!("Invalid --ram-size value: {val}");
                        std::process::exit(1);
                    }
                };
            }
            "--dtb" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --dtb");
                    std::process::exit(1);
                };
                dtb_path = Some(val);
            }
            "--dtb-addr" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --dtb-addr");
                    std::process::exit(1);
                };
                dtb_addr = parse_u64(&val);
                if dtb_addr.is_none() {
                    eprintln!("Invalid --dtb-addr value: {val}");
                    std::process::exit(1);
                }
            }
            "--initrd" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --initrd");
                    std::process::exit(1);
                };
                initrd_path = Some(val);
            }
            "--initrd-addr" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --initrd-addr");
                    std::process::exit(1);
                };
                initrd_addr = parse_u64(&val);
                if initrd_addr.is_none() {
                    eprintln!("Invalid --initrd-addr value: {val}");
                    std::process::exit(1);
                }
            }
            "--linux" => {
                linux_boot = true;
            }
            "--ext" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --ext");
                    std::process::exit(1);
                };
                ext_mask = ext_mask_from_str(&val);
                if ext_mask.is_none() {
                    eprintln!("Invalid --ext value: {val}");
                    std::process::exit(1);
                }
            }
            "--bootargs" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --bootargs");
                    std::process::exit(1);
                };
                bootargs = Some(val);
            }
            "--trace-traps" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --trace-traps");
                    std::process::exit(1);
                };
                trace_traps = parse_u64(&val);
                if trace_traps.is_none() {
                    eprintln!("Invalid --trace-traps value: {val}");
                    std::process::exit(1);
                }
            }
            "--trace-instr" => {
                let Some(val) = args.next() else {
                    eprintln!("Missing value for --trace-instr");
                    std::process::exit(1);
                };
                trace_instr = parse_u64(&val);
                if trace_instr.is_none() {
                    eprintln!("Invalid --trace-instr value: {val}");
                    std::process::exit(1);
                }
            }
            "--no-dump" => {
                dump_state = false;
            }
            _ => {
                eprintln!("Unknown argument: {arg}");
                print_usage();
                std::process::exit(1);
            }
        }
    }

    let data = match fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Failed to read {}: {e}", path);
            std::process::exit(1);
        }
    };

    let pe_image = pe::parse_pe(&data).ok();
    if pe_image.is_none() && data.len() > ram_size {
        eprintln!("Program too large: {} bytes (ram {} bytes)", data.len(), ram_size);
        std::process::exit(1);
    }

    let default_ext = (1u64 << 8) | (1u64 << 12) | (1u64 << 0) | (1u64 << 2) | (1u64 << 18) | (1u64 << 20);
    let ext_mask = ext_mask.unwrap_or(default_ext);
    let mut system = System::new(1, ram_base, ram_size, ext_mask);
    system.set_trace_traps(trace_traps);
    system.set_trace_instr(trace_instr);
    let load_addr_arg = load_addr;
    let mut load_addr = load_addr_arg.unwrap_or(ram_base);
    let mut image_size = data.len() as u64;
    let mut entry_addr_default = load_addr;
    if let Some(pe) = &pe_image {
        if std::env::var("PE_TRACE").ok().is_some() {
            eprintln!(
                "PE: image_base=0x{:x} entry_rva=0x{:x} size_of_image=0x{:x} sections={}",
                pe.image_base,
                pe.entry_rva,
                pe.size_of_image,
                pe.sections.len()
            );
        }
        let preferred = if pe.image_base == 0 { ram_base } else { pe.image_base };
        load_addr = load_addr_arg.unwrap_or(preferred);
        image_size = pe.size_of_image as u64;
        entry_addr_default = load_addr + pe.entry_rva as u64;
    }
    if load_addr < ram_base || load_addr + image_size > ram_base + ram_size as u64 {
        eprintln!(
            "Image does not fit in RAM at 0x{:016x} (size 0x{:x})",
            load_addr,
            image_size
        );
        std::process::exit(1);
    }
    let entry_addr = entry_addr.unwrap_or(entry_addr_default);
    system.set_reset_pc(entry_addr);
    system.reset();

    let mut exit_code = 0;
    let mut ran = false;

    let kernel_end = load_addr + image_size;
    let mut kernel_data_start: Option<u64> = None;
    if let Some(pe) = &pe_image {
        for sec in &pe.sections {
            if sec.vsize == 0 && sec.raw_size == 0 {
                continue;
            }
            if sec.is_executable() {
                continue;
            }
            let start = load_addr + sec.vaddr;
            kernel_data_start = Some(kernel_data_start.map_or(start, |cur| cur.min(start)));
        }
    }
    let mut load_ok = true;
    if let Some(pe) = &pe_image {
        if load_addr != pe.image_base && pe.base_reloc_size == 0 {
            eprintln!(
                "Warning: PE has no relocations; load_addr 0x{:x} differs from image base 0x{:x}",
                load_addr,
                pe.image_base
            );
        }
        for sec in &pe.sections {
            if sec.raw_size == 0 && sec.vsize == 0 {
                continue;
            }
            let vaddr = load_addr + sec.vaddr;
            if sec.raw_size > 0 {
                let start = sec.raw_ptr as usize;
                let end = start.saturating_add(sec.raw_size as usize).min(data.len());
                if let Err(e) = system.load(vaddr, &data[start..end]) {
                    eprintln!("PE load failed: {:?}", e);
                    load_ok = false;
                    break;
                }
            }
            if sec.vsize > sec.raw_size {
                let zero_len = (sec.vsize - sec.raw_size) as usize;
                let zeros = vec![0u8; zero_len.min(1024 * 1024)];
                let mut offset = 0usize;
                while offset < zero_len {
                    let chunk = (zero_len - offset).min(zeros.len());
                    if let Err(e) = system.load(vaddr + sec.raw_size as u64 + offset as u64, &zeros[..chunk]) {
                        eprintln!("PE BSS load failed: {:?}", e);
                        load_ok = false;
                        break;
                    }
                    offset += chunk;
                }
                if !load_ok {
                    break;
                }
            }
        }
    } else {
        if let Err(e) = system.load(load_addr, &data) {
            eprintln!("Load failed: {:?}", e);
            load_ok = false;
        }
    }

    if load_ok {
        if let Some(pe) = &pe_image {
            if load_addr != pe.image_base && pe.base_reloc_size != 0 {
                let delta = load_addr.wrapping_sub(pe.image_base);
                let mut rva = pe.base_reloc_rva as u64;
                let end = pe.base_reloc_rva as u64 + pe.base_reloc_size as u64;
                while rva < end {
                    let file_off = match pe.rva_to_file_offset(rva as u32) {
                        Some(off) => off,
                        None => break,
                    };
                    if file_off + 8 > data.len() {
                        break;
                    }
                    let page_rva = u32::from_le_bytes([
                        data[file_off],
                        data[file_off + 1],
                        data[file_off + 2],
                        data[file_off + 3],
                    ]);
                    let block_size = u32::from_le_bytes([
                        data[file_off + 4],
                        data[file_off + 5],
                        data[file_off + 6],
                        data[file_off + 7],
                    ]);
                    if block_size < 8 {
                        break;
                    }
                    let entries = (block_size - 8) / 2;
                    for i in 0..entries {
                        let entry_off = file_off + 8 + (i as usize) * 2;
                        if entry_off + 2 > data.len() {
                            break;
                        }
                        let entry = u16::from_le_bytes([data[entry_off], data[entry_off + 1]]);
                        let rtype = entry >> 12;
                        let roff = (entry & 0x0fff) as u64;
                        if rtype == 0 {
                            continue;
                        }
                        let reloc_addr = load_addr + page_rva as u64 + roff;
                        match rtype {
                            0xA => {
                                if let Ok(val) = system.bus.read_u64(0, reloc_addr, crate::bus::AccessType::Debug) {
                                    let _ = system
                                        .bus
                                        .write_u64(0, reloc_addr, val.wrapping_add(delta), crate::bus::AccessType::Debug);
                                }
                            }
                            0x3 => {
                                if let Ok(val) = system.bus.read_u32(0, reloc_addr, crate::bus::AccessType::Debug) {
                                    let _ = system
                                        .bus
                                        .write_u32(0, reloc_addr, val.wrapping_add(delta as u32), crate::bus::AccessType::Debug);
                                }
                            }
                            _ => {}
                        }
                    }
                    rva = rva.wrapping_add(block_size as u64);
                }
            }
        }

        let initrd_data = if let Some(path) = initrd_path {
            match fs::read(&path) {
                Ok(d) => Some(d),
                Err(e) => {
                    eprintln!("Failed to read initrd {}: {e}", path);
                    std::process::exit(1);
                }
            }
        } else {
            None
        };

        let mut initrd_range: Option<(u64, u64)> = None;
        if let Some(initrd) = &initrd_data {
            let top = ram_base + ram_size as u64;
            let size = align_up(initrd.len() as u64, 0x1000);
            let desired = initrd_addr.unwrap_or_else(|| align_down(top.saturating_sub(size), 0x1000));
            let end = desired + initrd.len() as u64;
            if desired < ram_base || end > ram_base + ram_size as u64 {
                eprintln!("Initrd does not fit in RAM at 0x{:016x}", desired);
                std::process::exit(1);
            }
            if !(end <= load_addr || desired >= kernel_end) {
                eprintln!("Initrd overlaps kernel image");
                std::process::exit(1);
            }
            if let Err(e) = system.load(desired, initrd) {
                eprintln!("Initrd load failed: {:?}", e);
                std::process::exit(1);
            }
            initrd_range = Some((desired, desired + initrd.len() as u64));
        }

        let dtb_data = if let Some(path) = dtb_path {
            match fs::read(&path) {
                Ok(d) => Some(d),
                Err(e) => {
                    eprintln!("Failed to read dtb {}: {e}", path);
                    std::process::exit(1);
                }
            }
        } else if linux_boot {
            let isa = isa_string_from_mask(ext_mask);
            Some(fdt::build_virt_dtb(
                1,
                ram_base,
                ram_size as u64,
                &isa,
                bootargs.as_deref(),
                initrd_range,
            ))
        } else {
            None
        };
        if let Ok(path) = std::env::var("DUMP_DTB") {
            if let Some(dtb) = &dtb_data {
                if let Err(e) = fs::write(&path, dtb) {
                    eprintln!("Failed to write dtb {}: {e}", path);
                } else {
                    eprintln!("Wrote dtb to {}", path);
                }
            }
        }

        let mut dtb_load_addr = 0u64;
        if let Some(dtb) = &dtb_data {
            let desired = dtb_addr.unwrap_or_else(|| {
                let top = initrd_range.map(|(start, _)| start).unwrap_or(ram_base + ram_size as u64);
                let size = align_up(dtb.len() as u64, 0x1000);
                align_down(top.saturating_sub(size), 0x1000)
            });
            let dtb_end = desired + dtb.len() as u64;
            let kernel_end = load_addr + image_size;
            if let Some((initrd_start, initrd_end)) = initrd_range {
                if !(dtb_end <= initrd_start || desired >= initrd_end) {
                    eprintln!("DTB overlaps initrd");
                    std::process::exit(1);
                }
            }
            if desired < ram_base || dtb_end > ram_base + ram_size as u64 {
                eprintln!("DTB does not fit in RAM at 0x{:016x}", desired);
                std::process::exit(1);
            }
            if !(dtb_end <= load_addr || desired >= kernel_end) {
                eprintln!("DTB overlaps kernel image");
                std::process::exit(1);
            }
            if let Err(e) = system.load(desired, dtb) {
                eprintln!("DTB load failed: {:?}", e);
                std::process::exit(1);
            }
            dtb_load_addr = desired;
        }

        if linux_boot {
            if dtb_load_addr == 0 {
                eprintln!("--linux requires --dtb or auto-generated DTB");
                std::process::exit(1);
            }
            if pe_image.is_some() {
                let dtb_len = dtb_data.as_ref().map(|d| d.len()).unwrap_or(0);
                let dtb_range = if dtb_len == 0 {
                    None
                } else {
                    Some((dtb_load_addr, dtb_load_addr + dtb_len as u64))
                };
                let mut top = ram_base + ram_size as u64;
                if let Some((initrd_start, _)) = initrd_range {
                    top = top.min(initrd_start);
                }
                if dtb_load_addr != 0 {
                    top = top.min(dtb_load_addr);
                }
                let efi_size = efi::EFI_REGION_SIZE;
                let efi_base = align_down(top.saturating_sub(efi_size), 0x1000);
                if efi_base < ram_base || efi_base + efi_size > top {
                    eprintln!("EFI tables do not fit in RAM");
                    std::process::exit(1);
                }
                if !(efi_base + efi_size <= load_addr || efi_base >= kernel_end) {
                    eprintln!("EFI tables overlap kernel image");
                    std::process::exit(1);
                }
                let alloc_bottom = align_up(kernel_end, 0x1000);
                let alloc_top = efi_base;
                if alloc_bottom >= alloc_top {
                    eprintln!("EFI allocator region is empty");
                    std::process::exit(1);
                }
                let kernel_data_start_efi = if std::env::var("EFI_SPLIT_KERNEL_MAP").is_ok() {
                    kernel_data_start
                } else {
                    None
                };
                let efi_build = efi::build_efi_blob(
                    efi_base,
                    ram_base,
                    ram_size as u64,
                    (load_addr, kernel_end),
                    kernel_data_start_efi,
                    bootargs.as_deref(),
                    initrd_range,
                    dtb_range,
                    alloc_bottom,
                    alloc_top,
                );
                if std::env::var("EFI_PROTO_TRACE").is_ok() {
                    let off = (efi_build.riscv_boot_proto - efi_base) as usize;
                    if off + 16 <= efi_build.blob.len() {
                        eprintln!(
                            "EFI boot proto bytes: {:02x?}",
                            &efi_build.blob[off..off + 16]
                        );
                    }
                    let off = (efi_build.riscv_fdt_proto - efi_base) as usize;
                    if off + 16 <= efi_build.blob.len() {
                        eprintln!(
                            "EFI fdt proto bytes: {:02x?}",
                            &efi_build.blob[off..off + 16]
                        );
                    }
                }
                eprintln!(
                    "EFI: base=0x{:016x} system_table=0x{:016x} image_handle=0x{:016x} alloc=[0x{:016x}..0x{:016x})",
                    efi_base,
                    efi_build.system_table,
                    efi_build.image_handle,
                    alloc_bottom,
                    alloc_top
                );
                if let Err(e) = system.load(efi_base, &efi_build.blob) {
                    eprintln!("EFI tables load failed: {:?}", e);
                    std::process::exit(1);
                }
                let system_table = efi_build.system_table;
                let image_handle = efi_build.image_handle;
                let efi_state = efi::EfiState::new(efi_build);
                system.configure_efi_boot(system_table, image_handle, efi_state);
            } else {
                system.configure_linux_boot(dtb_load_addr);
            }
        }
        let result = system.run(max_steps);
        ran = true;
        match result {
            Ok(steps) => {
                println!("Completed {} steps", steps);
            }
            Err(trap) => {
                exit_code = 2;
                match trap {
                    Trap::Ecall => println!("ECALL"),
                    Trap::Ebreak => println!("EBREAK"),
                    Trap::IllegalInstruction(instr) => {
                        eprintln!("Illegal instruction 0x{:08x}", instr)
                    }
                    Trap::MisalignedAccess { addr, size } => {
                        eprintln!("Misaligned access addr=0x{:016x} size={}", addr, size)
                    }
                    Trap::MemoryOutOfBounds { addr, size } => {
                        eprintln!("Out of bounds addr=0x{:016x} size={}", addr, size)
                    }
                    Trap::PageFault { addr, .. } => {
                        eprintln!("Page fault addr=0x{:016x}", addr)
                    }
                }
            }
        }
    } else {
        exit_code = 1;
    }

    if dump_state {
        if ran {
            system.dump_state(data.len());
            system.dump_bus_stats();
            system.dump_sbi_stats();
            system.dump_hotpcs();
        } else {
            system.dump_state(0);
            system.dump_bus_stats();
            system.dump_sbi_stats();
            system.dump_hotpcs();
        }
    } else if ran {
        if let Some(hart0) = system.harts.get(0) {
            println!(
                "final hart0: pc=0x{:016x} ra=0x{:016x} sp=0x{:016x} a0=0x{:016x} a1=0x{:016x} a2=0x{:016x} a6=0x{:016x} a7=0x{:016x}",
                hart0.pc,
                hart0.regs[1],
                hart0.regs[2],
                hart0.regs[10],
                hart0.regs[11],
                hart0.regs[12],
                hart0.regs[16],
                hart0.regs[17]
            );
        }
        system.dump_bus_stats();
        system.dump_sbi_stats();
        system.dump_hotpcs();
    }
    std::process::exit(exit_code);
}
