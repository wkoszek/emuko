#[derive(Debug)]
pub struct ElfSegment {
    pub vaddr: u64,
    pub file_offset: usize,
    pub filesz: usize,
    pub memsz: usize,
}

#[derive(Debug)]
pub struct ElfImage {
    pub entry: u64,
    pub segments: Vec<ElfSegment>,
}

impl ElfImage {
    pub fn mem_base(&self) -> u64 {
        self.segments.iter().map(|s| s.vaddr).min().unwrap_or(0)
    }

    pub fn mem_size(&self) -> u64 {
        let base = self.mem_base();
        let top = self
            .segments
            .iter()
            .map(|s| s.vaddr.saturating_add(s.memsz as u64))
            .max()
            .unwrap_or(0);
        top.saturating_sub(base)
    }
}

fn r16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn r32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn r64(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .and_then(|b| b.try_into().ok().map(u64::from_le_bytes))
}

pub fn parse_elf(data: &[u8]) -> Result<ElfImage, String> {
    if data.len() < 64 {
        return Err("too small for ELF header".to_string());
    }
    if &data[0..4] != b"\x7fELF" {
        return Err("not an ELF file".to_string());
    }
    if data[4] != 2 {
        return Err("not ELF64".to_string());
    }
    if data[5] != 1 {
        return Err("not little-endian ELF".to_string());
    }
    let e_machine = r16(data, 18).ok_or("bad e_machine")?;
    if e_machine != 0xf3 {
        return Err(format!(
            "not RISC-V ELF (e_machine=0x{e_machine:x})"
        ));
    }
    let e_entry = r64(data, 24).ok_or("bad e_entry")?;
    let e_phoff = r64(data, 32).ok_or("bad e_phoff")? as usize;
    let e_phentsize = r16(data, 54).ok_or("bad e_phentsize")? as usize;
    let e_phnum = r16(data, 56).ok_or("bad e_phnum")? as usize;

    if e_phentsize < 56 {
        return Err("e_phentsize too small".to_string());
    }
    if e_phnum == 0 || e_phoff == 0 {
        return Err("no program headers".to_string());
    }

    let mut segments = Vec::new();
    for i in 0..e_phnum {
        let off = e_phoff + i * e_phentsize;
        if off + 56 > data.len() {
            return Err(format!("program header {i} out of bounds"));
        }
        let p_type = r32(data, off).ok_or("bad p_type")?;
        if p_type != 1 {
            continue; // only PT_LOAD
        }
        let p_offset = r64(data, off + 8).ok_or("bad p_offset")? as usize;
        let p_vaddr = r64(data, off + 16).ok_or("bad p_vaddr")?;
        let p_filesz = r64(data, off + 32).ok_or("bad p_filesz")? as usize;
        let p_memsz = r64(data, off + 40).ok_or("bad p_memsz")? as usize;
        if p_filesz > 0 && p_offset.saturating_add(p_filesz) > data.len() {
            return Err(format!("segment {i} file data out of bounds"));
        }
        segments.push(ElfSegment {
            vaddr: p_vaddr,
            file_offset: p_offset,
            filesz: p_filesz,
            memsz: p_memsz,
        });
    }
    if segments.is_empty() {
        return Err("no PT_LOAD segments found".to_string());
    }
    Ok(ElfImage {
        entry: e_entry,
        segments,
    })
}
