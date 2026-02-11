#[derive(Debug)]
pub struct PeSection {
    pub vaddr: u64,
    pub vsize: u32,
    pub raw_ptr: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

#[derive(Debug)]
pub struct PeImage {
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_image: u32,
    pub base_reloc_rva: u32,
    pub base_reloc_size: u32,
    pub sections: Vec<PeSection>,
}

fn read_u16(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(data: &[u8], off: usize) -> Option<u64> {
    data.get(off..off + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

pub fn parse_pe(data: &[u8]) -> Result<PeImage, String> {
    if data.len() < 0x40 {
        return Err("file too small".to_string());
    }
    let mz = read_u16(data, 0).ok_or("bad header")?;
    if mz != 0x5a4d {
        return Err("missing MZ header".to_string());
    }
    let e_lfanew = read_u32(data, 0x3c).ok_or("bad e_lfanew")? as usize;
    if data.len() < e_lfanew + 4 + 20 {
        return Err("file too small for PE header".to_string());
    }
    if &data[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err("missing PE signature".to_string());
    }

    let coff = e_lfanew + 4;
    let num_sections = read_u16(data, coff + 2).ok_or("bad sections")? as usize;
    let opt_size = read_u16(data, coff + 16).ok_or("bad opt size")? as usize;
    let opt = coff + 20;
    if data.len() < opt + opt_size {
        return Err("optional header truncated".to_string());
    }

    let magic = read_u16(data, opt).ok_or("bad optional header")?;
    if magic != 0x20b {
        return Err("unsupported PE (need PE32+)".to_string());
    }

    let entry_rva = read_u32(data, opt + 16).ok_or("bad entry")?;
    let image_base = read_u64(data, opt + 24).ok_or("bad image base")?;
    let size_of_image = read_u32(data, opt + 56).ok_or("bad image size")?;
    let num_dirs = read_u32(data, opt + 108).ok_or("bad dir count")?;
    let mut base_reloc_rva = 0u32;
    let mut base_reloc_size = 0u32;
    if num_dirs > 5 {
        let dir_off = opt + 112 + 5 * 8;
        base_reloc_rva = read_u32(data, dir_off).unwrap_or(0);
        base_reloc_size = read_u32(data, dir_off + 4).unwrap_or(0);
    }

    let mut sections = Vec::with_capacity(num_sections);
    let sec_base = opt + opt_size;
    let sec_size = 40;
    if data.len() < sec_base + sec_size * num_sections {
        return Err("section headers truncated".to_string());
    }

    for i in 0..num_sections {
        let off = sec_base + i * sec_size;
        let vsize = read_u32(data, off + 8).ok_or("bad vsize")?;
        let vaddr = read_u32(data, off + 12).ok_or("bad vaddr")?;
        let raw_size = read_u32(data, off + 16).ok_or("bad raw size")?;
        let raw_ptr = read_u32(data, off + 20).ok_or("bad raw ptr")?;
        let characteristics = read_u32(data, off + 36).ok_or("bad characteristics")?;
        sections.push(PeSection {
            vaddr: vaddr as u64,
            vsize,
            raw_ptr,
            raw_size,
            characteristics,
        });
    }

    Ok(PeImage {
        image_base,
        entry_rva,
        size_of_image,
        base_reloc_rva,
        base_reloc_size,
        sections,
    })
}

impl PeImage {
    pub fn rva_to_file_offset(&self, rva: u32) -> Option<usize> {
        for sec in &self.sections {
            let start = sec.vaddr as u32;
            let end = start.saturating_add(sec.raw_size.max(sec.vsize));
            if rva >= start && rva < end {
                let delta = rva - start;
                return Some(sec.raw_ptr as usize + delta as usize);
            }
        }
        None
    }
}

impl PeSection {
    pub fn is_executable(&self) -> bool {
        (self.characteristics & 0x2000_0000) != 0
    }
}
