use super::*;

impl Hart {
    pub(super) fn watch_hit_slot(watch_pc: Option<u64>, watch_left: &mut u64, pc: u64) -> bool {
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
    pub(super) fn watch_hit(&mut self, pc: u64) -> bool {
        Self::watch_hit_slot(self.watch_pc, &mut self.watch_left, pc)
    }

    #[inline]
    pub(super) fn watch_hit2(&mut self, pc: u64) -> bool {
        Self::watch_hit_slot(self.watch_pc2, &mut self.watch_left2, pc)
    }

    #[inline]
    pub(super) fn watch_field(
        reg: Option<usize>,
        before: Option<u64>,
        after: Option<u64>,
    ) -> String {
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

    pub(super) fn read_guest_cstr(
        &mut self,
        bus: &mut impl Bus,
        addr: u64,
        max_len: usize,
    ) -> Option<String> {
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

    pub(super) fn watch_cstr_field(
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
}
