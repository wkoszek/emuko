use std::collections::HashMap;

const FDT_MAGIC: u32 = 0xd00dfeed;
const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_END: u32 = 9;

pub fn build_virt_dtb(
    num_harts: usize,
    ram_base: u64,
    ram_size: u64,
    isa: &str,
    bootargs: Option<&str>,
    initrd: Option<(u64, u64)>,
) -> Vec<u8> {
    let mut fdt = FdtBuilder::new();

    let plic_phandle = 1u32;
    let cpu_phandle_base = 0x100u32;
    let cpu_intc_phandle_base = 0x200u32;

    fdt.begin_node("");
    fdt.prop_str_list("compatible", &["riscv-virtio", "qemu,virt"]);
    fdt.prop_u32("#address-cells", 2);
    fdt.prop_u32("#size-cells", 2);
    fdt.prop_str("model", "riscv-virtio,qemu");

    fdt.begin_node("chosen");
    fdt.prop_str("stdout-path", "/soc/uart@10000000");
    if let Some(args) = bootargs {
        fdt.prop_str("bootargs", args);
    }
    if let Some((start, end)) = initrd {
        fdt.prop_u64("linux,initrd-start", start);
        fdt.prop_u64("linux,initrd-end", end);
    }
    fdt.end_node();

    fdt.begin_node("aliases");
    fdt.prop_str("serial0", "/soc/uart@10000000");
    fdt.end_node();

    fdt.begin_node("cpus");
    fdt.prop_u32("#address-cells", 1);
    fdt.prop_u32("#size-cells", 0);
    fdt.prop_u32("timebase-frequency", 10_000_000);

    let mut cpu_intc_phandles = Vec::with_capacity(num_harts);
    for hart_id in 0..num_harts {
        let cpu_phandle = cpu_phandle_base + hart_id as u32;
        let cpu_intc_phandle = cpu_intc_phandle_base + hart_id as u32;
        cpu_intc_phandles.push(cpu_intc_phandle);
        let name = format!("cpu@{hart_id}");
        fdt.begin_node(&name);
        fdt.prop_str("device_type", "cpu");
        fdt.prop_str("compatible", "riscv");
        fdt.prop_u32("reg", hart_id as u32);
        fdt.prop_str("riscv,isa", isa);
        fdt.prop_str("mmu-type", "riscv,sv39");
        fdt.prop_str("status", "okay");
        fdt.prop_u32("phandle", cpu_phandle);
        fdt.begin_node("interrupt-controller");
        fdt.prop_u32("#interrupt-cells", 1);
        fdt.prop_empty("interrupt-controller");
        fdt.prop_str("compatible", "riscv,cpu-intc");
        fdt.prop_u32("phandle", cpu_intc_phandle);
        fdt.end_node();
        fdt.end_node();
    }
    fdt.end_node();

    fdt.begin_node("timer");
    fdt.prop_str("compatible", "riscv,timer");
    let mut timer_irqs = Vec::with_capacity(num_harts * 4);
    for &ph in &cpu_intc_phandles {
        // Supervisor local interrupts: STIP=5, SSIP=1.
        timer_irqs.push(ph);
        timer_irqs.push(5);
        timer_irqs.push(ph);
        timer_irqs.push(1);
    }
    fdt.prop_u32s("interrupts-extended", &timer_irqs);
    fdt.end_node();

    let mem_name = format!("memory@{:x}", ram_base);
    fdt.begin_node(&mem_name);
    fdt.prop_str("device_type", "memory");
    fdt.prop_u64s("reg", &[ram_base, ram_size]);
    fdt.end_node();

    fdt.begin_node("soc");
    fdt.prop_u32("#address-cells", 2);
    fdt.prop_u32("#size-cells", 2);
    fdt.prop_str("compatible", "simple-bus");
    fdt.prop_empty("ranges");

    fdt.begin_node("uart@10000000");
    fdt.prop_str("compatible", "ns16550a");
    fdt.prop_u64s("reg", &[0x1000_0000, 0x100]);
    fdt.prop_u32("interrupt-parent", plic_phandle);
    fdt.prop_u32("interrupts", 10);
    fdt.prop_u32("clock-frequency", 3_686_400);
    fdt.prop_u32("reg-shift", 0);
    fdt.prop_u32("reg-io-width", 1);
    fdt.end_node();

    fdt.begin_node("clint@2000000");
    fdt.prop_str_list("compatible", &["sifive,clint0", "riscv,clint0"]);
    fdt.prop_u64s("reg", &[0x0200_0000, 0x0001_0000]);
    let mut clint_irqs = Vec::with_capacity(num_harts * 4);
    for &ph in &cpu_intc_phandles {
        clint_irqs.push(ph);
        clint_irqs.push(1);
        clint_irqs.push(ph);
        clint_irqs.push(5);
    }
    fdt.prop_u32s("interrupts-extended", &clint_irqs);
    fdt.end_node();

    fdt.begin_node("plic@c000000");
    fdt.prop_str("compatible", "riscv,plic0");
    fdt.prop_u32("#interrupt-cells", 1);
    fdt.prop_empty("interrupt-controller");
    fdt.prop_u64s("reg", &[0x0c00_0000, 0x0040_0000]);
    let mut plic_irqs = Vec::with_capacity(num_harts * 2);
    for &ph in &cpu_intc_phandles {
        plic_irqs.push(ph);
        plic_irqs.push(9);
    }
    fdt.prop_u32s("interrupts-extended", &plic_irqs);
    fdt.prop_u32("riscv,ndev", 32);
    fdt.prop_u32("phandle", plic_phandle);
    fdt.end_node();

    fdt.end_node(); // soc
    fdt.end_node(); // root

    fdt.finish()
}

struct FdtBuilder {
    struct_block: Vec<u8>,
    strings: Vec<u8>,
    offsets: HashMap<String, u32>,
}

impl FdtBuilder {
    fn new() -> Self {
        Self {
            struct_block: Vec::new(),
            strings: Vec::new(),
            offsets: HashMap::new(),
        }
    }

    fn finish(mut self) -> Vec<u8> {
        self.put_u32(FDT_END);
        Self::pad4(&mut self.struct_block);

        let off_mem_rsvmap = 40u32;
        let rsvmap = vec![0u8; 16];
        let off_dt_struct = off_mem_rsvmap + rsvmap.len() as u32;
        let off_dt_strings = off_dt_struct + self.struct_block.len() as u32;
        let pad_bytes = 0x10000u32;
        let totalsize_raw = off_dt_strings + self.strings.len() as u32 + pad_bytes;
        let totalsize = (totalsize_raw + 3) & !3;

        let mut out = Vec::with_capacity(totalsize as usize);
        self.push_u32(&mut out, FDT_MAGIC);
        self.push_u32(&mut out, totalsize);
        self.push_u32(&mut out, off_dt_struct);
        self.push_u32(&mut out, off_dt_strings);
        self.push_u32(&mut out, off_mem_rsvmap);
        self.push_u32(&mut out, 17); // version
        self.push_u32(&mut out, 16); // last_comp_version
        self.push_u32(&mut out, 0); // boot_cpuid_phys
        self.push_u32(&mut out, self.strings.len() as u32);
        self.push_u32(&mut out, self.struct_block.len() as u32);

        out.extend_from_slice(&rsvmap);
        out.extend_from_slice(&self.struct_block);
        out.extend_from_slice(&self.strings);
        out.resize(totalsize as usize, 0);
        out
    }

    fn begin_node(&mut self, name: &str) {
        self.put_u32(FDT_BEGIN_NODE);
        self.struct_block.extend_from_slice(name.as_bytes());
        self.struct_block.push(0);
        Self::pad4(&mut self.struct_block);
    }

    fn end_node(&mut self) {
        self.put_u32(FDT_END_NODE);
    }

    fn prop_empty(&mut self, name: &str) {
        self.prop_raw(name, &[]);
    }

    fn prop_str(&mut self, name: &str, val: &str) {
        let mut bytes = Vec::with_capacity(val.len() + 1);
        bytes.extend_from_slice(val.as_bytes());
        bytes.push(0);
        self.prop_raw(name, &bytes);
    }

    fn prop_str_list(&mut self, name: &str, vals: &[&str]) {
        let mut bytes = Vec::new();
        for v in vals {
            bytes.extend_from_slice(v.as_bytes());
            bytes.push(0);
        }
        self.prop_raw(name, &bytes);
    }

    fn prop_u32(&mut self, name: &str, val: u32) {
        self.prop_raw(name, &val.to_be_bytes());
    }

    fn prop_u64(&mut self, name: &str, val: u64) {
        self.prop_raw(name, &val.to_be_bytes());
    }

    fn prop_u32s(&mut self, name: &str, vals: &[u32]) {
        let mut bytes = Vec::with_capacity(vals.len() * 4);
        for v in vals {
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        self.prop_raw(name, &bytes);
    }

    fn prop_u64s(&mut self, name: &str, vals: &[u64]) {
        let mut bytes = Vec::with_capacity(vals.len() * 8);
        for v in vals {
            bytes.extend_from_slice(&v.to_be_bytes());
        }
        self.prop_raw(name, &bytes);
    }

    fn prop_raw(&mut self, name: &str, val: &[u8]) {
        let nameoff = self.string_offset(name);
        self.put_u32(FDT_PROP);
        self.put_u32(val.len() as u32);
        self.put_u32(nameoff);
        self.struct_block.extend_from_slice(val);
        Self::pad4(&mut self.struct_block);
    }

    fn string_offset(&mut self, name: &str) -> u32 {
        if let Some(off) = self.offsets.get(name) {
            return *off;
        }
        let off = self.strings.len() as u32;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        self.offsets.insert(name.to_string(), off);
        off
    }

    fn put_u32(&mut self, val: u32) {
        self.struct_block.extend_from_slice(&val.to_be_bytes());
    }

    fn push_u32(&self, out: &mut Vec<u8>, val: u32) {
        out.extend_from_slice(&val.to_be_bytes());
    }

    fn pad4(buf: &mut Vec<u8>) {
        while buf.len() % 4 != 0 {
            buf.push(0);
        }
    }
}
