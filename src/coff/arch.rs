//! Machine-specific details for x64, ARM64 and x86.

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Machine {
    X64,
    Arm64,
    X86,
}

// x86 relocations.
pub const IMAGE_REL_I386_ABSOLUTE: u16 = 0x00;
pub const IMAGE_REL_I386_DIR32: u16 = 0x06;
pub const IMAGE_REL_I386_DIR32NB: u16 = 0x07;
pub const IMAGE_REL_I386_SECTION: u16 = 0x0A;
pub const IMAGE_REL_I386_SECREL: u16 = 0x0B;
pub const IMAGE_REL_I386_SECREL7: u16 = 0x0D;
pub const IMAGE_REL_I386_REL32: u16 = 0x14;

// ARM64 relocations.
pub const IMAGE_REL_ARM64_ABSOLUTE: u16 = 0x00;
pub const IMAGE_REL_ARM64_ADDR32: u16 = 0x01;
pub const IMAGE_REL_ARM64_ADDR32NB: u16 = 0x02;
pub const IMAGE_REL_ARM64_BRANCH26: u16 = 0x03;
pub const IMAGE_REL_ARM64_PAGEBASE_REL21: u16 = 0x04;
pub const IMAGE_REL_ARM64_REL21: u16 = 0x05;
pub const IMAGE_REL_ARM64_PAGEOFFSET_12A: u16 = 0x06;
pub const IMAGE_REL_ARM64_PAGEOFFSET_12L: u16 = 0x07;
pub const IMAGE_REL_ARM64_SECREL: u16 = 0x08;
pub const IMAGE_REL_ARM64_SECREL_LOW12A: u16 = 0x09;
pub const IMAGE_REL_ARM64_SECREL_HIGH12A: u16 = 0x0A;
pub const IMAGE_REL_ARM64_SECREL_LOW12L: u16 = 0x0B;
pub const IMAGE_REL_ARM64_SECTION: u16 = 0x0D;
pub const IMAGE_REL_ARM64_ADDR64: u16 = 0x0E;
pub const IMAGE_REL_ARM64_BRANCH19: u16 = 0x0F;
pub const IMAGE_REL_ARM64_BRANCH14: u16 = 0x10;
pub const IMAGE_REL_ARM64_REL32: u16 = 0x11;

impl Machine {
    pub fn from_coff(m: u16) -> Option<Machine> {
        match m {
            IMAGE_FILE_MACHINE_AMD64 => Some(Machine::X64),
            IMAGE_FILE_MACHINE_ARM64 => Some(Machine::Arm64),
            IMAGE_FILE_MACHINE_I386 => Some(Machine::X86),
            _ => None,
        }
    }

    pub fn parse(name: &str) -> Option<Machine> {
        match name.to_ascii_lowercase().as_str() {
            "x64" | "amd64" | "x86_64" => Some(Machine::X64),
            "arm64" | "aarch64" => Some(Machine::Arm64),
            "x86" | "i386" | "i686" => Some(Machine::X86),
            _ => None,
        }
    }

    pub fn coff(self) -> u16 {
        match self {
            Machine::X64 => IMAGE_FILE_MACHINE_AMD64,
            Machine::Arm64 => IMAGE_FILE_MACHINE_ARM64,
            Machine::X86 => IMAGE_FILE_MACHINE_I386,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Machine::X64 => "x64",
            Machine::Arm64 => "arm64",
            Machine::X86 => "x86",
        }
    }

    pub fn lib_dir(self) -> &'static str {
        self.name()
    }

    pub fn is64(self) -> bool {
        self != Machine::X86
    }

    pub fn ptr_size(self) -> u32 {
        if self.is64() { 8 } else { 4 }
    }

    pub fn default_image_base(self, dll: bool) -> u64 {
        match (self.is64(), dll) {
            (true, false) => 0x1_4000_0000,
            (true, true) => 0x1_8000_0000,
            (false, false) => 0x40_0000,
            (false, true) => 0x1000_0000,
        }
    }

    pub fn mangle(self, name: &str) -> String {
        if self == Machine::X86 {
            format!("_{name}")
        } else {
            name.to_string()
        }
    }

    pub fn thunk_size(self) -> u32 {
        match self {
            Machine::Arm64 => 12,
            _ => 8,
        }
    }

    pub fn pdata_entry_size(self) -> Option<usize> {
        match self {
            Machine::X64 => Some(12),
            Machine::Arm64 => Some(8),
            Machine::X86 => None,
        }
    }

    pub fn optional_header_size(self) -> u32 {
        if self.is64() { 240 } else { 224 }
    }

    pub fn tls_directory_size(self) -> u32 {
        if self.is64() { 0x28 } else { 0x18 }
    }

    pub fn is_absolute_reloc(self, ty: u16) -> bool {
        ty == match self {
            Machine::X64 => IMAGE_REL_AMD64_ABSOLUTE,
            Machine::Arm64 => IMAGE_REL_ARM64_ABSOLUTE,
            Machine::X86 => IMAGE_REL_I386_ABSOLUTE,
        }
    }

    pub fn reloc_width(self, ty: u16) -> usize {
        match (self, ty) {
            (Machine::X64, IMAGE_REL_AMD64_ADDR64) | (Machine::Arm64, IMAGE_REL_ARM64_ADDR64) => 8,
            (Machine::X64, IMAGE_REL_AMD64_SECTION)
            | (Machine::X86, IMAGE_REL_I386_SECTION)
            | (Machine::Arm64, IMAGE_REL_ARM64_SECTION) => 2,
            (Machine::X64, IMAGE_REL_AMD64_SECREL7) | (Machine::X86, IMAGE_REL_I386_SECREL7) => 1,
            _ => 4,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Target {
    pub va: u64,
    pub absolute: bool,
    pub out: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseRel {
    None,
    Dir64,
    HighLow,
}

pub struct RelocCtx<'a> {
    pub image_base: u64,
    pub out_rvas: &'a [u32],
}

impl RelocCtx<'_> {
    fn section_index(&self, t: &Target) -> u16 {
        if t.out == u32::MAX {
            self.out_rvas.len() as u16 + 1
        } else {
            t.out as u16 + 1
        }
    }

    fn secrel(&self, t: &Target) -> u64 {
        if t.absolute || t.out == u32::MAX {
            t.va
        } else {
            t.va - self.image_base - self.out_rvas[t.out as usize] as u64
        }
    }
}

pub fn apply(
    machine: Machine,
    ctx: &RelocCtx,
    ty: u16,
    buf: &mut [u8],
    off: usize,
    t: Target,
    p: u64,
) -> Result<BaseRel, String> {
    match machine {
        Machine::X64 => apply_x64(ctx, ty, buf, off, t, p),
        Machine::X86 => apply_x86(ctx, ty, buf, off, t, p),
        Machine::Arm64 => apply_arm64(ctx, ty, buf, off, t, p),
    }
}

fn base_rel(t: &Target, kind: BaseRel) -> BaseRel {
    if t.absolute { BaseRel::None } else { kind }
}

fn rel32(buf: &mut [u8], off: usize, v: i64) -> Result<(), String> {
    if v != v as i32 as i64 {
        return Err("relative address is out of range".into());
    }
    put32(buf, off, v as i32 as u32);
    Ok(())
}

fn abs32(buf: &mut [u8], off: usize, va: u64) -> Result<(), String> {
    if va > u32::MAX as u64 {
        return Err(
            "a 32-bit absolute address doesn't fit; link with /LARGEADDRESSAWARE:NO and a low /BASE"
                .into(),
        );
    }
    put32(buf, off, (va as u32).wrapping_add(u32le(buf, off)));
    Ok(())
}

fn apply_x64(
    ctx: &RelocCtx,
    ty: u16,
    buf: &mut [u8],
    off: usize,
    t: Target,
    p: u64,
) -> Result<BaseRel, String> {
    let ib = ctx.image_base;
    match ty {
        IMAGE_REL_AMD64_ADDR64 => {
            put64(buf, off, t.va.wrapping_add(u64le(buf, off)));
            return Ok(base_rel(&t, BaseRel::Dir64));
        }
        IMAGE_REL_AMD64_ADDR32 => {
            abs32(buf, off, t.va)?;
            return Ok(base_rel(&t, BaseRel::HighLow));
        }
        IMAGE_REL_AMD64_ADDR32NB => {
            let v = t.va.wrapping_sub(ib).wrapping_add(u32le(buf, off) as u64);
            put32(buf, off, v as u32);
        }
        IMAGE_REL_AMD64_REL32..=IMAGE_REL_AMD64_REL32_5 => {
            let k = (ty - IMAGE_REL_AMD64_REL32) as u64;
            let a = u32le(buf, off) as i32 as i64;
            rel32(buf, off, t.va as i64 + a - (p + 4 + k) as i64)?;
        }
        IMAGE_REL_AMD64_SECTION => {
            let n = ctx.section_index(&t);
            put16(buf, off, n.wrapping_add(u16le(buf, off)));
        }
        IMAGE_REL_AMD64_SECREL => {
            let v = (ctx.secrel(&t) as u32).wrapping_add(u32le(buf, off));
            put32(buf, off, v);
        }
        IMAGE_REL_AMD64_SECREL7 => {
            let v = (ctx.secrel(&t) as u8).wrapping_add(buf[off]) & 0x7F;
            buf[off] = (buf[off] & 0x80) | v;
        }
        _ => return Err(format!("unsupported x64 relocation type {ty:#x}")),
    }
    Ok(BaseRel::None)
}

fn apply_x86(
    ctx: &RelocCtx,
    ty: u16,
    buf: &mut [u8],
    off: usize,
    t: Target,
    p: u64,
) -> Result<BaseRel, String> {
    let ib = ctx.image_base;
    match ty {
        IMAGE_REL_I386_DIR32 => {
            abs32(buf, off, t.va)?;
            return Ok(base_rel(&t, BaseRel::HighLow));
        }
        IMAGE_REL_I386_DIR32NB => {
            let v = t.va.wrapping_sub(ib).wrapping_add(u32le(buf, off) as u64);
            put32(buf, off, v as u32);
        }
        IMAGE_REL_I386_REL32 => {
            let a = u32le(buf, off) as i32 as i64;
            rel32(buf, off, t.va as i64 + a - (p + 4) as i64)?;
        }
        IMAGE_REL_I386_SECTION => {
            let n = ctx.section_index(&t);
            put16(buf, off, n.wrapping_add(u16le(buf, off)));
        }
        IMAGE_REL_I386_SECREL => {
            let v = (ctx.secrel(&t) as u32).wrapping_add(u32le(buf, off));
            put32(buf, off, v);
        }
        IMAGE_REL_I386_SECREL7 => {
            let v = (ctx.secrel(&t) as u8).wrapping_add(buf[off]) & 0x7F;
            buf[off] = (buf[off] & 0x80) | v;
        }
        _ => return Err(format!("unsupported x86 relocation type {ty:#x}")),
    }
    Ok(BaseRel::None)
}

fn sign_extend(v: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((v << shift) as i64) >> shift
}

pub fn arm64_adr(buf: &mut [u8], off: usize, s: u64, p: u64, shift: u32) -> Result<(), String> {
    let orig = u32le(buf, off);
    let imm = sign_extend(
        (((orig >> 29) & 0x3) | ((orig >> 3) & 0x1F_FFFC)) as u64,
        21,
    );
    let s = s.wrapping_add(imm as u64);
    let v = ((s >> shift) as i64).wrapping_sub((p >> shift) as i64);
    if !(-(1 << 20)..(1 << 20)).contains(&v) {
        return Err("adrp/adr target is out of range".into());
    }
    let mask = (0x3 << 29) | (0x1F_FFFC << 3);
    let enc = (((v as u32) & 0x3) << 29) | (((v as u32) & 0x1F_FFFC) << 3);
    put32(buf, off, (orig & !mask) | enc);
    Ok(())
}

pub fn arm64_imm12(buf: &mut [u8], off: usize, imm: u64, range_limit: u32) {
    let orig = u32le(buf, off);
    let imm = imm.wrapping_add(((orig >> 10) & 0xFFF) as u64);
    let orig = orig & !(0xFFF << 10);
    put32(
        buf,
        off,
        orig | (((imm as u32) & (0xFFF >> range_limit)) << 10),
    );
}

pub fn arm64_ldst12(buf: &mut [u8], off: usize, imm: u64) -> Result<(), String> {
    let orig = u32le(buf, off);
    let mut size = orig >> 30;
    if orig & 0x0480_0000 == 0x0480_0000 {
        size += 4;
    }
    if imm & ((1 << size) - 1) != 0 {
        return Err("misaligned ldr/str offset".into());
    }
    arm64_imm12(buf, off, imm >> size, size);
    Ok(())
}

fn arm64_branch(buf: &mut [u8], off: usize, v: i64, bits: u32, shift: u32) -> Result<(), String> {
    let orig = u32le(buf, off);
    let field = (1u32 << bits) - 1;
    let addend = sign_extend(((orig >> shift) & field) as u64, bits) << 2;
    let v = v + addend;
    let range = 1i64 << (bits + 1);
    if v < -range || v >= range || v & 3 != 0 {
        return Err("branch target is out of range".into());
    }
    let enc = ((v >> 2) as u32 & field) << shift;
    put32(buf, off, (orig & !(field << shift)) | enc);
    Ok(())
}

fn apply_arm64(
    ctx: &RelocCtx,
    ty: u16,
    buf: &mut [u8],
    off: usize,
    t: Target,
    p: u64,
) -> Result<BaseRel, String> {
    let ib = ctx.image_base;
    let s = t.va;
    match ty {
        IMAGE_REL_ARM64_PAGEBASE_REL21 => arm64_adr(buf, off, s, p, 12)?,
        IMAGE_REL_ARM64_REL21 => arm64_adr(buf, off, s, p, 0)?,
        IMAGE_REL_ARM64_PAGEOFFSET_12A => arm64_imm12(buf, off, s & 0xFFF, 0),
        IMAGE_REL_ARM64_PAGEOFFSET_12L => arm64_ldst12(buf, off, s & 0xFFF)?,
        IMAGE_REL_ARM64_BRANCH26 => arm64_branch(buf, off, s as i64 - p as i64, 26, 0)?,
        IMAGE_REL_ARM64_BRANCH19 => arm64_branch(buf, off, s as i64 - p as i64, 19, 5)?,
        IMAGE_REL_ARM64_BRANCH14 => arm64_branch(buf, off, s as i64 - p as i64, 14, 5)?,
        IMAGE_REL_ARM64_ADDR32 => {
            abs32(buf, off, s)?;
            return Ok(base_rel(&t, BaseRel::HighLow));
        }
        IMAGE_REL_ARM64_ADDR32NB => {
            let v = s.wrapping_sub(ib).wrapping_add(u32le(buf, off) as u64);
            put32(buf, off, v as u32);
        }
        IMAGE_REL_ARM64_ADDR64 => {
            put64(buf, off, s.wrapping_add(u64le(buf, off)));
            return Ok(base_rel(&t, BaseRel::Dir64));
        }
        IMAGE_REL_ARM64_SECREL => {
            let v = (ctx.secrel(&t) as u32).wrapping_add(u32le(buf, off));
            put32(buf, off, v);
        }
        IMAGE_REL_ARM64_SECREL_LOW12A => arm64_imm12(buf, off, ctx.secrel(&t) & 0xFFF, 0),
        IMAGE_REL_ARM64_SECREL_HIGH12A => {
            let high = ctx.secrel(&t) >> 12;
            if high > 0xFFF {
                return Err(
                    "SECREL_HIGH12A overflow (thread-local data larger than 16 MiB)".into(),
                );
            }
            arm64_imm12(buf, off, high, 0);
        }
        IMAGE_REL_ARM64_SECREL_LOW12L => arm64_ldst12(buf, off, ctx.secrel(&t) & 0xFFF)?,
        IMAGE_REL_ARM64_SECTION => {
            let n = ctx.section_index(&t);
            put16(buf, off, n.wrapping_add(u16le(buf, off)));
        }
        IMAGE_REL_ARM64_REL32 => {
            let a = u32le(buf, off) as i32 as i64;
            rel32(buf, off, s as i64 + a - (p + 4) as i64)?;
        }
        _ => return Err(format!("unsupported ARM64 relocation type {ty:#x}")),
    }
    Ok(BaseRel::None)
}

pub fn write_thunk(machine: Machine, buf: &mut [u8], thunk: u64, slot: u64) -> bool {
    match machine {
        Machine::X64 => {
            // jmp qword ptr [rip + disp32]
            buf[..2].copy_from_slice(&[0xFF, 0x25]);
            put32(buf, 2, (slot as i64 - (thunk as i64 + 6)) as i32 as u32);
            buf[6..8].copy_from_slice(&[0xCC, 0xCC]);
            false
        }
        Machine::X86 => {
            // jmp dword ptr [slot]
            buf[..2].copy_from_slice(&[0xFF, 0x25]);
            put32(buf, 2, slot as u32);
            buf[6..8].copy_from_slice(&[0xCC, 0xCC]);
            true
        }
        Machine::Arm64 => {
            // adrp x16, slot; ldr x16, [x16, :lo12:slot]; br x16
            put32(buf, 0, 0x9000_0010);
            put32(buf, 4, 0xF940_0210);
            put32(buf, 8, 0xD61F_0200);
            let _ = arm64_adr(buf, 0, slot, thunk, 12);
            let _ = arm64_ldst12(buf, 4, slot & 0xFFF);
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn insn(v: u32) -> Vec<u8> {
        v.to_le_bytes().to_vec()
    }

    #[test]
    fn arm64_adrp_add_ldr() {
        let mut b = insn(0x9000_0000);
        arm64_adr(&mut b, 0, 0x1_4000_5123, 0x1_4000_1000, 12).unwrap();
        assert_eq!(u32le(&b, 0), 0x9000_0020);
        let mut b = insn(0x9100_0000);
        arm64_imm12(&mut b, 0, 0x123, 0);
        assert_eq!(u32le(&b, 0), 0x9104_8C00);
        let mut b = insn(0xF940_0001);
        arm64_ldst12(&mut b, 0, 0x128).unwrap();
        assert_eq!(u32le(&b, 0), 0xF940_9401);
        assert!(arm64_ldst12(&mut insn(0xF940_0001), 0, 0x124).is_err());
    }

    #[test]
    fn arm64_branches() {
        let mut b = insn(0x9400_0000);
        arm64_branch(&mut b, 0, 0x100, 26, 0).unwrap();
        assert_eq!(u32le(&b, 0), 0x9400_0040);
        let mut b = insn(0x9400_0000);
        arm64_branch(&mut b, 0, -8, 26, 0).unwrap();
        assert_eq!(u32le(&b, 0), 0x97FF_FFFE);
        let mut b = insn(0x5400_0000);
        arm64_branch(&mut b, 0, 0x20, 19, 5).unwrap();
        assert_eq!(u32le(&b, 0), 0x5400_0100);
        assert!(arm64_branch(&mut insn(0x9400_0000), 0, 1 << 28, 26, 0).is_err());
    }

    #[test]
    fn thunks() {
        let mut b = [0u8; 12];
        write_thunk(Machine::Arm64, &mut b, 0x1_4000_1000, 0x1_4000_3008);
        assert_eq!(u32le(&b, 0), 0xD000_0010);
        assert_eq!(u32le(&b, 4), 0xF940_0610);
        assert_eq!(u32le(&b, 8), 0xD61F_0200);
        let mut b = [0u8; 8];
        assert!(!write_thunk(Machine::X64, &mut b, 0x1000, 0x2000));
        assert_eq!(&b[..2], &[0xFF, 0x25]);
        assert_eq!(u32le(&b, 2), 0x2000 - 0x1006);
        assert!(write_thunk(Machine::X86, &mut b, 0x40_1000, 0x40_2000));
        assert_eq!(u32le(&b, 2), 0x40_2000);
    }
}
