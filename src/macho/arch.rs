//! What differs between arm64 and x86_64: relocation types and their semantics, stub code.

use super::config::Arch;
use super::*;

pub const ARM64_RELOC_UNSIGNED: u8 = 0;
pub const ARM64_RELOC_SUBTRACTOR: u8 = 1;
pub const ARM64_RELOC_BRANCH26: u8 = 2;
pub const ARM64_RELOC_PAGE21: u8 = 3;
pub const ARM64_RELOC_PAGEOFF12: u8 = 4;
pub const ARM64_RELOC_GOT_LOAD_PAGE21: u8 = 5;
pub const ARM64_RELOC_GOT_LOAD_PAGEOFF12: u8 = 6;
pub const ARM64_RELOC_POINTER_TO_GOT: u8 = 7;
pub const ARM64_RELOC_TLVP_LOAD_PAGE21: u8 = 8;
pub const ARM64_RELOC_TLVP_LOAD_PAGEOFF12: u8 = 9;
pub const ARM64_RELOC_ADDEND: u8 = 10;
pub const ARM64_RELOC_AUTHENTICATED_POINTER: u8 = 11;

pub const X86_64_RELOC_UNSIGNED: u8 = 0;
pub const X86_64_RELOC_SIGNED: u8 = 1;
pub const X86_64_RELOC_BRANCH: u8 = 2;
pub const X86_64_RELOC_GOT_LOAD: u8 = 3;
pub const X86_64_RELOC_GOT: u8 = 4;
pub const X86_64_RELOC_SUBTRACTOR: u8 = 5;
pub const X86_64_RELOC_SIGNED_1: u8 = 6;
pub const X86_64_RELOC_SIGNED_2: u8 = 7;
pub const X86_64_RELOC_SIGNED_4: u8 = 8;
pub const X86_64_RELOC_TLV: u8 = 9;

/// Relocation types of both architectures, by meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An absolute address, 4 or 8 bytes.
    Unsigned,
    /// Subtracts its symbol from the `Unsigned` that follows.
    Subtractor,
    /// A call or jump: through a stub when the target is imported.
    Branch,
    /// arm64 `adrp`: the 4 KiB page of the target.
    Page,
    /// arm64 `add`/`ldr`/`str` low 12 bits of the target.
    PageOff,
    GotPage,
    GotPageOff,
    /// A pc-relative (or absolute) pointer to the target's GOT slot; never relaxed.
    PointerToGot,
    TlvPage,
    TlvPageOff,
    /// arm64: the addend for the next relocation.
    Addend,
    /// arm64e: a signed pointer.
    AuthPointer,
    /// x86_64 pc-relative data access; the number of immediate bytes after the field.
    Signed(u8),
    /// x86_64 `movq sym@GOTPCREL(%rip)`: relaxable to `leaq`.
    GotLoad,
    /// x86_64 `movq sym@TLVP(%rip)`.
    Tlv,
    Unknown,
}

pub fn kind(arch: Arch, ty: u8) -> Kind {
    if arch.is_arm() {
        match ty {
            ARM64_RELOC_UNSIGNED => Kind::Unsigned,
            ARM64_RELOC_SUBTRACTOR => Kind::Subtractor,
            ARM64_RELOC_BRANCH26 => Kind::Branch,
            ARM64_RELOC_PAGE21 => Kind::Page,
            ARM64_RELOC_PAGEOFF12 => Kind::PageOff,
            ARM64_RELOC_GOT_LOAD_PAGE21 => Kind::GotPage,
            ARM64_RELOC_GOT_LOAD_PAGEOFF12 => Kind::GotPageOff,
            ARM64_RELOC_POINTER_TO_GOT => Kind::PointerToGot,
            ARM64_RELOC_TLVP_LOAD_PAGE21 => Kind::TlvPage,
            ARM64_RELOC_TLVP_LOAD_PAGEOFF12 => Kind::TlvPageOff,
            ARM64_RELOC_ADDEND => Kind::Addend,
            ARM64_RELOC_AUTHENTICATED_POINTER => Kind::AuthPointer,
            _ => Kind::Unknown,
        }
    } else {
        match ty {
            X86_64_RELOC_UNSIGNED => Kind::Unsigned,
            X86_64_RELOC_SIGNED => Kind::Signed(0),
            X86_64_RELOC_BRANCH => Kind::Branch,
            X86_64_RELOC_GOT_LOAD => Kind::GotLoad,
            X86_64_RELOC_GOT => Kind::PointerToGot,
            X86_64_RELOC_SUBTRACTOR => Kind::Subtractor,
            X86_64_RELOC_SIGNED_1 => Kind::Signed(1),
            X86_64_RELOC_SIGNED_2 => Kind::Signed(2),
            X86_64_RELOC_SIGNED_4 => Kind::Signed(4),
            X86_64_RELOC_TLV => Kind::Tlv,
            _ => Kind::Unknown,
        }
    }
}

pub fn reloc_is_subtractor(arch: Arch, ty: u8) -> bool {
    kind(arch, ty) == Kind::Subtractor
}

pub fn reloc_is_unsigned(arch: Arch, ty: u8) -> bool {
    matches!(kind(arch, ty), Kind::Unsigned | Kind::AuthPointer)
}

/// The value in place, as an addend. x86_64 pc-relative fields count from the field's end
/// plus the instruction's trailing immediate bytes; arm64 code fields hold none.
pub fn embedded_addend(arch: Arch, k: Kind, data: &[u8], off: usize, len: u8) -> i64 {
    let v = match len {
        2 => data
            .get(off..off + 4)
            .map_or(0, |b| i32::from_le_bytes(b.try_into().unwrap()) as i64),
        3 => data
            .get(off..off + 8)
            .map_or(0, |b| i64::from_le_bytes(b.try_into().unwrap())),
        _ => 0,
    };
    if arch.is_arm() {
        match k {
            Kind::Unsigned | Kind::Subtractor | Kind::PointerToGot => v,
            Kind::AuthPointer => (v as u32 as i32) as i64,
            _ => 0,
        }
    } else {
        match k {
            Kind::Signed(n) => v + n as i64,
            _ => v,
        }
    }
}

/// The object address a non-extern relocation points at.
pub fn section_target(arch: Arch, k: Kind, field_addr: u64, addend: i64, pcrel: bool) -> u64 {
    if pcrel && !arch.is_arm() {
        // x86_64: relative to the end of the 4-byte field (the immediate bytes are in the addend).
        (field_addr as i64 + 4 + addend) as u64
    } else {
        let _ = k;
        addend as u64
    }
}

#[inline]
fn page(v: u64) -> u64 {
    v & !0xfff
}

pub fn fits_signed(v: i64, bits: u32) -> bool {
    let lim = 1i64 << (bits - 1);
    v >= -lim && v < lim
}

/// `adrp` to the page of `target` from `p`.
pub fn encode_page21(insn: u32, p: u64, target: u64) -> Result<u32, String> {
    let delta = (page(target) as i64).wrapping_sub(page(p) as i64) >> 12;
    if !fits_signed(delta, 21) {
        return Err(format!("ADRP target {target:#x} is out of range of {p:#x}"));
    }
    let d = delta as u64;
    Ok((insn & 0x9f00_001f) | (((d & 3) as u32) << 29) | ((((d >> 2) & 0x7ffff) as u32) << 5))
}

/// The low 12 bits of `target`, scaled by the access size of the load or store.
pub fn encode_pageoff12(insn: u32, target: u64) -> Result<u32, String> {
    let mut scale = 0;
    if insn & 0x3b00_0000 == 0x3900_0000 {
        scale = insn >> 30;
        if scale == 0 && insn & 0x0480_0000 == 0x0480_0000 {
            scale = 4;
        }
    }
    let lo = target & 0xfff;
    if lo & ((1 << scale) - 1) != 0 {
        return Err(format!(
            "{target:#x} is not aligned to the {}-byte access that loads it",
            1 << scale
        ));
    }
    Ok((insn & 0xffc0_03ff) | (((lo >> scale) as u32) << 10))
}

/// `b`/`bl` to `target` from `p`.
pub fn encode_branch26(insn: u32, p: u64, target: u64) -> Result<u32, String> {
    let delta = target as i64 - p as i64;
    if delta & 3 != 0 || !fits_signed(delta, 28) {
        return Err(format!(
            "branch target {target:#x} is out of range of {p:#x} (±128 MiB)"
        ));
    }
    Ok((insn & 0xfc00_0000) | (((delta >> 2) as u32) & 0x03ff_ffff))
}

/// `ldr xN, [xM, #off]` → `add xN, xM, #off`, for a GOT or TLV load of a symbol defined here.
pub fn relax_ldr_to_add(insn: u32) -> Option<u32> {
    if insn & 0xbfc0_0000 != 0xb940_0000 {
        return None;
    }
    Some((insn & 0x001f_ffff) | 0x9100_0000)
}

pub fn stub_size(arch: Arch) -> u64 {
    match arch {
        Arch::Arm64 => 12,
        Arch::Arm64e => 16,
        Arch::X86_64 | Arch::X86_64h => 6,
    }
}

pub fn stub_align(arch: Arch) -> u8 {
    if arch.is_arm() { 2 } else { 1 }
}

/// A stub at `addr` jumping through the pointer at `slot`.
pub fn write_stub(arch: Arch, out: &mut [u8], addr: u64, slot: u64) {
    match arch {
        Arch::Arm64 => {
            let adrp = encode_page21(0x9000_0010, addr, slot).unwrap_or(0x9000_0010);
            let ldr = encode_pageoff12(0xf940_0210, slot).unwrap_or(0xf940_0210);
            put32(out, 0, adrp);
            put32(out, 4, ldr);
            put32(out, 8, 0xd61f_0200);
        }
        Arch::Arm64e => {
            let adrp = encode_page21(0x9000_0011, addr, slot).unwrap_or(0x9000_0011);
            let add = encode_pageoff12(0x9100_0231, slot).unwrap_or(0x9100_0231);
            put32(out, 0, adrp);
            put32(out, 4, add);
            put32(out, 8, 0xf940_0230);
            put32(out, 12, 0xd71f_0a11);
        }
        Arch::X86_64 | Arch::X86_64h => {
            out[0] = 0xff;
            out[1] = 0x25;
            put32(out, 2, (slot as i64 - (addr as i64 + 6)) as u32);
        }
    }
}

/// An `_objc_msgSend$sel` stub at `addr`: load the selector from `selref`, jump through `msgsend`.
pub fn write_objc_stub(arch: Arch, out: &mut [u8], addr: u64, selref: u64, msgsend: u64) {
    if arch.is_arm() {
        let i = [
            encode_page21(0x9000_0001, addr, selref).unwrap_or(0x9000_0001),
            encode_pageoff12(0xf940_0021, selref).unwrap_or(0xf940_0021),
            encode_page21(0x9000_0010, addr + 8, msgsend).unwrap_or(0x9000_0010),
            encode_pageoff12(0xf940_0210, msgsend).unwrap_or(0xf940_0210),
            0xd61f_0200,
            0xd420_0020,
            0xd420_0020,
            0xd420_0020,
        ];
        for (k, w) in i.iter().enumerate() {
            put32(out, k * 4, *w);
        }
    } else {
        // movq selref(%rip), %rsi; jmpq *msgsend(%rip)
        out[..3].copy_from_slice(&[0x48, 0x8b, 0x35]);
        put32(out, 3, (selref as i64 - (addr as i64 + 7)) as u32);
        out[7] = 0xff;
        out[8] = 0x25;
        put32(out, 9, (msgsend as i64 - (addr as i64 + 13)) as u32);
        out[13..16].fill(0xcc);
    }
}

/// Apply one relocation. `target` is the final address the field must reach (the symbol, its
/// stub, GOT slot or TLV descriptor, plus addend); `relax` turns a GOT/TLV load into an add.
#[allow(clippy::too_many_arguments)]
pub fn apply(
    arch: Arch,
    k: Kind,
    buf: &mut [u8],
    off: usize,
    len: u8,
    pcrel: bool,
    p: u64,
    target: u64,
    relax: bool,
) -> Result<(), String> {
    let width = 1usize << len;
    if off + width > buf.len() {
        return Err(format!(
            "relocation at {off:#x} runs past the end of its atom"
        ));
    }
    if arch.is_arm() {
        let insn = || u32le(buf, off);
        match k {
            Kind::Unsigned | Kind::Subtractor | Kind::AuthPointer => {
                write_value(buf, off, len, target)
            }
            Kind::PointerToGot if pcrel => {
                let d = target as i64 - p as i64;
                if !fits_signed(d, 32) {
                    return Err("GOT slot out of range".into());
                }
                put32(buf, off, d as u32);
            }
            Kind::PointerToGot => write_value(buf, off, len, target),
            Kind::Branch => put32(buf, off, encode_branch26(insn(), p, target)?),
            Kind::Page | Kind::GotPage | Kind::TlvPage => {
                put32(buf, off, encode_page21(insn(), p, target)?)
            }
            Kind::PageOff => put32(buf, off, encode_pageoff12(insn(), target)?),
            Kind::GotPageOff | Kind::TlvPageOff => {
                let mut i = insn();
                if relax {
                    i = relax_ldr_to_add(i)
                        .ok_or("GOT load relocation is not on an LDR instruction")?;
                }
                put32(buf, off, encode_pageoff12(i, target)?);
            }
            Kind::Addend | Kind::Unknown | Kind::Signed(_) | Kind::GotLoad | Kind::Tlv => {
                return Err(format!("unsupported arm64 relocation {k:?}"));
            }
        }
    } else {
        // The field counts from the end of the instruction: the field plus trailing immediates.
        let end = p + 4 + if let Kind::Signed(n) = k { n as u64 } else { 0 };
        match k {
            Kind::Unsigned | Kind::Subtractor if !pcrel => write_value(buf, off, len, target),
            Kind::GotLoad | Kind::Tlv if relax => {
                if off < 2 || buf[off - 2] != 0x8b {
                    return Err("GOT load relocation is not on a MOVQ instruction".into());
                }
                buf[off - 2] = 0x8d;
                write_pcrel32(buf, off, end, target)?;
            }
            _ if pcrel => write_pcrel32(buf, off, end, target)?,
            Kind::PointerToGot => write_value(buf, off, len, target),
            _ => return Err(format!("unsupported x86_64 relocation {k:?}")),
        }
    }
    Ok(())
}

fn write_value(buf: &mut [u8], off: usize, len: u8, v: u64) {
    match len {
        3 => put64(buf, off, v),
        2 => put32(buf, off, v as u32),
        1 => put16(buf, off, v as u16),
        _ => buf[off] = v as u8,
    }
}

fn write_pcrel32(buf: &mut [u8], off: usize, end: u64, target: u64) -> Result<(), String> {
    let d = target as i64 - end as i64;
    if !fits_signed(d, 32) {
        return Err(format!(
            "pc-relative target {target:#x} is out of range of {end:#x}"
        ));
    }
    put32(buf, off, d as u32);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arm64_encodings() {
        // adrp x16, from 0x100003000 to 0x100008010: +5 pages.
        let i = encode_page21(0x9000_0010, 0x1_0000_3000, 0x1_0000_8010).unwrap();
        assert_eq!(i, 0x9000_0010 | (1 << 29) | (1 << 5));
        // ldr x16, [x16, #0x10]: scaled by 8.
        assert_eq!(
            encode_pageoff12(0xf940_0210, 0x1_0000_8010).unwrap(),
            0xf940_0210 | (2 << 10)
        );
        assert!(encode_pageoff12(0xf940_0210, 0x1_0000_8014).is_err());
        // ldr q0: 16-byte scale.
        assert_eq!(
            encode_pageoff12(0x3dc0_0000, 0x20).unwrap(),
            0x3dc0_0000 | (2 << 10)
        );
        // add x0, x0, #off: unscaled.
        assert_eq!(
            encode_pageoff12(0x9100_0000, 0x123).unwrap(),
            0x9100_0000 | (0x123 << 10)
        );
        assert_eq!(
            encode_branch26(0x9400_0000, 0x1000, 0x2000).unwrap(),
            0x9400_0400
        );
        assert_eq!(
            encode_branch26(0x9400_0000, 0x2000, 0x1000).unwrap(),
            0x97ff_fc00
        );
        assert!(encode_branch26(0x9400_0000, 0, 1 << 28).is_err());
        assert_eq!(relax_ldr_to_add(0xf940_0210), Some(0x9100_0210));
        assert_eq!(relax_ldr_to_add(0x9100_0000), None);
    }

    #[test]
    fn x86_64_relaxation_and_stubs() {
        let mut code = [0x48, 0x8b, 0x05, 0, 0, 0, 0];
        apply(
            Arch::X86_64,
            Kind::GotLoad,
            &mut code,
            3,
            2,
            true,
            0x1003,
            0x2000,
            true,
        )
        .unwrap();
        assert_eq!(code[1], 0x8d);
        assert_eq!(u32le(&code, 3), 0x2000 - 0x1007);
        let mut stub = [0u8; 6];
        write_stub(Arch::X86_64, &mut stub, 0x1000, 0x3000);
        assert_eq!(stub[..2], [0xff, 0x25]);
        assert_eq!(u32le(&stub, 2), 0x3000 - 0x1006);
        assert_eq!(
            embedded_addend(
                Arch::X86_64,
                Kind::Signed(1),
                &[0xff, 0xff, 0xff, 0xff],
                0,
                2
            ),
            0
        );
    }
}
