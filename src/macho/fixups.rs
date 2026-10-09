//! Chained fixups (`LC_DYLD_CHAINED_FIXUPS`): every rebase and bind is a pointer in place that
//! also links to the next one in its page; the load command lists where each page's chain starts
//! and the imported symbols.

use std::collections::HashMap;

use super::layout::Layout;
use super::*;
use crate::bail;
use crate::diag::Result;

pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;
pub const DYLD_CHAINED_PTR_64: u16 = 2;
pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xffff;
pub const DYLD_CHAINED_IMPORT: u32 = 1;
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;

/// A fixup: rebase to `target` (an unslid address), or bind to import `import`.
#[derive(Debug, Clone, Copy)]
pub struct Fixup {
    pub addr: u64,
    pub import: u32,
    pub target: u64,
    pub addend: i64,
    /// arm64e signing schema (`gc::auth`), or 0.
    pub auth: u32,
}

pub struct ChainPlan {
    pub blob: Vec<u8>,
    pub format: u16,
    pub inline_addends: bool,
    pub image_base: u64,
}

pub struct Import<'a> {
    pub ordinal: i32,
    pub name: &'a [u8],
    pub weak: bool,
    pub addend: i64,
}

/// Lay out the fixups blob. `fixups` must be sorted by address.
pub fn plan(
    layout: &Layout,
    fixups: &[Fixup],
    imports: &[Import],
    arm64e: bool,
) -> Result<ChainPlan> {
    let format = if arm64e {
        DYLD_CHAINED_PTR_ARM64E_USERLAND24
    } else {
        DYLD_CHAINED_PTR_64
    };
    let with_addends = imports.iter().any(|i| i.addend != 0);
    let page = layout.page;
    let mut blob = vec![0u8; 28];
    let starts_off = align_up(blob.len() as u64, 8) as usize;
    blob.resize(starts_off, 0);
    let nseg = layout.segments.len();
    // starts_in_image: count + one offset per segment.
    let image_hdr = 4 + 4 * nseg;
    blob.resize(starts_off + image_hdr, 0);
    put32(&mut blob, starts_off, nseg as u32);
    let mut i = 0;
    for (gi, g) in layout.segments.iter().enumerate() {
        let lo = i;
        while i < fixups.len() && fixups[i].addr < g.vmaddr + g.vmsize {
            if fixups[i].addr < g.vmaddr {
                bail!("fixup at {:#x} is outside every segment", fixups[i].addr);
            }
            i += 1;
        }
        if lo == i {
            continue;
        }
        let npages = g.vmsize.div_ceil(page) as usize;
        let at = align_up(blob.len() as u64, 8) as usize;
        let size = 22 + 2 * npages;
        blob.resize(at + size, 0);
        put32(&mut blob, starts_off + 4 + 4 * gi, (at - starts_off) as u32);
        put32(&mut blob, at, size as u32);
        put16(&mut blob, at + 4, page as u16);
        put16(&mut blob, at + 6, format);
        put64(&mut blob, at + 8, g.vmaddr - layout.image_base);
        put32(&mut blob, at + 16, 0);
        put16(&mut blob, at + 20, npages as u16);
        for p in 0..npages {
            put16(&mut blob, at + 22 + 2 * p, DYLD_CHAINED_PTR_START_NONE);
        }
        for f in &fixups[lo..i] {
            let p = ((f.addr - g.vmaddr) / page) as usize;
            let slot = at + 22 + 2 * p;
            if u16le(&blob, slot) == DYLD_CHAINED_PTR_START_NONE {
                put16(&mut blob, slot, ((f.addr - g.vmaddr) % page) as u16);
            }
        }
    }
    let imports_off = align_up(blob.len() as u64, 4) as usize;
    let entry = if with_addends { 8 } else { 4 };
    blob.resize(imports_off + entry * imports.len(), 0);
    let symbols_off = blob.len();
    let mut names: HashMap<&[u8], u32> = HashMap::new();
    let mut pool: Vec<u8> = vec![0];
    for (k, imp) in imports.iter().enumerate() {
        let off = *names.entry(imp.name).or_insert_with(|| {
            let o = pool.len() as u32;
            pool.extend_from_slice(imp.name);
            pool.push(0);
            o
        });
        if off >= 1 << 23 {
            bail!("too many imported symbol names for chained fixups");
        }
        let ord = (imp.ordinal as u32) & 0xff;
        let v = ord | (u32::from(imp.weak) << 8) | (off << 9);
        put32(&mut blob, imports_off + entry * k, v);
        if with_addends {
            put32(
                &mut blob,
                imports_off + entry * k + 4,
                imp.addend as i32 as u32,
            );
        }
    }
    blob.extend_from_slice(&pool);
    super::dyldinfo::pad8(&mut blob);
    put32(&mut blob, 0, 0);
    put32(&mut blob, 4, starts_off as u32);
    put32(&mut blob, 8, imports_off as u32);
    put32(&mut blob, 12, symbols_off as u32);
    put32(&mut blob, 16, imports.len() as u32);
    put32(
        &mut blob,
        20,
        if with_addends {
            DYLD_CHAINED_IMPORT_ADDEND
        } else {
            DYLD_CHAINED_IMPORT
        },
    );
    put32(&mut blob, 24, 0);
    Ok(ChainPlan {
        blob,
        format,
        inline_addends: !with_addends,
        image_base: layout.image_base,
    })
}

/// Write each fixup's chain entry into the image (`at` maps an address to a file offset). A
/// rebase's target is the address already written in place.
pub fn apply(
    file: &mut [u8],
    fixups: &[Fixup],
    plan: &ChainPlan,
    page: u64,
    at: impl Fn(u64) -> usize,
) -> Result<()> {
    for (k, f) in fixups.iter().enumerate() {
        let o = at(f.addr);
        let f = &Fixup {
            target: if f.import == u32::MAX {
                u64le(file, o)
            } else {
                0
            },
            ..*f
        };
        if !f.addr.is_multiple_of(4) {
            bail!("pointer at {:#x} is not aligned for chained fixups", f.addr);
        }
        let arm64e = plan.format == DYLD_CHAINED_PTR_ARM64E_USERLAND24;
        let next = match fixups.get(k + 1) {
            Some(n) if n.addr / page == f.addr / page => {
                let stride = if arm64e { 8 } else { 4 };
                if !(n.addr - f.addr).is_multiple_of(stride) {
                    bail!(
                        "pointers at {:#x} and {:#x} can't share a fixup chain",
                        f.addr,
                        n.addr
                    );
                }
                (n.addr - f.addr) / stride
            }
            _ => 0,
        };
        let v: u64 = if arm64e {
            // USERLAND24: 24-bit import ordinals, rebase targets as offsets from the image base.
            let signed = f.auth != 0;
            let schema = if signed {
                ((f.auth as u64 & 0xffff) << 32)
                    | (((f.auth as u64 >> 16) & 1) << 48)
                    | (((f.auth as u64 >> 17) & 3) << 49)
                    | (1 << 63)
            } else {
                0
            };
            if f.import != u32::MAX {
                let addend = if plan.inline_addends && !signed {
                    (f.addend as u64 & 0x7ffff) << 32
                } else {
                    0
                };
                (f.import as u64 & 0xff_ffff) | addend | ((next & 0x7ff) << 51) | (1 << 62) | schema
            } else {
                let off = f.target.wrapping_sub(plan.image_base);
                if signed {
                    if off > u32::MAX as u64 {
                        bail!(
                            "signed rebase target {:#x} is too far from the image base",
                            f.target
                        );
                    }
                    off | ((next & 0x7ff) << 51) | schema
                } else {
                    let high8 = f.target >> 56;
                    (off & 0x7ff_ffff_ffff) | (high8 << 43) | ((next & 0x7ff) << 51)
                }
            }
        } else if f.import != u32::MAX {
            let addend = if plan.inline_addends {
                f.addend as u64 & 0xff
            } else {
                0
            };
            (f.import as u64 & 0xff_ffff) | (addend << 24) | ((next & 0xfff) << 51) | (1 << 63)
        } else {
            if f.target & !0xff00_000f_ffff_ffff != 0 {
                bail!("rebase target {:#x} does not fit chained fixups", f.target);
            }
            let target = f.target & 0xf_ffff_ffff;
            let high8 = f.target >> 56;
            target | (high8 << 36) | ((next & 0xfff) << 51)
        };
        put64(file, o, v);
    }
    Ok(())
}
