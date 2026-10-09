//! The global symbol table, keyed by name hashes precomputed on the parsing threads.

use std::sync::atomic::{AtomicU8, Ordering};

use hashbrown::HashTable;

pub type SymId = u32;

#[inline]
pub fn hash_name(name: &[u8]) -> u64 {
    xxhash_rust::xxh3::xxh3_64(name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Synthetic {
    /// `__mh_execute_header`, `__mh_dylib_header`, `__mh_bundle_header`, `___dso_handle`.
    Header,
    /// `section$start$SEG$sect` and friends: resolved after layout.
    SectionStart(u32),
    SectionEnd(u32),
    SegmentStart(u32),
    SegmentEnd(u32),
    /// A common symbol, allocated in `__DATA,__common`.
    Common(u32),
    /// `_objc_msgSend$<selector>`: a stub the linker writes in `__TEXT,__objc_stubs`.
    ObjcStub(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Def {
    Undefined,
    Lazy { archive: u32, offset: u32 },
    Defined { obj: u32, atom: u32, off: u32 },
    Absolute { value: u64 },
    Common { obj: u32, size: u64, align: u8 },
    Dylib { dylib: u32 },
    DynamicLookup,
    Synthetic(Synthetic),
}

impl Def {
    pub fn is_undefined(self) -> bool {
        matches!(self, Def::Undefined)
    }

    pub fn is_lazy(self) -> bool {
        matches!(self, Def::Lazy { .. })
    }

    /// Resolved to something this image or another provides.
    pub fn is_resolved(self) -> bool {
        !matches!(self, Def::Undefined | Def::Lazy { .. })
    }

    /// Bound by dyld at load time rather than fixed by the linker.
    pub fn is_imported(self) -> bool {
        matches!(self, Def::Dylib { .. } | Def::DynamicLookup)
    }
}

pub const NEEDS_GOT: u8 = 1;
pub const NEEDS_STUB: u8 = 2;
pub const NEEDS_TLVP: u8 = 4;
pub const LIVE: u8 = 16;
/// arm64e: a signed `__auth_got` slot (stub targets, personality routines).
pub const NEEDS_AUTH_GOT: u8 = 32;

pub struct Symbol<'a> {
    pub name: &'a [u8],
    pub def: Def,
    pub weak_def: bool,
    pub private_extern: bool,
    pub tlv: bool,
    pub no_dead_strip: bool,
    pub referenced_dynamically: bool,
    pub strong_ref: bool,
    pub weak_ref: bool,
    /// A strong definition here for a symbol some dylib defines weakly.
    pub overrides_weak: bool,
    pub first_ref: u32,
    pub flags: AtomicU8,
    pub got: u32,
    pub stub: u32,
    pub tlvp: u32,
    pub auth_got: u32,
}

impl Symbol<'_> {
    #[inline]
    pub fn has(&self, f: u8) -> bool {
        self.flags.load(Ordering::Relaxed) & f != 0
    }

    #[inline]
    pub fn set(&self, f: u8) {
        if self.flags.load(Ordering::Relaxed) & f != f {
            self.flags.fetch_or(f, Ordering::Relaxed);
        }
    }

    /// Imported with `BIND_SYMBOL_FLAGS_WEAK_IMPORT`: every reference was weak.
    pub fn weak_import(&self) -> bool {
        self.weak_ref && !self.strong_ref
    }
}

#[derive(Default)]
pub struct SymbolTable<'a> {
    pub syms: Vec<Symbol<'a>>,
    hashes: Vec<u64>,
    map: HashTable<SymId>,
}

impl<'a> SymbolTable<'a> {
    pub fn with_capacity(n: usize) -> Self {
        SymbolTable {
            syms: Vec::with_capacity(n),
            hashes: Vec::with_capacity(n),
            map: HashTable::with_capacity(n),
        }
    }

    pub fn len(&self) -> usize {
        self.syms.len()
    }

    pub fn find(&self, name: &[u8]) -> Option<SymId> {
        self.find_hashed(name, hash_name(name))
    }

    #[inline]
    pub fn find_hashed(&self, name: &[u8], hash: u64) -> Option<SymId> {
        let syms = &self.syms;
        self.map
            .find(hash, |&id| syms[id as usize].name == name)
            .copied()
    }

    #[inline]
    pub fn intern(&mut self, name: &'a [u8], hash: u64, referrer: u32) -> (SymId, bool) {
        let syms = &self.syms;
        let hashes = &self.hashes;
        match self.map.entry(
            hash,
            |&id| syms[id as usize].name == name,
            |&id| hashes[id as usize],
        ) {
            hashbrown::hash_table::Entry::Occupied(e) => (*e.get(), false),
            hashbrown::hash_table::Entry::Vacant(v) => {
                let id = self.syms.len() as SymId;
                v.insert(id);
                self.syms.push(Symbol {
                    name,
                    def: Def::Undefined,
                    weak_def: false,
                    private_extern: false,
                    tlv: false,
                    no_dead_strip: false,
                    referenced_dynamically: false,
                    strong_ref: false,
                    weak_ref: false,
                    overrides_weak: false,
                    first_ref: referrer,
                    flags: AtomicU8::new(0),
                    got: u32::MAX,
                    stub: u32::MAX,
                    tlvp: u32::MAX,
                    auth_got: u32::MAX,
                });
                self.hashes.push(hash);
                (id, true)
            }
        }
    }

    #[inline]
    pub fn get(&self, id: SymId) -> &Symbol<'a> {
        &self.syms[id as usize]
    }

    #[inline]
    pub fn get_mut(&mut self, id: SymId) -> &mut Symbol<'a> {
        &mut self.syms[id as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interns_and_finds() {
        let mut t = SymbolTable::default();
        let (a, new_a) = t.intern(b"_alpha", hash_name(b"_alpha"), 0);
        let (b, _) = t.intern(b"_beta", hash_name(b"_beta"), 1);
        let (a2, new_a2) = t.intern(b"_alpha", hash_name(b"_alpha"), 2);
        assert!(new_a && !new_a2);
        assert_eq!(a, a2);
        assert_ne!(a, b);
        assert_eq!(t.find(b"_beta"), Some(b));
        assert_eq!(t.find(b"_gamma"), None);
        t.get(a).set(NEEDS_GOT);
        assert!(t.get(a).has(NEEDS_GOT) && !t.get(a).has(NEEDS_STUB));
    }
}
