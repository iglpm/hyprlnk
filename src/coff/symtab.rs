//! The global symbol table, keyed by name hashes precomputed on the parsing threads.

use hashbrown::HashTable;

pub type SymId = u32;

#[inline]
pub fn hash_name(name: &[u8]) -> u64 {
    xxhash_rust::xxh3::xxh3_64(name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Def {
    Undefined,
    Lazy { archive: u32, offset: u32 },
    Defined { obj: u32, sec: u32, value: u32 },
    Absolute { va: u64 },
    Common { obj: u32, size: u32 },
    Import { imp: u32 },
    Thunk { imp: u32 },
    LocalImport { slot: u32 },
    Synthetic { chunk: u8, off: u32 },
    ImageBase,
}

impl Def {
    pub fn is_undefined(self) -> bool {
        matches!(self, Def::Undefined)
    }

    pub fn is_lazy(self) -> bool {
        matches!(self, Def::Lazy { .. })
    }

    pub fn is_defined(self) -> bool {
        !matches!(self, Def::Undefined | Def::Lazy { .. })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WeakAlias {
    Global(SymId),
    Local { obj: u32, sec: u32, value: u32 },
}

pub struct Symbol<'a> {
    pub name: &'a [u8],
    pub def: Def,
    pub first_ref: u32,
    pub comdat: bool,
    /// A linker default (e.g. `__guard_flags`) that a real definition replaces.
    pub replaceable: bool,
    pub weak_alias: Option<WeakAlias>,
    pub function: bool,
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
                    first_ref: referrer,
                    comdat: false,
                    replaceable: false,
                    weak_alias: None,
                    function: false,
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
        let (a, new_a) = t.intern(b"alpha", hash_name(b"alpha"), 0);
        let (b, new_b) = t.intern(b"beta", hash_name(b"beta"), 1);
        let (a2, new_a2) = t.intern(b"alpha", hash_name(b"alpha"), 2);
        assert!(new_a && new_b && !new_a2);
        assert_eq!(a, a2);
        assert_ne!(a, b);
        assert_eq!(t.find(b"beta"), Some(b));
        assert_eq!(t.find(b"gamma"), None);
        assert_eq!(t.get(a).first_ref, 0);
        let names: Vec<Vec<u8>> = (0..10_000)
            .map(|i| format!("sym{i}").into_bytes())
            .collect();
        for n in &names {
            t.intern(n, hash_name(n), 0);
        }
        assert_eq!(t.len(), 10_002);
        assert!(names.iter().all(|n| t.find(n).is_some()));
    }
}
