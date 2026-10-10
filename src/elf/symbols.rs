//! The global symbol table. Names are interned in two parallel passes — per group of files:
//! hash and bucket by shard; per shard: insert in file order — so ids are the same on every
//! run, without locks. Names are told apart by 128-bit hashes (as merged strings are), so a
//! name that is already known is never read again. Resolution keeps the best definition of
//! each symbol in one atomic word.

use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use hashbrown::HashTable;
use rayon::prelude::*;

use super::NONE;

pub type SymId = u32;

const SHARD_BITS: u32 = 8;
pub const SHARDS: usize = 1 << SHARD_BITS;
const LOCAL_BITS: u32 = 32 - SHARD_BITS;

// Definition ranks: lower wins. `pack(class, prio, index)`.
pub const CLASS_STRONG: u64 = 0;
pub const CLASS_WEAK: u64 = 1;
pub const CLASS_COMMON: u64 = 2;
pub const CLASS_INTERNAL: u64 = 3;
/// A shared object's definition (and, while finding archive members to load, a member's).
pub const CLASS_LAZY: u64 = 4;
pub const UNDEF: u64 = u64::MAX;

#[inline]
pub fn pack(class: u64, prio: u32, index: u32) -> u64 {
    (class << 60) | ((prio as u64 & 0x0fff_ffff) << 32) | index as u64
}
#[inline]
pub fn def_class(d: u64) -> u64 {
    d >> 60
}
#[inline]
pub fn def_prio(d: u64) -> u32 {
    ((d >> 32) & 0x0fff_ffff) as u32
}
#[inline]
pub fn def_index(d: u64) -> u32 {
    d as u32
}

// Symbol flags.
pub const NEEDS_GOT: u32 = 1 << 0;
pub const NEEDS_PLT: u32 = 1 << 1;
/// A canonical PLT entry: the function's address in the executable is its PLT entry.
pub const NEEDS_CPLT: u32 = 1 << 2;
pub const NEEDS_COPY: u32 = 1 << 3;
pub const NEEDS_GOTTP: u32 = 1 << 4;
pub const NEEDS_TLSGD: u32 = 1 << 5;
pub const NEEDS_TLSDESC: u32 = 1 << 6;
pub const NEEDS_DYNSYM: u32 = 1 << 7;
pub const EXPORTED: u32 = 1 << 8;
pub const PREEMPTIBLE: u32 = 1 << 9;
pub const REF_BY_DSO: u32 = 1 << 10;
pub const IMPORTED: u32 = 1 << 11;
pub const IS_FUNC: u32 = 1 << 12;
pub const IS_IFUNC: u32 = 1 << 13;
pub const IS_TLS: u32 = 1 << 14;
pub const IS_ABS: u32 = 1 << 15;
/// Referenced by a non-weak undefined symbol.
pub const STRONG_REF: u32 = 1 << 16;
pub const REFERENCED: u32 = 1 << 17;
/// Defined, but by `--wrap` or `--defsym`, or by the linker.
pub const LINKER_DEFINED: u32 = 1 << 18;
/// Hidden by a version script or visibility: stays out of `.dynsym`.
pub const LOCALIZED: u32 = 1 << 21;
/// Referenced by a relocation of a live section.
pub const USED: u32 = 1 << 23;

pub const ANY_GOT: u32 = NEEDS_GOT | NEEDS_GOTTP | NEEDS_TLSGD | NEEDS_TLSDESC;

pub struct Symbol<'a> {
    pub name: &'a [u8],
    pub def: AtomicU64,
    /// The lowest priority of a live file referencing it.
    pub first_ref: AtomicU32,
    pub flags: AtomicU32,
    /// The most restrictive visibility seen: 0 default, 1 protected, 2 hidden.
    pub vis: AtomicU8,
    /// Index into the per-symbol slot table (GOT, PLT, `.dynsym`), or NONE.
    pub aux: AtomicU32,
    /// The final address (after layout).
    pub addr: AtomicU64,
    /// The version index it is exported or imported with.
    pub ver: AtomicU32,
}

impl Symbol<'_> {
    #[inline]
    pub fn def(&self) -> u64 {
        self.def.load(Ordering::Relaxed)
    }
    #[inline]
    pub fn flags(&self) -> u32 {
        self.flags.load(Ordering::Relaxed)
    }
    #[inline]
    pub fn has(&self, f: u32) -> bool {
        self.flags() & f != 0
    }
    /// Set flags, skipping the atomic write when they are already set (shared symbols are
    /// referenced from every thread).
    #[inline]
    pub fn set(&self, f: u32) {
        if self.flags() & f != f {
            self.flags.fetch_or(f, Ordering::Relaxed);
        }
    }
    #[inline]
    pub fn addr(&self) -> u64 {
        self.addr.load(Ordering::Relaxed)
    }
    #[inline]
    pub fn aux(&self) -> u32 {
        self.aux.load(Ordering::Relaxed)
    }
}

/// A name's 128-bit hash: equal hashes are equal names.
pub type NameHash = [u64; 2];

pub struct SymbolTable<'a> {
    pub shards: Vec<Vec<Symbol<'a>>>,
    /// Per shard: each symbol's name hash, by local id.
    hashes: Vec<Vec<NameHash>>,
    tables: Vec<HashTable<u32>>,
}

/// A name to intern: the name, its hash, and the rank of the definition it is (or [`UNDEF`]).
pub type Named<'a> = (&'a [u8], NameHash, u64);

/// One file's names to intern: `names[i]` gets an id written to `out[i]` (empty names are
/// skipped), and each symbol starts out with the best of its definitions' ranks.
pub struct Batch<'a, 's> {
    pub names: Vec<Named<'a>>,
    pub out: &'s [AtomicU32],
}

#[inline]
pub fn hash_name(n: &[u8]) -> NameHash {
    let h = xxhash_rust::xxh3::xxh3_128(n);
    [h as u64, (h >> 64) as u64]
}

/// The shard comes from the first half's top bits, so the tables hash by the second half.
#[inline]
fn shard_of(h: NameHash) -> usize {
    (h[0] >> (64 - SHARD_BITS)) as usize
}

/// A name occurrence, as its shard sees it.
#[derive(Clone, Copy)]
struct Rec {
    hash: NameHash,
    def: u64,
    batch: u32,
    index: u32,
}

/// A group of files' occurrences, by shard.
struct Bucketed {
    recs: Vec<Rec>,
    starts: Vec<u32>,
}

impl<'a> SymbolTable<'a> {
    #[inline]
    pub fn get(&self, id: SymId) -> &Symbol<'a> {
        &self.shards[(id >> LOCAL_BITS) as usize][(id & ((1 << LOCAL_BITS) - 1)) as usize]
    }

    pub fn len(&self) -> usize {
        self.shards.iter().map(Vec::len).sum()
    }

    /// The ids of the symbols `keep` accepts, in id order, found on all threads.
    pub fn par_filter(&self, keep: impl Fn(&Symbol<'a>) -> bool + Sync + Send) -> Vec<SymId> {
        let per_shard: Vec<Vec<SymId>> = self
            .shards
            .par_iter()
            .enumerate()
            .map(|(s, v)| {
                v.iter()
                    .enumerate()
                    .filter(|(_, sym)| keep(sym))
                    .map(|(i, _)| ((s as u32) << LOCAL_BITS) | i as u32)
                    .collect()
            })
            .collect();
        per_shard.concat()
    }

    pub fn par_for_each(&self, f: impl Fn(SymId, &Symbol<'a>) + Sync + Send) {
        self.shards.par_iter().enumerate().for_each(|(s, v)| {
            for (i, sym) in v.iter().enumerate() {
                f(((s as u32) << LOCAL_BITS) | i as u32, sym);
            }
        });
    }

    pub fn find(&self, name: &[u8]) -> Option<SymId> {
        let h = hash_name(name);
        let s = shard_of(h);
        let hashes = &self.hashes[s];
        self.tables[s]
            .find(h[1], |&id| hashes[id as usize] == h)
            .map(|&id| ((s as u32) << LOCAL_BITS) | id)
    }

    /// Add a name after interning (linker-made symbols); returns the existing id if any.
    pub fn insert(&mut self, name: &'a [u8]) -> SymId {
        if let Some(id) = self.find(name) {
            return id;
        }
        let h = hash_name(name);
        let s = shard_of(h);
        let id = self.shards[s].len() as u32;
        self.shards[s].push(new_symbol(name));
        self.hashes[s].push(h);
        let hashes = &self.hashes[s];
        self.tables[s].insert_unique(h[1], id, |&x| hashes[x as usize][1]);
        ((s as u32) << LOCAL_BITS) | id
    }

    pub fn intern(batches: &[Batch<'a, '_>]) -> SymbolTable<'a> {
        // Groups of about the same number of names, in file order — runs of files, or parts of
        // a big one — so each shard visits a few buckets, in order.
        let total: usize = batches.iter().map(|b| b.names.len()).sum();
        let per = (total / (rayon::current_num_threads() * 4)).max(4096);
        let mut groups: Vec<Vec<(usize, usize, usize)>> = vec![Vec::new()];
        let mut acc = 0;
        for (bi, b) in batches.iter().enumerate() {
            let mut lo = 0;
            while lo < b.names.len() {
                let take = (per - acc).min(b.names.len() - lo);
                groups.last_mut().unwrap().push((bi, lo, lo + take));
                acc += take;
                lo += take;
                if acc >= per {
                    groups.push(Vec::new());
                    acc = 0;
                }
            }
        }
        let bucketed: Vec<Bucketed> = groups
            .par_iter()
            .map(|g| {
                let mut counts = vec![0u32; SHARDS + 1];
                for &(bi, lo, hi) in g {
                    for &(n, h, _) in &batches[bi].names[lo..hi] {
                        if !n.is_empty() {
                            counts[shard_of(h) + 1] += 1;
                        }
                    }
                }
                for s in 0..SHARDS {
                    counts[s + 1] += counts[s];
                }
                let empty = Rec {
                    hash: [0; 2],
                    def: UNDEF,
                    batch: 0,
                    index: 0,
                };
                let mut recs = vec![empty; counts[SHARDS] as usize];
                let mut pos = counts.clone();
                for &(bi, lo, hi) in g {
                    for (i, &(n, h, def)) in batches[bi].names[lo..hi].iter().enumerate() {
                        if n.is_empty() {
                            continue;
                        }
                        let s = shard_of(h);
                        recs[pos[s] as usize] = Rec {
                            hash: h,
                            def,
                            batch: bi as u32,
                            index: (lo + i) as u32,
                        };
                        pos[s] += 1;
                    }
                }
                Bucketed {
                    recs,
                    starts: counts,
                }
            })
            .collect();
        type Shard<'s> = (Vec<Symbol<'s>>, Vec<NameHash>, HashTable<u32>);
        let shards: Vec<Shard<'a>> = (0..SHARDS)
            .into_par_iter()
            .map(|s| {
                let mut syms: Vec<Symbol<'a>> = Vec::new();
                let mut hashes: Vec<NameHash> = Vec::new();
                let mut table: HashTable<u32> = HashTable::new();
                for bk in &bucketed {
                    let range = bk.starts[s] as usize..bk.starts[s + 1] as usize;
                    for r in &bk.recs[range] {
                        let h = r.hash;
                        let local = match table.find(h[1], |&id| hashes[id as usize] == h) {
                            Some(&id) => id,
                            None => {
                                let id = syms.len() as u32;
                                let b = &batches[r.batch as usize];
                                syms.push(new_symbol(b.names[r.index as usize].0));
                                hashes.push(h);
                                table.insert_unique(h[1], id, |&x| hashes[x as usize][1]);
                                id
                            }
                        };
                        // This thread owns the shard: the best definition needs no atomics.
                        let def = syms[local as usize].def.get_mut();
                        *def = (*def).min(r.def);
                        batches[r.batch as usize].out[r.index as usize]
                            .store(((s as u32) << LOCAL_BITS) | local, Ordering::Relaxed);
                    }
                }
                (syms, hashes, table)
            })
            .collect();
        let mut t = SymbolTable {
            shards: Vec::with_capacity(SHARDS),
            hashes: Vec::with_capacity(SHARDS),
            tables: Vec::with_capacity(SHARDS),
        };
        for (syms, hashes, table) in shards {
            t.shards.push(syms);
            t.hashes.push(hashes);
            t.tables.push(table);
        }
        t
    }
}

fn new_symbol(name: &[u8]) -> Symbol<'_> {
    Symbol {
        name,
        def: AtomicU64::new(UNDEF),
        first_ref: AtomicU32::new(NONE),
        flags: AtomicU32::new(0),
        vis: AtomicU8::new(0),
        aux: AtomicU32::new(NONE),
        addr: AtomicU64::new(0),
        ver: AtomicU32::new(super::VER_NDX_GLOBAL as u32),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interning_is_deterministic_and_dedupes() {
        let names: Vec<Vec<u8>> = (0..5000)
            .map(|i| format!("sym{}", i % 3000).into_bytes())
            .collect();
        let outs: Vec<AtomicU32> = names.iter().map(|_| AtomicU32::new(NONE)).collect();
        let outs2: Vec<AtomicU32> = names.iter().map(|_| AtomicU32::new(NONE)).collect();
        let (a, b) = names.split_at(2500);
        let batches = vec![
            Batch {
                names: a
                    .iter()
                    .map(|n| (n.as_slice(), hash_name(n), UNDEF))
                    .collect(),
                out: &outs[..2500],
            },
            Batch {
                names: b
                    .iter()
                    .map(|n| (n.as_slice(), hash_name(n), UNDEF))
                    .collect(),
                out: &outs[2500..],
            },
        ];
        let t = SymbolTable::intern(&batches);
        assert_eq!(t.len(), 3000);
        let batches2 = vec![
            Batch {
                names: a
                    .iter()
                    .map(|n| (n.as_slice(), hash_name(n), UNDEF))
                    .collect(),
                out: &outs2[..2500],
            },
            Batch {
                names: b
                    .iter()
                    .map(|n| (n.as_slice(), hash_name(n), UNDEF))
                    .collect(),
                out: &outs2[2500..],
            },
        ];
        let t2 = SymbolTable::intern(&batches2);
        for (x, y) in outs.iter().zip(&outs2) {
            assert_eq!(x.load(Ordering::Relaxed), y.load(Ordering::Relaxed));
        }
        for (i, n) in names.iter().enumerate() {
            let id = outs[i].load(Ordering::Relaxed);
            assert_eq!(t.get(id).name, n.as_slice());
            assert_eq!(t2.find(n), Some(id));
        }
        // "sym5" appears at index 5 and 3005: same id.
        assert_eq!(
            outs[5].load(Ordering::Relaxed),
            outs[3005].load(Ordering::Relaxed)
        );
    }

    #[test]
    fn ranks_order_by_class_then_priority() {
        assert!(pack(CLASS_STRONG, 9, 0) < pack(CLASS_WEAK, 1, 0));
        assert!(pack(CLASS_LAZY, 1, 5) < pack(CLASS_LAZY, 2, 0));
        let d = pack(CLASS_COMMON, 1234, 77);
        assert_eq!(
            (def_class(d), def_prio(d), def_index(d)),
            (CLASS_COMMON, 1234, 77)
        );
        assert!(pack(CLASS_LAZY, 0x0fff_ffff, u32::MAX) < UNDEF);
    }
}
