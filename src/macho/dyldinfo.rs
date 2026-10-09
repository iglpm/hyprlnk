//! `LC_DYLD_INFO` contents: rebase and bind opcodes, and the export trie (also used with
//! chained fixups, in `LC_DYLD_EXPORTS_TRIE`).

use super::*;

pub const REBASE_TYPE_POINTER: u8 = 1;
pub const REBASE_OPCODE_DONE: u8 = 0x00;
pub const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
pub const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
pub const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
pub const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
pub const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB: u8 = 0x80;

pub const BIND_TYPE_POINTER: u8 = 1;
pub const BIND_SYMBOL_FLAGS_WEAK_IMPORT: u8 = 0x1;
pub const BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION: u8 = 0x8;
pub const BIND_OPCODE_DONE: u8 = 0x00;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
pub const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
pub const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
pub const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
pub const BIND_OPCODE_DO_BIND: u8 = 0x90;

pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u64 = 0x00;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64 = 0x01;
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u64 = 0x02;
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u64 = 0x04;

/// Rebase opcodes for pointers at (segment index, offset in segment), sorted.
pub fn encode_rebases(locs: &[(u8, u64)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(locs.len() / 2 + 16);
    if locs.is_empty() {
        return out;
    }
    out.push(REBASE_OPCODE_SET_TYPE_IMM | REBASE_TYPE_POINTER);
    let mut seg = u8::MAX;
    let mut cur = 0u64;
    let mut i = 0;
    while i < locs.len() {
        let (s, off) = locs[i];
        if s != seg || off < cur {
            out.push(REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | s);
            push_uleb(&mut out, off);
            seg = s;
        } else if off != cur {
            let d = off - cur;
            if d.is_multiple_of(8) && d / 8 < 16 {
                out.push(REBASE_OPCODE_ADD_ADDR_IMM_SCALED | (d / 8) as u8);
            } else {
                out.push(REBASE_OPCODE_ADD_ADDR_ULEB);
                push_uleb(&mut out, d);
            }
        }
        // A run of adjacent pointers.
        let mut j = i + 1;
        while j < locs.len() && locs[j].0 == s && locs[j].1 == locs[j - 1].1 + 8 {
            j += 1;
        }
        let run = j - i;
        if run == 1 && j + 1 < locs.len() && locs[j].0 == s && locs[j + 1].0 == s {
            // Equally spaced pointers (vtables, descriptors): one opcode for all of them.
            let stride = locs[j].1 - off;
            let mut k = j + 1;
            while k < locs.len() && locs[k].0 == s && locs[k].1 - locs[k - 1].1 == stride {
                k += 1;
            }
            if k - i >= 3 && stride > 8 {
                out.push(REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB);
                push_uleb(&mut out, (k - i) as u64);
                push_uleb(&mut out, stride - 8);
                // dyld steps a whole stride after each, the last one too.
                cur = locs[k - 1].1 + stride;
                i = k;
                continue;
            }
        }
        if run < 16 {
            out.push(REBASE_OPCODE_DO_REBASE_IMM_TIMES | run as u8);
        } else {
            out.push(REBASE_OPCODE_DO_REBASE_ULEB_TIMES);
            push_uleb(&mut out, run as u64);
        }
        cur = locs[j - 1].1 + 8;
        i = j;
    }
    out.push(REBASE_OPCODE_DONE);
    pad8(&mut out);
    out
}

pub struct Bind<'a> {
    pub seg: u8,
    pub off: u64,
    pub ordinal: i32,
    pub name: &'a [u8],
    pub flags: u8,
    pub addend: i64,
}

/// Bind opcodes, grouped by symbol (one name per run of locations), sorted by the caller.
pub fn encode_binds(binds: &[Bind]) -> Vec<u8> {
    let mut out = Vec::new();
    if binds.is_empty() {
        return out;
    }
    let mut ordinal = i32::MIN;
    let mut name: &[u8] = b"\xff";
    let mut flags = u8::MAX;
    let mut addend = 0i64;
    let mut seg = u8::MAX;
    let mut cur = 0u64;
    let mut typed = false;
    for b in binds {
        if b.ordinal != ordinal {
            if b.ordinal <= 0 {
                out.push(BIND_OPCODE_SET_DYLIB_SPECIAL_IMM | (b.ordinal as u8 & 0x0f));
            } else if b.ordinal < 16 {
                out.push(BIND_OPCODE_SET_DYLIB_ORDINAL_IMM | b.ordinal as u8);
            } else {
                out.push(BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB);
                push_uleb(&mut out, b.ordinal as u64);
            }
            ordinal = b.ordinal;
        }
        if b.name != name || b.flags != flags {
            out.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | b.flags);
            out.extend_from_slice(b.name);
            out.push(0);
            name = b.name;
            flags = b.flags;
        }
        if !typed {
            out.push(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER);
            typed = true;
        }
        if b.addend != addend {
            out.push(BIND_OPCODE_SET_ADDEND_SLEB);
            push_sleb(&mut out, b.addend);
            addend = b.addend;
        }
        if b.seg != seg || b.off < cur {
            out.push(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | b.seg);
            push_uleb(&mut out, b.off);
            seg = b.seg;
        } else if b.off != cur {
            out.push(BIND_OPCODE_ADD_ADDR_ULEB);
            push_uleb(&mut out, b.off - cur);
        }
        out.push(BIND_OPCODE_DO_BIND);
        cur = b.off + 8;
    }
    out.push(BIND_OPCODE_DONE);
    pad8(&mut out);
    out
}

/// Weak binding: strong definitions that override weak ones first, then every pointer to a
/// weak definition, sorted by name (dyld coalesces by walking it in order).
pub fn encode_weak_binds(overrides: &[&[u8]], binds: &[Bind]) -> Vec<u8> {
    let mut out = Vec::new();
    if overrides.is_empty() && binds.is_empty() {
        return out;
    }
    let mut names: Vec<&[u8]> = overrides.to_vec();
    names.sort();
    for n in names {
        out.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM | BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION);
        out.extend_from_slice(n);
        out.push(0);
    }
    let mut name: &[u8] = b"\xff";
    let mut seg = u8::MAX;
    let mut cur = 0u64;
    let mut addend = 0i64;
    let mut typed = false;
    for b in binds {
        if b.name != name {
            out.push(BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM);
            out.extend_from_slice(b.name);
            out.push(0);
            name = b.name;
        }
        if !typed {
            out.push(BIND_OPCODE_SET_TYPE_IMM | BIND_TYPE_POINTER);
            typed = true;
        }
        if b.addend != addend {
            out.push(BIND_OPCODE_SET_ADDEND_SLEB);
            push_sleb(&mut out, b.addend);
            addend = b.addend;
        }
        if b.seg != seg || b.off < cur {
            out.push(BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | b.seg);
            push_uleb(&mut out, b.off);
            seg = b.seg;
        } else if b.off != cur {
            out.push(BIND_OPCODE_ADD_ADDR_ULEB);
            push_uleb(&mut out, b.off - cur);
        }
        out.push(BIND_OPCODE_DO_BIND);
        cur = b.off + 8;
    }
    out.push(BIND_OPCODE_DONE);
    pad8(&mut out);
    out
}

pub fn pad8(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(8) {
        v.push(0);
    }
}

pub struct ExportEntry<'a> {
    pub name: &'a [u8],
    pub flags: u64,
    /// Offset from the image base.
    pub addr: u64,
}

/// Sort by name, comparing 16-byte prefixes kept beside each entry before whole names:
/// most comparisons then never touch the (scattered) name bytes.
pub fn sort_by_name(v: &mut Vec<ExportEntry>) {
    use rayon::prelude::*;
    fn key(n: &[u8], at: usize) -> u64 {
        let mut b = [0u8; 8];
        let s = n.get(at..).unwrap_or(&[]);
        let k = s.len().min(8);
        b[..k].copy_from_slice(&s[..k]);
        u64::from_be_bytes(b)
    }
    let mut keyed: Vec<(u64, u64, u32)> = v
        .par_iter()
        .enumerate()
        .map(|(i, e)| (key(e.name, 0), key(e.name, 8), i as u32))
        .collect();
    keyed.par_sort_unstable_by(|a, b| {
        (a.0, a.1).cmp(&(b.0, b.1)).then_with(|| {
            let (x, y) = (v[a.2 as usize].name, v[b.2 as usize].name);
            x.get(16..)
                .unwrap_or(&[])
                .cmp(y.get(16..).unwrap_or(&[]))
                .then(x.len().cmp(&y.len()))
        })
    });
    let mut out: Vec<ExportEntry> = keyed
        .par_iter()
        .map(|k| {
            let e = &v[k.2 as usize];
            ExportEntry {
                name: e.name,
                flags: e.flags,
                addr: e.addr,
            }
        })
        .collect();
    std::mem::swap(v, &mut out);
}

struct TrieNodes {
    depth: Vec<u32>,
    rep: Vec<u32>,
    term: Vec<u32>,
    first: Vec<u32>,
    last: Vec<u32>,
    next: Vec<u32>,
    prev: Vec<u32>,
}

impl TrieNodes {
    fn add(&mut self, d: u32, r: u32, term: u32) -> u32 {
        self.depth.push(d);
        self.rep.push(r);
        self.term.push(term);
        self.first.push(u32::MAX);
        self.last.push(u32::MAX);
        self.next.push(u32::MAX);
        self.prev.push(u32::MAX);
        (self.depth.len() - 1) as u32
    }
}

/// The export trie for `entries`, which must be sorted by name with no duplicates.
///
/// Built in one pass over the longest common prefixes of neighbouring names (computed in
/// parallel): a stack holds the path to the last name; a smaller common prefix pops it, and a
/// prefix ending mid-edge splits that edge. Nodes are then renumbered in preorder, the order
/// they are written in, and their offsets iterated until the ULEB sizes settle.
pub fn build_trie(entries: &[ExportEntry]) -> Vec<u8> {
    use rayon::prelude::*;
    const NIL: u32 = u32::MAX;
    let n = entries.len();
    if n == 0 {
        return Vec::new();
    }
    let lcp: Vec<u32> = (0..n)
        .into_par_iter()
        .map(|i| {
            if i == 0 {
                return 0;
            }
            let (a, b) = (entries[i - 1].name, entries[i].name);
            let m = a.len().min(b.len());
            let mut k = 0;
            while k + 8 <= m && a[k..k + 8] == b[k..k + 8] {
                k += 8;
            }
            while k < m && a[k] == b[k] {
                k += 1;
            }
            k as u32
        })
        .collect();

    // Node arrays: depth, an entry whose name spells the path, terminal entry, child links.
    let cap = 2 * n + 1;
    let mut t = TrieNodes {
        depth: Vec::with_capacity(cap),
        rep: Vec::with_capacity(cap),
        term: Vec::with_capacity(cap),
        first: Vec::with_capacity(cap),
        last: Vec::with_capacity(cap),
        next: Vec::with_capacity(cap),
        prev: Vec::with_capacity(cap),
    };
    let root = t.add(0, 0, NIL);
    let mut stack: Vec<u32> = vec![root];
    for i in 0..n {
        let l = lcp[i];
        let mut popped = NIL;
        while t.depth[*stack.last().unwrap() as usize] > l {
            popped = stack.pop().unwrap();
        }
        let top = *stack.last().unwrap();
        if t.depth[top as usize] < l {
            // The common prefix ends inside the edge top → popped: split it.
            let mid = t.add(l, t.rep[popped as usize], NIL);
            let (p, nx) = (t.prev[popped as usize], t.next[popped as usize]);
            t.prev[mid as usize] = p;
            t.next[mid as usize] = nx;
            if p == NIL {
                t.first[top as usize] = mid;
            } else {
                t.next[p as usize] = mid;
            }
            if t.last[top as usize] == popped {
                t.last[top as usize] = mid;
            }
            t.first[mid as usize] = popped;
            t.last[mid as usize] = popped;
            t.prev[popped as usize] = NIL;
            t.next[popped as usize] = NIL;
            stack.push(mid);
        }
        let top = *stack.last().unwrap();
        let len = entries[i].name.len() as u32;
        if len == t.depth[top as usize] {
            t.term[top as usize] = i as u32;
            continue;
        }
        let leaf = t.add(len, i as u32, i as u32);
        let lc = t.last[top as usize];
        if lc == NIL {
            t.first[top as usize] = leaf;
        } else {
            t.next[lc as usize] = leaf;
            t.prev[leaf as usize] = lc;
        }
        t.last[top as usize] = leaf;
        stack.push(leaf);
    }

    let TrieNodes {
        depth,
        rep,
        term,
        first,
        next,
        ..
    } = t;
    // Preorder, and children by preorder index.
    let count = depth.len();
    let mut order: Vec<u32> = Vec::with_capacity(count);
    let mut st = vec![root];
    while let Some(v) = st.pop() {
        order.push(v);
        // The next sibling waits under the first child, which comes out first.
        if v != root && next[v as usize] != NIL {
            st.push(next[v as usize]);
        }
        if first[v as usize] != NIL {
            st.push(first[v as usize]);
        }
    }
    let mut pre = vec![0u32; count];
    for (k, &v) in order.iter().enumerate() {
        pre[v as usize] = k as u32;
    }
    // Per preorder node: terminal, depth, rep, and its children's range in `kids`.
    let mut kids: Vec<u32> = Vec::with_capacity(count);
    let mut kid_range: Vec<(u32, u32)> = Vec::with_capacity(count);
    for &v in &order {
        let start = kids.len() as u32;
        let mut c = first[v as usize];
        while c != NIL {
            kids.push(pre[c as usize]);
            c = next[c as usize];
        }
        kid_range.push((start, kids.len() as u32));
    }
    let pdepth: Vec<u32> = order.iter().map(|&v| depth[v as usize]).collect();
    let prep: Vec<u32> = order.iter().map(|&v| rep[v as usize]).collect();
    let pterm: Vec<u32> = order.iter().map(|&v| term[v as usize]).collect();
    let term_size = |t: u32| -> usize {
        if t == NIL {
            0
        } else {
            let e = &entries[t as usize];
            uleb_len(e.flags) + uleb_len(e.addr)
        }
    };
    let fixed: Vec<usize> = (0..count)
        .into_par_iter()
        .map(|k| {
            let ts = term_size(pterm[k]);
            let (a, b) = kid_range[k];
            let labels: usize = kids[a as usize..b as usize]
                .iter()
                .map(|&c| (pdepth[c as usize] - pdepth[k]) as usize + 1)
                .sum();
            uleb_len(ts as u64) + ts + 1 + labels
        })
        .collect();
    // Offsets: node sizes from the previous offsets, then a prefix sum; repeat until stable.
    let mut offset = vec![0u32; count];
    let mut total = 0usize;
    const BLOCK: usize = 4096;
    for _ in 0..32 {
        let sizes: Vec<u32> = (0..count)
            .into_par_iter()
            .map(|k| {
                let (a, b) = kid_range[k];
                let mut size = fixed[k];
                for &c in &kids[a as usize..b as usize] {
                    size += uleb_len(offset[c as usize] as u64);
                }
                size as u32
            })
            .collect();
        let block_sums: Vec<u64> = sizes
            .par_chunks(BLOCK)
            .map(|c| c.iter().map(|&x| x as u64).sum())
            .collect();
        let mut block_start = Vec::with_capacity(block_sums.len());
        let mut acc = 0u64;
        for s in &block_sums {
            block_start.push(acc);
            acc += s;
        }
        total = acc as usize;
        let changed = offset
            .par_chunks_mut(BLOCK)
            .zip(sizes.par_chunks(BLOCK))
            .zip(block_start.par_iter())
            .map(|((offs, sz), &start)| {
                let mut o = start;
                let mut changed = false;
                for (dst, &s) in offs.iter_mut().zip(sz) {
                    if *dst != o as u32 {
                        *dst = o as u32;
                        changed = true;
                    }
                    o += s as u64;
                }
                changed
            })
            .reduce(|| false, |a, b| a || b);
        if !changed {
            break;
        }
    }
    // Each block of nodes writes its own slice of the output.
    let mut out = vec![0u8; total];
    let mut pieces: Vec<(usize, usize)> = Vec::new();
    for start in (0..count).step_by(BLOCK) {
        let end = (start + BLOCK).min(count);
        let lo = offset[start] as usize;
        let hi = if end < count {
            offset[end] as usize
        } else {
            total
        };
        pieces.push((lo, hi - lo));
    }
    let slices = super::linkedit::split_pieces(&mut out, &pieces);
    slices.into_par_iter().enumerate().for_each(|(bi, dst)| {
        let start = bi * BLOCK;
        let end = (start + BLOCK).min(count);
        let mut w: Vec<u8> = Vec::with_capacity(dst.len());
        for k in start..end {
            let t = pterm[k];
            if t == NIL {
                w.push(0);
            } else {
                let e = &entries[t as usize];
                push_uleb(&mut w, (uleb_len(e.flags) + uleb_len(e.addr)) as u64);
                push_uleb(&mut w, e.flags);
                push_uleb(&mut w, e.addr);
            }
            let (a, b) = kid_range[k];
            w.push((b - a) as u8);
            for &c in &kids[a as usize..b as usize] {
                let name = entries[prep[c as usize] as usize].name;
                w.extend_from_slice(&name[pdepth[k] as usize..pdepth[c as usize] as usize]);
                w.push(0);
                push_uleb(&mut w, offset[c as usize] as u64);
            }
        }
        dst.copy_from_slice(&w);
    });
    pad8(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::macho::dylib::tests_walk;

    #[test]
    fn rebases_compress_runs_and_strides() {
        let locs: Vec<(u8, u64)> = vec![
            (2, 0),
            (2, 8),
            (2, 16),
            (2, 64),
            (2, 96),
            (2, 128),
            (2, 160),
            (2, 168),
            (2, 400),
            (3, 0x10),
        ];
        let ops = encode_rebases(&locs);
        assert_eq!(ops[0], REBASE_OPCODE_SET_TYPE_IMM | 1);
        assert_eq!(ops[1], REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB | 2);
        assert!(ops.contains(&(REBASE_OPCODE_DO_REBASE_IMM_TIMES | 3)));
        assert!(ops.contains(&REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB));
        assert_eq!(ops.len() % 8, 0);
        assert_eq!(decode_rebases(&ops), locs);
    }

    fn decode_rebases(ops: &[u8]) -> Vec<(u8, u64)> {
        let mut out = Vec::new();
        let (mut seg, mut addr) = (0u8, 0u64);
        let mut p = 0;
        while p < ops.len() {
            let b = ops[p];
            p += 1;
            let imm = b & 0x0f;
            match b & 0xf0 {
                REBASE_OPCODE_DONE => break,
                REBASE_OPCODE_SET_TYPE_IMM => {}
                REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                    seg = imm;
                    addr = read_uleb(ops, &mut p).unwrap();
                }
                REBASE_OPCODE_ADD_ADDR_ULEB => addr += read_uleb(ops, &mut p).unwrap(),
                REBASE_OPCODE_ADD_ADDR_IMM_SCALED => addr += imm as u64 * 8,
                REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                    for _ in 0..imm {
                        out.push((seg, addr));
                        addr += 8;
                    }
                }
                REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                    for _ in 0..read_uleb(ops, &mut p).unwrap() {
                        out.push((seg, addr));
                        addr += 8;
                    }
                }
                REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB => {
                    let n = read_uleb(ops, &mut p).unwrap();
                    let skip = read_uleb(ops, &mut p).unwrap();
                    for _ in 0..n {
                        out.push((seg, addr));
                        addr += 8 + skip;
                    }
                }
                _ => panic!("bad opcode {b:#x}"),
            }
        }
        out
    }

    #[test]
    fn tries_round_trip() {
        let names: Vec<Vec<u8>> = [
            "__mh_execute_header",
            "_a",
            "_ab",
            "_abc",
            "_abd",
            "_b",
            "_main",
            "_mainly",
            "_x86",
        ]
        .iter()
        .map(|s| s.as_bytes().to_vec())
        .collect();
        let entries: Vec<ExportEntry> = names
            .iter()
            .enumerate()
            .map(|(i, n)| ExportEntry {
                name: n,
                flags: (i % 2) as u64 * 4,
                addr: 0x1000 + i as u64 * 0x10,
            })
            .collect();
        let trie = build_trie(&entries);
        let mut got = tests_walk(&trie);
        got.sort();
        let mut want: Vec<(Vec<u8>, bool)> = entries
            .iter()
            .map(|e| (e.name.to_vec(), e.flags & 4 != 0))
            .collect();
        want.sort();
        assert_eq!(got, want);
    }
}
