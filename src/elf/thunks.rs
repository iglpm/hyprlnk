//! Thunks: small pieces of code a branch goes through when it can't reach its target directly
//! — on ARM, to switch between ARM and Thumb state where the branch instruction can't. They
//! are requested while scanning, numbered in a fixed order, and placed after `.text`.

use std::sync::Mutex;

use super::layout::{Layout, Synthetic};
use super::resolve::Ctx;
use super::scan::SymRef;
use super::target::Target;
use super::*;

#[derive(Default)]
pub struct ThunkTable {
    pending: Mutex<Vec<(SymRef, u8)>>,
    /// Sorted: (target, kind). A thunk's index is its position.
    pub list: Vec<(SymRef, u8)>,
}

impl<'a, T: Target> Ctx<'a, T> {
    /// Branch(es) to `sym` need a thunk of `kind`.
    pub fn need_thunk(&self, sym: SymRef, kind: u8) {
        self.thunks.pending.lock().unwrap().push((sym, kind));
    }

    pub fn finalize_thunks(&mut self) {
        let mut v = std::mem::take(&mut *self.thunks.pending.lock().unwrap());
        v.sort_unstable();
        v.dedup();
        self.thunks.list = v;
    }

    pub fn thunk_addr(&self, lay: &Layout, sym: SymRef, kind: u8) -> Option<u64> {
        let i = self.thunks.list.binary_search(&(sym, kind)).ok()?;
        Some(lay.addr_of(Synthetic::Thunks) + i as u64 * T::THUNK_SIZE)
    }

    pub fn write_thunks(&self, lay: &Layout, out: OutBuf) {
        let Some(o) = lay.out(Synthetic::Thunks) else {
            return;
        };
        let buf = out.slice(o.offset, o.size);
        for (i, &(sym, kind)) in self.thunks.list.iter().enumerate() {
            let target = self.thunk_target(lay, sym);
            let at = o.addr + i as u64 * T::THUNK_SIZE;
            let b = &mut buf[i * T::THUNK_SIZE as usize..(i + 1) * T::THUNK_SIZE as usize];
            T::write_thunk(b, at, target, kind, lay.got + 0x8000);
        }
    }

    /// Where a thunk jumps: the symbol's PLT entry if it has one (on POWER: its slot, which
    /// the call stub loads), else the symbol.
    fn thunk_target(&self, lay: &Layout, sym: SymRef) -> u64 {
        if let Some(a) = self.aux_of(sym)
            && a.plt != NONE
            && (self.slot_imported(sym) || matches!(T::M, Machine::Ppc64 | Machine::Ppc64le))
        {
            if matches!(T::M, Machine::Ppc64 | Machine::Ppc64le) {
                let reserved = if self.has_dynamic {
                    T::GOTPLT_RESERVED
                } else {
                    0
                };
                return lay.gotplt + (reserved + a.plt as u64) * 8;
            }
            return lay.plt + T::PLT0_SIZE + a.plt as u64 * T::PLT_SIZE;
        }
        if sym.obj != NONE {
            return self.local_addr(&self.objs[sym.obj as usize], sym.idx);
        }
        self.syms.get(sym.idx).addr()
    }
}
