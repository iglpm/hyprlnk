//! Inputs are memory-mapped and kept alive in an [`Arena`] so parsed data can borrow.

use std::fs::File;
use std::io;
use std::path::Path;
use std::sync::Mutex;

/// Files smaller than this are read: mapping costs a few system calls and a
/// page fault per page, more than copying a small file.
const MAP_THRESHOLD: u64 = 64 * 1024;

pub enum Bytes {
    Mapped(Mmap),
    Owned(Box<[u8]>),
}

impl Bytes {
    fn as_slice(&self) -> &[u8] {
        match self {
            Bytes::Mapped(m) => m.as_slice(),
            Bytes::Owned(b) => b,
        }
    }
}

pub fn load(path: &Path) -> io::Result<Bytes> {
    load_with_metadata(path).map(|(b, _)| b)
}

/// The file's bytes and its metadata, from one `open` and one `fstat`.
pub fn load_with_metadata(path: &Path) -> io::Result<(Bytes, std::fs::Metadata)> {
    let file = File::open(path)?;
    let meta = file.metadata()?;
    let len = meta.len();
    let bytes = if len < MAP_THRESHOLD {
        use std::io::Read;
        let mut buf = Vec::with_capacity(len as usize);
        (&file).read_to_end(&mut buf)?;
        Bytes::Owned(buf.into_boxed_slice())
    } else {
        Mmap::map(&file, len as usize).map(Bytes::Mapped)?
    };
    Ok((bytes, meta))
}

pub struct Arena {
    items: Mutex<Vec<Bytes>>,
}

impl Default for Arena {
    fn default() -> Self {
        Self::new()
    }
}

impl Arena {
    pub fn new() -> Arena {
        Arena {
            items: Mutex::new(Vec::new()),
        }
    }

    pub fn keep(&self, bytes: Bytes) -> &[u8] {
        let slice = bytes.as_slice();
        // SAFETY: the memory behind `slice` is a mapping or a heap block owned
        // by `bytes`. Moving `bytes` into the vector moves neither, and the
        // arena never drops an item before it is dropped itself, which the
        // borrow of `self` in the return type outlives.
        let slice: &[u8] = unsafe { std::slice::from_raw_parts(slice.as_ptr(), slice.len()) };
        self.items.lock().unwrap().push(bytes);
        slice
    }

    pub fn alloc(&self, data: Vec<u8>) -> &[u8] {
        self.keep(Bytes::Owned(data.into_boxed_slice()))
    }
}

pub struct Mmap {
    ptr: *const u8,
    len: usize,
}

// SAFETY: the mapping is read-only and owned; sharing `&[u8]` into it across
// threads is no different from sharing a `Box<[u8]>`.
unsafe impl Send for Mmap {}
unsafe impl Sync for Mmap {}

impl Mmap {
    fn as_slice(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY: `ptr` maps `len` readable bytes until `drop`.
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }

    #[cfg(unix)]
    fn map(file: &File, len: usize) -> io::Result<Mmap> {
        use std::os::unix::io::AsRawFd;
        if len == 0 {
            return Ok(Mmap {
                ptr: std::ptr::null(),
                len,
            });
        }
        // SAFETY: a fresh private read-only mapping of an open file.
        let ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if ptr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        Ok(Mmap {
            ptr: ptr as *const u8,
            len,
        })
    }

    #[cfg(windows)]
    fn map(file: &File, len: usize) -> io::Result<Mmap> {
        use std::os::windows::io::AsRawHandle;
        if len == 0 {
            return Ok(Mmap {
                ptr: std::ptr::null(),
                len,
            });
        }
        // SAFETY: plain Win32 calls on a handle we own; the view keeps the
        // mapping object alive after its handle is closed.
        unsafe {
            let mapping = win::CreateFileMappingW(
                file.as_raw_handle(),
                std::ptr::null(),
                win::PAGE_READONLY,
                0,
                0,
                std::ptr::null(),
            );
            if mapping.is_null() {
                return Err(io::Error::last_os_error());
            }
            let ptr = win::MapViewOfFile(mapping, win::FILE_MAP_READ, 0, 0, 0);
            let err = io::Error::last_os_error();
            win::CloseHandle(mapping);
            if ptr.is_null() {
                return Err(err);
            }
            Ok(Mmap {
                ptr: ptr as *const u8,
                len,
            })
        }
    }

    #[cfg(not(any(unix, windows)))]
    fn map(file: &File, len: usize) -> io::Result<Mmap> {
        use std::io::Read;
        let mut buf = Vec::with_capacity(len);
        (&*file).read_to_end(&mut buf)?;
        let len = buf.len();
        let ptr = Box::leak(buf.into_boxed_slice()).as_ptr();
        Ok(Mmap { ptr, len })
    }
}

impl Drop for Mmap {
    fn drop(&mut self) {
        if self.len == 0 {
            return;
        }
        #[cfg(unix)]
        // SAFETY: unmapping the mapping created in `map`.
        unsafe {
            libc::munmap(self.ptr as *mut libc::c_void, self.len);
        }
        #[cfg(windows)]
        // SAFETY: unmapping the view created in `map`.
        unsafe {
            win::UnmapViewOfFile(self.ptr as *const std::ffi::c_void);
        }
        #[cfg(not(any(unix, windows)))]
        // SAFETY: reclaiming the box leaked in `map`.
        unsafe {
            drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                self.ptr as *mut u8,
                self.len,
            )));
        }
    }
}

/// Memory-mapped temp file renamed over the destination when complete. Never writes into an
/// existing output: it may be a hard link into Rune's store or a running program.
pub struct OutputFile {
    path: std::path::PathBuf,
    tmp: std::path::PathBuf,
    file: Option<File>,
    ptr: *mut u8,
    len: usize,
    /// Built in memory and written at commit instead of through a shared mapping.
    buffer: Option<Vec<u8>>,
}

// SAFETY: the mapping is owned and only reachable through `&mut self`.
unsafe impl Send for OutputFile {}

impl OutputFile {
    pub fn create(path: &Path, len: usize) -> io::Result<OutputFile> {
        Self::create_with_mode(path, len, 0o666)
    }

    /// A code-signed image the user can run (mode 0777 less the umask). It is built in memory
    /// and written with `pwrite`: macOS treats pages of a file that were written through a
    /// shared mapping as tampered once the file is executed, and kills whoever maps them.
    pub fn create_executable(path: &Path, len: usize) -> io::Result<OutputFile> {
        let mut out = Self::open_tmp(path, 0o777)?;
        out.len = len;
        out.buffer = Some(vec![0u8; len]);
        Ok(out)
    }

    fn open_tmp(path: &Path, mode: u32) -> io::Result<OutputFile> {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".hyprlnk-{}.tmp", std::process::id()));
        let tmp = path.with_file_name(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let file = opts.open(&tmp)?;
        Ok(OutputFile {
            path: path.to_path_buf(),
            tmp,
            file: Some(file),
            ptr: std::ptr::null_mut(),
            len: 0,
            buffer: None,
        })
    }

    fn create_with_mode(path: &Path, len: usize, mode: u32) -> io::Result<OutputFile> {
        let mut name = path.file_name().unwrap_or_default().to_os_string();
        name.push(format!(".hyprlnk-{}.tmp", std::process::id()));
        let tmp = path.with_file_name(name);
        let mut opts = std::fs::OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(mode);
        }
        #[cfg(not(unix))]
        let _ = mode;
        let file = opts.open(&tmp)?;
        let mut out = OutputFile {
            path: path.to_path_buf(),
            tmp,
            file: None,
            ptr: std::ptr::null_mut(),
            len,
            buffer: None,
        };
        file.set_len(len as u64)?;
        if len > 0 {
            out.ptr = map_rw(&file, len)?;
        }
        out.file = Some(file);
        Ok(out)
    }

    pub fn bytes(&mut self) -> &mut [u8] {
        if let Some(b) = &mut self.buffer {
            return b;
        }
        if self.len == 0 {
            return &mut [];
        }
        // SAFETY: `ptr` maps `len` writable bytes until `unmap`.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    pub fn commit(mut self, len: usize) -> io::Result<()> {
        self.unmap();
        let file = self.file.take().unwrap();
        file.set_len(len as u64)?;
        if let Some(buf) = self.buffer.take() {
            write_parallel(&file, &buf[..len])?;
            // Leaked: the caller exits right after; unmapping a large image costs time.
            std::mem::forget(buf);
        }
        drop(file);
        if std::fs::rename(&self.tmp, &self.path).is_err() {
            // On Windows a read-only destination (from Rune's store) must be removed before the rename.
            if std::fs::remove_file(&self.path).is_ok() {
                return std::fs::rename(&self.tmp, &self.path);
            }
            if let Ok(meta) = std::fs::metadata(&self.path) {
                let mut perm = meta.permissions();
                #[allow(clippy::permissions_set_readonly_false)]
                perm.set_readonly(false);
                let _ = std::fs::set_permissions(&self.path, perm);
            }
            let _ = std::fs::remove_file(&self.path);
            std::fs::rename(&self.tmp, &self.path)?;
        }
        Ok(())
    }

    fn unmap(&mut self) {
        if !self.ptr.is_null() {
            unmap_rw(self.ptr, self.len);
            self.ptr = std::ptr::null_mut();
        }
    }
}

impl Drop for OutputFile {
    fn drop(&mut self) {
        self.unmap();
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// An output written piece by piece, from any thread, then renamed over the destination.
pub struct PartsFile {
    path: std::path::PathBuf,
    tmp: std::path::PathBuf,
    file: Option<File>,
}

impl PartsFile {
    pub fn create(path: &Path, len: u64, mode: u32) -> io::Result<PartsFile> {
        let out = OutputFile::open_tmp(path, mode)?;
        let mut out = std::mem::ManuallyDrop::new(out);
        let file = out.file.take().unwrap();
        let tmp = std::mem::take(&mut out.tmp);
        file.set_len(len)?;
        Ok(PartsFile {
            path: path.to_path_buf(),
            tmp,
            file: Some(file),
        })
    }

    pub fn write_at(&self, data: &[u8], off: u64) -> io::Result<()> {
        write_at(self.file.as_ref().unwrap(), data, off)
    }

    /// Write `data` at `off` in large chunks on the calling thread and helpers.
    pub fn write_parallel(&self, data: &[u8], off: u64) -> io::Result<()> {
        const CHUNK: usize = 16 << 20;
        let file = self.file.as_ref().unwrap();
        std::thread::scope(|s| {
            let handles: Vec<_> = data
                .chunks(CHUNK)
                .enumerate()
                .map(|(i, c)| s.spawn(move || write_at(file, c, off + (i * CHUNK) as u64)))
                .collect();
            handles.into_iter().try_for_each(|h| h.join().unwrap())
        })
    }

    pub fn commit(mut self) -> io::Result<()> {
        drop(self.file.take());
        let (tmp, path) = (
            std::mem::take(&mut self.tmp),
            std::mem::take(&mut self.path),
        );
        if std::fs::rename(&tmp, &path).is_err() {
            let _ = std::fs::remove_file(&path);
            std::fs::rename(&tmp, &path)?;
        }
        Ok(())
    }
}

impl Drop for PartsFile {
    fn drop(&mut self) {
        if self.file.take().is_some() {
            let _ = std::fs::remove_file(&self.tmp);
        }
    }
}

/// Write `data` at offset 0 in chunks on all threads.
fn write_parallel(file: &File, data: &[u8]) -> io::Result<()> {
    use rayon::prelude::*;
    const CHUNK: usize = 4 << 20;
    data.par_chunks(CHUNK)
        .enumerate()
        .try_for_each(|(i, chunk)| write_at(file, chunk, (i * CHUNK) as u64))
}

#[cfg(unix)]
fn write_at(file: &File, mut data: &[u8], mut off: u64) -> io::Result<()> {
    use std::os::unix::fs::FileExt;
    while !data.is_empty() {
        let n = file.write_at(data, off)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
        }
        data = &data[n..];
        off += n as u64;
    }
    Ok(())
}

#[cfg(windows)]
fn write_at(file: &File, mut data: &[u8], mut off: u64) -> io::Result<()> {
    use std::os::windows::fs::FileExt;
    while !data.is_empty() {
        let n = file.seek_write(data, off)?;
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::WriteZero, "short write"));
        }
        data = &data[n..];
        off += n as u64;
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn write_at(file: &File, data: &[u8], off: u64) -> io::Result<()> {
    use std::io::{Seek, SeekFrom, Write};
    let mut f = file;
    f.seek(SeekFrom::Start(off))?;
    f.write_all(data)
}

#[cfg(unix)]
fn map_rw(file: &File, len: usize) -> io::Result<*mut u8> {
    use std::os::unix::io::AsRawFd;
    // SAFETY: a fresh shared writable mapping of a file we just sized.
    let ptr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            0,
        )
    };
    if ptr == libc::MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    Ok(ptr as *mut u8)
}

#[cfg(unix)]
fn unmap_rw(ptr: *mut u8, len: usize) {
    // SAFETY: unmapping the mapping created by `map_rw`.
    unsafe {
        libc::munmap(ptr as *mut libc::c_void, len);
    }
}

#[cfg(windows)]
fn map_rw(file: &File, len: usize) -> io::Result<*mut u8> {
    use std::os::windows::io::AsRawHandle;
    // SAFETY: plain Win32 calls on a handle we own; the view keeps the
    // mapping object alive after its handle is closed.
    unsafe {
        let mapping = win::CreateFileMappingW(
            file.as_raw_handle(),
            std::ptr::null(),
            win::PAGE_READWRITE,
            (len as u64 >> 32) as u32,
            len as u32,
            std::ptr::null(),
        );
        if mapping.is_null() {
            return Err(io::Error::last_os_error());
        }
        let ptr = win::MapViewOfFile(mapping, win::FILE_MAP_WRITE, 0, 0, len);
        let err = io::Error::last_os_error();
        win::CloseHandle(mapping);
        if ptr.is_null() {
            return Err(err);
        }
        Ok(ptr as *mut u8)
    }
}

#[cfg(windows)]
fn unmap_rw(ptr: *mut u8, _len: usize) {
    // SAFETY: unmapping the view created by `map_rw`.
    unsafe {
        win::UnmapViewOfFile(ptr as *const std::ffi::c_void);
    }
}

#[cfg(not(any(unix, windows)))]
fn map_rw(_file: &File, _len: usize) -> io::Result<*mut u8> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no memory mapping on this platform",
    ))
}

#[cfg(not(any(unix, windows)))]
fn unmap_rw(_ptr: *mut u8, _len: usize) {}

#[cfg(windows)]
#[allow(non_snake_case, clippy::upper_case_acronyms)]
mod win {
    use std::ffi::c_void;

    pub type HANDLE = *mut c_void;
    pub const PAGE_READONLY: u32 = 0x02;
    pub const PAGE_READWRITE: u32 = 0x04;
    pub const FILE_MAP_READ: u32 = 0x0004;
    pub const FILE_MAP_WRITE: u32 = 0x0002;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn CreateFileMappingW(
            file: HANDLE,
            attributes: *const c_void,
            protect: u32,
            max_size_high: u32,
            max_size_low: u32,
            name: *const u16,
        ) -> HANDLE;
        pub fn MapViewOfFile(
            mapping: HANDLE,
            access: u32,
            offset_high: u32,
            offset_low: u32,
            bytes: usize,
        ) -> *mut c_void;
        pub fn UnmapViewOfFile(base: *const c_void) -> i32;
        pub fn CloseHandle(handle: HANDLE) -> i32;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_and_large_files_load_the_same_bytes() {
        let dir = std::env::temp_dir().join(format!("hyprlnk-fileio-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let small = dir.join("small");
        let large = dir.join("large");
        let empty = dir.join("empty");
        let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(&small, b"hello").unwrap();
        std::fs::write(&large, &big).unwrap();
        std::fs::write(&empty, b"").unwrap();
        let arena = Arena::new();
        assert_eq!(arena.keep(load(&small).unwrap()), b"hello");
        assert_eq!(arena.keep(load(&large).unwrap()), &big[..]);
        assert_eq!(arena.keep(load(&empty).unwrap()), b"");
        drop(arena);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn output_replaces_the_destination_and_cleans_up() {
        let dir = std::env::temp_dir().join(format!("hyprlnk-output-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.exe");
        std::fs::write(&path, b"old contents that are longer").unwrap();
        let mut out = OutputFile::create(&path, 4096).unwrap();
        out.bytes()[..3].copy_from_slice(b"new");
        out.commit(3).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        drop(OutputFile::create(&path, 10).unwrap());
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
