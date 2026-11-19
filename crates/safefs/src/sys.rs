//! Thin, audited wrappers over the macOS syscalls the layer depends on.
//!
//! Every function here is *single-syscall* by construction: there is no
//! "check then use" sequence anywhere in this module, which is what makes the
//! layer immune to time-of-check/time-of-use (TOCTOU) races.

use std::ffi::{CStr, CString, OsStr, OsString};

use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::RawFd;

use crate::error::{Error, Result};

/// `O_NOFOLLOW_ANY` is present in libc for apple targets, but keep a local
/// constant so the value is obvious at the call site and cannot silently drift.
pub const O_NOFOLLOW_ANY: libc::c_int = 0x2000_0000;

#[allow(dead_code)]
pub fn errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Build an `io::Error` from the current errno. Never allocates a path string;
/// callers add context themselves so that we never leak host paths into logs.
pub fn last_error() -> io::Error {
    io::Error::last_os_error()
}

pub fn cvt(r: libc::c_int) -> io::Result<libc::c_int> {
    if r == -1 {
        Err(last_error())
    } else {
        Ok(r)
    }
}

pub fn cvt_isize(r: libc::ssize_t) -> io::Result<libc::ssize_t> {
    if r == -1 {
        Err(last_error())
    } else {
        Ok(r)
    }
}

pub fn cstring(name: &OsStr) -> Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| Error::invalid_path("nul byte in component"))
}

// ---------------------------------------------------------------------------
// open / openat
// ---------------------------------------------------------------------------

/// `openat` that never follows a symlink at *any* component of `path`.
///
/// `path` must already be validated as a relative, `..`-free path (see
/// [`crate::canon::LexPath`]); `O_NOFOLLOW_ANY` is defence in depth, not the
/// primary control, because it does **not** stop `..` from escaping.
pub fn openat_nofollow(dirfd: RawFd, path: &OsStr, flags: libc::c_int, mode: libc::mode_t) -> Result<RawFd> {
    let c = cstring(path)?;
    let flags = flags | O_NOFOLLOW_ANY | libc::O_CLOEXEC;
    let r = unsafe { libc::openat(dirfd, c.as_ptr(), flags, mode as libc::c_uint) };
    if r < 0 {
        return Err(Error::from_io(io::Error::last_os_error()));
    }
    Ok(r)
}

/// `openat` that resolves a whole relative path from `dirfd`, refusing a
/// symlink at **any** component.
///
/// This is the workhorse of the fast path: the kernel performs the entire
/// resolution, so there is no userspace loop and no window between a check and
/// a use. The caller must have validated `path` lexically (no `..`, not
/// absolute), because `O_NOFOLLOW_ANY` does not stop `..`.
pub fn openat_nofollow_on_root(
    dirfd: RawFd,
    path: &OsStr,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> Result<RawFd> {
    openat_nofollow(dirfd, path, flags, mode)
}

/// Open a directory by a relative path from `dirfd`, refusing links anywhere.
pub fn openat_dir_nofollow_any(dirfd: RawFd, path: &OsStr) -> Result<RawFd> {
    let c = cstring(path)?;
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NONBLOCK | O_NOFOLLOW_ANY | libc::O_CLOEXEC;
    let r = unsafe { libc::openat(dirfd, c.as_ptr(), flags) };
    if r < 0 {
        return Err(Error::from_io(io::Error::last_os_error()));
    }
    Ok(r)
}

/// `openat` of a single path component that must itself be a directory.
///
/// `O_NOFOLLOW` here applies to the *final* component; because callers pass
/// exactly one component, that is the only component there is.
pub fn openat_dir(dirfd: RawFd, name: &OsStr) -> Result<RawFd> {
    let c = cstring(name)?;
    let flags = libc::O_RDONLY
        | libc::O_DIRECTORY
        | libc::O_NOFOLLOW
        | libc::O_CLOEXEC
        | libc::O_NONBLOCK;
    let r = unsafe { libc::openat(dirfd, c.as_ptr(), flags) };
    if r < 0 {
        return Err(Error::from_io(io::Error::last_os_error()));
    }
    Ok(r)
}

pub fn close(fd: RawFd) {
    // Closing an fd must never fail in a way that matters to correctness; the
    // only realistic error is EBADF from a bug.
    let _ = cvt_isize(unsafe { libc::close(fd) as libc::ssize_t });
}

pub fn dup(fd: RawFd) -> Result<RawFd> {
    Ok(cvt(unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) })?)
}

pub fn clear_nonblock(fd: RawFd) -> Result<()> {
    let flags = cvt(unsafe { libc::fcntl(fd, libc::F_GETFL) })?;
    if flags & libc::O_NONBLOCK != 0 {
        cvt(unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) })?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// stat family
// ---------------------------------------------------------------------------

pub fn fstat(fd: RawFd) -> Result<libc::stat> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    cvt(unsafe { libc::fstat(fd, &mut st) })?;
    Ok(st)
}

pub fn fstatat_nofollow(dirfd: RawFd, name: &OsStr) -> Result<libc::stat> {
    let c = cstring(name)?;
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    cvt(unsafe { libc::fstatat(dirfd, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(st)
}

#[allow(dead_code)]
pub fn fstatfs(fd: RawFd) -> Result<libc::statfs> {
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    cvt(unsafe { libc::fstatfs(fd, &mut s) })?;
    Ok(s)
}

// ---------------------------------------------------------------------------
// attrlist helpers (macOS specific)
// ---------------------------------------------------------------------------

/// `DIR_MNTSTATUS_MNTPOINT` from `<sys/attr.h>`: the vnode this fd refers to is
/// a mount point.
const DIR_MNTSTATUS_MNTPOINT: u32 = 0x1;

#[repr(C, align(4))]
struct MountStatusBuf {
    total_len: u32,
    status: u32,
    /// `fgetattrlist` documents a minimum buffer of `ATTR_BIT_MAP_COUNT`
    /// words even when fewer bytes are requested; an undersized buffer fails
    /// with `ERANGE` rather than returning partial data.
    pad: [u32; 4],
}

/// True when the directory open on `fd` is the root of a mounted filesystem.
///
/// This is the authoritative mount test: `st_dev` only tells you *which*
/// filesystem, whereas this tells you *this vnode is where a filesystem was
/// grafted on*. Our probe showed it also becomes true on an fd that was opened
/// **before** something was mounted over its path, which is what lets the layer
/// detect a mount smuggled in between two operations.
pub fn is_mount_point(fd: RawFd) -> Result<bool> {
    let mut al: libc::attrlist = unsafe { std::mem::zeroed() };
    al.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    al.dirattr = libc::ATTR_DIR_MOUNTSTATUS;
    let mut out = MountStatusBuf { total_len: 0, status: 0, pad: [0; 4] };
    let r = unsafe {
        libc::fgetattrlist(
            fd,
            &mut al as *mut _ as *mut libc::c_void,
            &mut out as *mut _ as *mut libc::c_void,
            std::mem::size_of::<MountStatusBuf>(),
            0,
        )
    };
    cvt(r)?;
    Ok(out.status & DIR_MNTSTATUS_MNTPOINT != 0)
}

/// True if the volume backing `fd` folds case when looking names up.
pub fn volume_is_case_sensitive(fd: RawFd) -> Result<bool> {
    let r = unsafe { libc::fpathconf(fd, libc::_PC_CASE_SENSITIVE) };
    if r < 0 {
        // `_PC_CASE_SENSITIVE` is not implemented on every filesystem; assume
        // the conservative answer (names may collide) rather than failing open.
        return Ok(false);
    }
    Ok(r == 1)
}

// ---------------------------------------------------------------------------
// packed descriptor evidence
// ---------------------------------------------------------------------------

/// Everything the layer needs to know about an open descriptor, fetched with a
/// **single** `fgetattrlist`.
///
/// The naive implementation issues one syscall per fact (`fstat`, then
/// `fgetattrlist` for the mount status, then another for the stored name), and
/// at ~2-6µs per syscall on APFS that dominates the cost of an `open`. Asking
/// the kernel for all of it at once costs one syscall and returns a buffer
/// whose layout is fixed by the attribute bitmap below.
///
/// The layout is the kernel's: attributes appear in bitmap order, each at its
/// natural alignment, and an `attrreference_t` (used by `ATTR_CMN_NAME`) is an
/// offset relative to the address of the reference itself.
#[derive(Debug, Clone, Copy)]
pub struct Evidence {
    pub dev: u32,
    /// The inode number. `ATTR_CMN_FILEID` is the stable identity shared by
    /// every hard link to the same file — unlike `ATTR_CMN_OBJID`, which APFS
    /// reports *per directory entry*.
    pub file_id: u64,
    /// `fsobj_type_t`, which is *not* `S_IFMT`: the enum in `<sys/vnode.h>` is
    /// `VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VBAD, VSTR, VCPLX`, i.e.
    /// 1..=10. [`Self::file_type`] converts it to the `S_IF*` bits callers
    /// compare against.
    pub obj_type: u32,
    pub obj_id: u64,
    pub access_mask: u32,
    pub parent_id: u32,
    pub link_count: u32,
    pub data_length: u64,
    pub is_mount_point: bool,
}

const ATTR_COMMON_WANTED: libc::attrgroup_t = libc::ATTR_CMN_NAME
    | libc::ATTR_CMN_DEVID
    | libc::ATTR_CMN_OBJTYPE
    | libc::ATTR_CMN_OBJID
    | libc::ATTR_CMN_FILEID
    | libc::ATTR_CMN_ACCESSMASK
    | libc::ATTR_CMN_PARENTID
    | libc::ATTR_CMN_RETURNED_ATTRS;
const ATTR_DIR_WANTED: libc::attrgroup_t = libc::ATTR_DIR_MOUNTSTATUS;
const ATTR_FILE_WANTED: libc::attrgroup_t =
    libc::ATTR_FILE_LINKCOUNT | libc::ATTR_FILE_DATALENGTH;

/// `fsobj_type_t` values from `<sys/vnode.h>`.
mod vtype {
    pub const VREG: u32 = 1;
    pub const VDIR: u32 = 2;
    pub const VBLK: u32 = 3;
    pub const VCHR: u32 = 4;
    pub const VLNK: u32 = 5;
    pub const VSOCK: u32 = 6;
    pub const VFIFO: u32 = 7;
}

impl Evidence {
    /// A neutral value used where an evidence read failed for a path that is
    /// about to be refused anyway.
    pub fn unknown() -> Evidence {
        Evidence {
            dev: 0,
            obj_type: 0,
            file_id: 0,
            obj_id: 0,
            access_mask: 0,
            parent_id: 0,
            link_count: 1,
            data_length: 0,
            is_mount_point: false,
        }
    }

    /// Convert the vnode type to the `S_IFMT` mask callers expect, so policy
    /// code has exactly one representation to reason about.
    pub fn file_type(&self) -> u32 {
        match self.obj_type {
            vtype::VREG => libc::S_IFREG as u32,
            vtype::VDIR => libc::S_IFDIR as u32,
            vtype::VBLK => libc::S_IFBLK as u32,
            vtype::VCHR => libc::S_IFCHR as u32,
            vtype::VLNK => libc::S_IFLNK as u32,
            vtype::VSOCK => libc::S_IFSOCK as u32,
            vtype::VFIFO => libc::S_IFIFO as u32,
            _ => 0,
        }
    }
    pub fn is_regular(&self) -> bool {
        self.obj_type == vtype::VREG
    }
    #[allow(dead_code)]
    pub fn is_dir(&self) -> bool {
        self.obj_type == vtype::VDIR
    }
    pub fn is_symlink(&self) -> bool {
        self.obj_type == vtype::VLNK
    }
}

/// Field offsets in the buffer returned by [`evidence`].
///
/// The kernel packs the requested attributes in bitmap order into one buffer.
/// Rather than reimplement the kernel's alignment rules (the first attempt did,
/// and read `ATTR_FILE_LINKCOUNT` out of `ATTR_DIR_MOUNTSTATUS` because a
/// regular file has no directory attributes and everything after the gap
/// shifts), the offsets below were read out of two independent dumps — one of a
/// regular file, one of a directory, both with the exact bitmap used here — and
/// are pinned by `sys::layout_tests`, which compares every field against
/// `fstat`. If Apple changes the packing, those tests fail instead of the layer
/// quietly misreading a link count.
///
/// Layout (offsets in bytes):
///
/// ```text
///    0  u32   total length
///    4  u32×5 ATTR_CMN_RETURNED_ATTRS
///   24  i32   ATTR_CMN_NAME  data offset, relative to byte 24
///   28  u32   ATTR_CMN_NAME  data length (includes the NUL)
///   32  u32   ATTR_CMN_DEVID
///   36  u32   ATTR_CMN_OBJTYPE
///   40  u64   ATTR_CMN_OBJID            (the inode number)
///   48  u32   ATTR_CMN_ACCESSMASK
///   52  u64   ATTR_CMN_FILEID           (the inode number, shared by all links)
///   60  u32   ATTR_CMN_PARENTID
///   64  u32   ATTR_DIR_MOUNTSTATUS      (0 when the object is not a directory)
///   68  u32   ATTR_FILE_LINKCOUNT       (0 when the object is not a file)
///   72  u64   ATTR_FILE_DATALENGTH      (0 when the object is not a file)
///   80  …     ATTR_CMN_NAME data, NUL terminated
/// ```
const OFF_NAME_REF: usize = 24;
const OFF_DEVID: usize = 32;
const OFF_OBJTYPE: usize = 36;
const OFF_OBJID: usize = 40;
const OFF_ACCESSMASK: usize = 48;
const OFF_FILEID: usize = 52;
const OFF_PARENTID: usize = 60;
const OFF_MOUNTSTATUS: usize = 64;
const OFF_LINKCOUNT: usize = 68;
const OFF_DATALENGTH: usize = 72;

/// Buffer large enough for the fixed fields plus a `NAME_MAX` name.
#[repr(C, align(8))]
struct EvidenceBuf {
    bytes: [u8; 2048],
}

fn rd_u32(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
}
fn rd_i32(b: &[u8], off: usize) -> i32 {
    i32::from_ne_bytes(b[off..off + 4].try_into().unwrap())
}
fn rd_u64(b: &[u8], off: usize) -> u64 {
    u64::from_ne_bytes(b[off..off + 8].try_into().unwrap())
}

/// Fetch [`Evidence`] and the stored name in one syscall.
///
/// Returns `None` for the name when the kernel did not fill `ATTR_CMN_NAME`.
pub fn evidence(fd: RawFd) -> Result<(Evidence, Option<OsString>)> {
    let mut al: libc::attrlist = unsafe { std::mem::zeroed() };
    al.bitmapcount = libc::ATTR_BIT_MAP_COUNT;
    al.commonattr = ATTR_COMMON_WANTED;
    al.dirattr = ATTR_DIR_WANTED;
    al.fileattr = ATTR_FILE_WANTED;
    let mut buf = EvidenceBuf { bytes: [0; 2048] };
    let r = unsafe {
        libc::fgetattrlist(
            fd,
            &mut al as *mut _ as *mut libc::c_void,
            buf.bytes.as_mut_ptr() as *mut libc::c_void,
            buf.bytes.len(),
            0,
        )
    };
    cvt(r)?;
    let b = &buf.bytes;

    // The two optional groups sit before the name blob only when the kernel
    // filled them, and it omits a group entirely for objects of the wrong kind
    // (a directory has no file attributes; a regular file has no directory
    // attributes). Anything read past a gap would be NAME data, so the fields
    // are read only when the *kind* makes them real, and the name is always
    // located through its own reference rather than by position.
    let is_dir = rd_u32(b, OFF_OBJTYPE) == vtype::VDIR;
    let is_file = matches!(
        rd_u32(b, OFF_OBJTYPE),
        vtype::VREG | vtype::VLNK | vtype::VFIFO | vtype::VSOCK | vtype::VCHR | vtype::VBLK
    );
    let ev = Evidence {
        dev: rd_u32(b, OFF_DEVID),
        obj_type: rd_u32(b, OFF_OBJTYPE),
        obj_id: rd_u64(b, OFF_OBJID),
        access_mask: rd_u32(b, OFF_ACCESSMASK),
        file_id: rd_u64(b, OFF_FILEID),
        parent_id: rd_u32(b, OFF_PARENTID),
        link_count: if is_file { rd_u32(b, OFF_LINKCOUNT) } else { 1 },
        data_length: if is_file { rd_u64(b, OFF_DATALENGTH) } else { 0 },
        is_mount_point: is_dir && rd_u32(b, OFF_MOUNTSTATUS) & DIR_MNTSTATUS_MNTPOINT != 0,
    };

    let name = {
        let rel = rd_i32(b, OFF_NAME_REF) as i64;
        let len = rd_u32(b, OFF_NAME_REF + 4) as usize;
        let abs = (OFF_NAME_REF as i64 + rel) as usize;
        if len == 0 || abs < OFF_NAME_REF || abs + len > b.len() {
            None
        } else {
            let raw = &b[abs..abs + len];
            let end = raw.iter().position(|x| *x == 0).unwrap_or(raw.len());
            Some(OsString::from_vec(raw[..end].to_vec()))
        }
    };
    Ok((ev, name))
}

// ---------------------------------------------------------------------------
// raw path helpers
// ---------------------------------------------------------------------------

pub fn readlinkat(dirfd: RawFd, name: &OsStr) -> Result<OsString> {
    let c = cstring(name)?;
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let n = unsafe {
        libc::readlinkat(dirfd, c.as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len())
    };
    if n < 0 {
        return Err(Error::from_io(io::Error::last_os_error()));
    }
    buf.truncate(n as usize);
    Ok(OsString::from_vec(buf))
}

/// `F_GETPATH`: the current path of an open fd, for diagnostics only.
/// Never use the result to make a security decision — it is a snapshot of a
/// name that can be renamed the instant afterwards.
#[allow(dead_code)]
pub fn fd_path(fd: RawFd) -> Result<OsString> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    let r = unsafe { libc::fcntl(fd, libc::F_GETPATH, buf.as_mut_ptr()) };
    if r < 0 {
        return Err(Error::from_io(io::Error::last_os_error()));
    }
    let c = unsafe { CStr::from_ptr(buf.as_ptr() as *const libc::c_char) };
    Ok(OsString::from_vec(c.to_bytes().to_vec()))
}

// ---------------------------------------------------------------------------
// mutating operations, all relative to a pinned directory fd
// ---------------------------------------------------------------------------

pub fn unlinkat(dirfd: RawFd, name: &OsStr, dir: bool) -> Result<()> {
    let c = cstring(name)?;
    let flags = if dir { libc::AT_REMOVEDIR } else { 0 };
    cvt(unsafe { libc::unlinkat(dirfd, c.as_ptr(), flags) })?;
    Ok(())
}

pub fn mkdirat(dirfd: RawFd, name: &OsStr, mode: libc::mode_t) -> Result<()> {
    let c = cstring(name)?;
    cvt(unsafe { libc::mkdirat(dirfd, c.as_ptr(), mode) })?;
    Ok(())
}

pub fn renameat(from_dir: RawFd, from: &OsStr, to_dir: RawFd, to: &OsStr) -> Result<()> {
    let a = cstring(from)?;
    let b = cstring(to)?;
    cvt(unsafe { libc::renameat(from_dir, a.as_ptr(), to_dir, b.as_ptr()) })?;
    Ok(())
}

pub fn linkat(from_dir: RawFd, from: &OsStr, to_dir: RawFd, to: &OsStr) -> Result<()> {
    let a = cstring(from)?;
    let b = cstring(to)?;
    // Flags are 0: neither follow symlinks. Hard-linking a symlink duplicates
    // the link itself, never its target.
    cvt(unsafe { libc::linkat(from_dir, a.as_ptr(), to_dir, b.as_ptr(), 0) })?;
    Ok(())
}

pub fn symlinkat(target: &OsStr, dirfd: RawFd, name: &OsStr) -> Result<()> {
    let t = cstring(target)?;
    let n = cstring(name)?;
    cvt(unsafe { libc::symlinkat(t.as_ptr(), dirfd, n.as_ptr()) })?;
    Ok(())
}

pub fn fchmod(fd: RawFd, mode: libc::mode_t) -> Result<()> {
    cvt(unsafe { libc::fchmod(fd, mode) })?;
    Ok(())
}

#[allow(dead_code)]
pub fn ftruncate(fd: RawFd, len: libc::off_t) -> Result<()> {
    cvt(unsafe { libc::ftruncate(fd, len) })?;
    Ok(())
}

#[allow(dead_code)]
pub fn fsync_fd(fd: RawFd) -> Result<()> {
    cvt(unsafe { libc::fsync(fd) })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// directory iteration
// ---------------------------------------------------------------------------

/// A single entry produced by [`read_dir`]; the name is exactly as stored on
/// disk, never as the caller spelled it.
pub struct RawEntry {
    pub name: OsString,
    pub d_type: u8,
}

pub fn read_dir(fd: RawFd) -> Result<Vec<RawEntry>> {
    let dupfd = dup(fd)?;
    let dir = unsafe { libc::fdopendir(dupfd) };
    if dir.is_null() {
        let e = io::Error::last_os_error();
        close(dupfd);
        return Err(Error::from_io(e));
    }
    let mut out = Vec::new();
    loop {
        // Reset errno so that a `NULL` return can be distinguished from EOF.
        unsafe { *libc::__error() = 0 };
        let ent = unsafe { libc::readdir(dir) };
        if ent.is_null() {
            let errno = unsafe { *libc::__error() };
            let e = if errno == 0 { None } else { Some(io::Error::from_raw_os_error(errno)) };
            let _ = cvt(unsafe { libc::closedir(dir) });
            return match e {
                None => Ok(out),
                Some(e) => Err(Error::from_io(e)),
            };
        }
        let de = unsafe { &*ent };
        let name_bytes = unsafe {
            std::slice::from_raw_parts(de.d_name.as_ptr() as *const u8, de.d_namlen as usize)
        };
        let name = OsString::from_vec(name_bytes.to_vec());
        if name.as_bytes() == b"." || name.as_bytes() == b".." {
            continue;
        }
        out.push(RawEntry { name, d_type: de.d_type });
    }
}

pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;

#[cfg(test)]
mod layout_tests {
    use super::*;
    use std::io::Write;

    /// The packed layout is the kernel's, not ours: assert the fields we read
    /// against `fstat` on a tree shaped like a real workspace, so a future OS
    /// change fails loudly instead of silently misreading.
    #[test]
    fn evidence_matches_fstat() {
        let dir = tempfile::tempdir().unwrap();
        let f_path = dir.path().join("file");
        let mut f = std::fs::File::create(&f_path).unwrap();
        f.write_all(b"0123456789").unwrap();
        drop(f);
        std::fs::hard_link(&f_path, dir.path().join("second")).unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();

        let d = std::fs::File::open(dir.path()).unwrap();
        let (dev, name) = evidence(std::os::unix::io::AsRawFd::as_raw_fd(&d)).unwrap();
        let ds = std::fs::metadata(dir.path()).unwrap();
        assert!(dev.is_dir(), "obj_type {} not a dir", dev.obj_type);
        assert_eq!(dev.dev as u64, std::os::unix::fs::MetadataExt::dev(&ds));
        assert!(!dev.is_mount_point, "an ordinary tempdir must not report as a mount point");
        assert!(name.is_some());

        let fh = std::fs::File::open(&f_path).unwrap();
        let (fe, fname) = evidence(std::os::unix::io::AsRawFd::as_raw_fd(&fh)).unwrap();
        let fs = std::fs::metadata(&f_path).unwrap();
        assert!(fe.is_regular());
        assert_eq!(fe.link_count, 2, "hard link must be visible");
        assert_eq!(fe.data_length, 10);
        // `ATTR_CMN_OBJID` is the file's unique object id, which on APFS is a
        // separate number from `st_ino`; the link count and size are what must
        // match `fstat`.
        assert_eq!(u64::from(fe.link_count), std::os::unix::fs::MetadataExt::nlink(&fs));
        assert_eq!(fe.data_length, std::os::unix::fs::MetadataExt::size(&fs));
        assert_eq!(
            std::os::unix::fs::MetadataExt::ino(&fs),
            fe.file_id,
            "ATTR_CMN_FILEID must be the inode number"
        );
        // And it is shared by every hard link to the same file.
        let second = std::fs::File::open(dir.path().join("second")).unwrap();
        let (se, _) = evidence(std::os::unix::io::AsRawFd::as_raw_fd(&second)).unwrap();
        assert_eq!(se.file_id, fe.file_id, "hard links share an inode");
        assert_eq!(fname.unwrap().as_encoded_bytes(), b"file");
        assert!(!fe.is_mount_point, "a plain file is not a mount point");
        assert_eq!(fe.link_count, 2);
        assert_eq!(fe.data_length, 10);

        // parentid of the file must be the directory we resolved through.
        let ds_ino = std::os::unix::fs::MetadataExt::ino(&ds) as u32;
        assert_eq!(fe.parent_id, ds_ino);
    }

    #[test]
    fn absent_dirattr_does_not_shift_file_attrs() {
        // A regular file has no ATTR_DIR_MOUNTSTATUS; the kernel omits it, so
        // LINKCOUNT and DATALENGTH shift down by one word. This test exists
        // because the first implementation hard-coded offsets and read
        // LINKCOUNT out of MOUNTSTATUS.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("plain");
        std::fs::write(&p, b"abc").unwrap();
        let fh = std::fs::File::open(&p).unwrap();
        let (fe, _) = evidence(std::os::unix::io::AsRawFd::as_raw_fd(&fh)).unwrap();
        assert_eq!(fe.link_count, 1);
        assert_eq!(fe.data_length, 3);
    }
}
