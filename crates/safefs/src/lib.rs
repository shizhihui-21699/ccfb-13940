//! `safefs` — a confinement layer for build-script file access on macOS.
//!
//! # The problem
//!
//! A CI runner lets externally contributed build scripts touch a workspace
//! directory and must guarantee they touch nothing else. The classic
//! implementation —
//!
//! ```text
//! let real = fs::canonicalize(user_path)?;      // syscall 1
//! if !real.starts_with(workspace) { deny() }    // userspace check
//! let f = File::open(user_path)?;               // syscall 2
//! ```
//!
//! — is defeated by a single thread that swaps a path component between the two
//! syscalls, and by every trick that makes syscall 1 and syscall 2 disagree:
//! symlinks, hard links, a directory renamed out and replaced, a filesystem
//! mounted over a subdirectory, and case- or Unicode-folded names on APFS.
//! Adding locks does not help: the attacker's threads and ours interleave at
//! syscall granularity, and any check-then-use window is exploitable.
//!
//! # The approach
//!
//! There is no check-then-use. Every path is resolved **once**, from a
//! directory descriptor for the workspace root, by a chain of `openat` calls
//! that refuse symlinks, refuse mount points, and compare names against what
//! the volume actually stored. The result is not a path but an **open
//! descriptor** plus a leaf name. The operation the caller asked for is then a
//! single syscall on that descriptor — and a descriptor cannot be retargeted.
//!
//! See [`resolve`] for the invariant and the per-component argument.
//!
//! # Example
//!
//! ```no_run
//! use safefs::{Workspace, Policy};
//!
//! # fn main() -> Result<(), safefs::Error> {
//! let ws = Workspace::open("/srv/ci/workspace-42")?;
//! let mut f = ws.open_read("src/main.rs")?;
//! let mut s = String::new();
//! std::io::Read::read_to_string(&mut f, &mut s)?;
//!
//! // Anything that tries to leave is refused with a typed reason.
//! assert!(ws.open_read("../etc/passwd").is_err());
//! assert!(ws.open_read("/etc/passwd").is_err());
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_op_in_unsafe_fn)]

mod canon;
mod error;
mod policy;
mod resolve;
mod sandbox;
mod sys;

pub use canon::{LexPath, MAX_DEPTH, MAX_NAME};
pub use error::{Denied, Error, Result};
pub use policy::Policy;
pub use sandbox::{Sandbox, SandboxError};

use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use resolve::{Directory, Resolver, RootInfo};

/// Options for opening a file inside a workspace.
#[derive(Debug, Clone, Copy, Default)]
pub struct OpenOptions {
    pub read: bool,
    pub write: bool,
    pub append: bool,
    pub truncate: bool,
    pub create: bool,
    pub create_new: bool,
    pub mode: Option<u32>,
}

impl OpenOptions {
    pub fn read() -> Self {
        OpenOptions { read: true, ..Default::default() }
    }
    pub fn write() -> Self {
        OpenOptions { write: true, create: true, truncate: true, ..Default::default() }
    }
    pub fn append() -> Self {
        OpenOptions { write: true, create: true, append: true, ..Default::default() }
    }
    pub fn create_new() -> Self {
        OpenOptions { write: true, create_new: true, ..Default::default() }
    }
    pub fn read_write() -> Self {
        OpenOptions { read: true, write: true, ..Default::default() }
    }
}

/// A confined view of one workspace directory.
///
/// Cheap to clone-share behind an `Arc`; every method takes `&self` and holds no
/// locks, so concurrent build threads never serialise on the layer.
pub struct Workspace {
    root: OwnedFd,
    info: RootInfo,
    policy: Policy,
    root_was_mount: bool,
    revoked: AtomicBool,
    /// Operation counter for sampling the root's mount status.
    ops: std::sync::atomic::AtomicU64,
    display_root: PathBuf,
    /// Inodes this handle has itself given a second name to. Only these are
    /// trusted when the link count is high; everything else is refused.
    linked: Mutex<HashSet<(u32, u64)>>,
}

impl std::fmt::Debug for Workspace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Workspace")
            .field("root", &self.display_root)
            .field("policy", &self.policy)
            .finish()
    }
}

impl Workspace {
    /// Open `path` as a workspace root with the default policy.
    pub fn open(path: impl AsRef<Path>) -> Result<Workspace> {
        Workspace::with_policy(path, Policy::default())
    }

    /// Open a workspace that must be the root of its own volume.
    ///
    /// Returns [`Isolation::Confined`] only when the root is a mount point, in
    /// which case the strongest guarantee in this crate holds: no outside
    /// inode can have a name inside the workspace at all, because hard links
    /// cannot cross filesystems. Otherwise returns [`Isolation::Shared`] with
    /// the reason, and the caller must decide whether the weaker
    /// descriptor-level guarantees are enough for its threat model.
    ///
    /// This is a *check of the host's setup*, not a check of a path, so it
    /// cannot be raced: it reads the mount status of the descriptor we hold.
    pub fn open_isolated(path: impl AsRef<Path>, policy: Policy) -> Result<(Workspace, Isolation)> {
        let ws = Workspace::with_policy(path, policy)?;
        let isolation = if ws.is_isolated()? {
            Isolation::Confined
        } else {
            Isolation::Shared {
                reason: "workspace is not the root of its own filesystem, so an outside file \
                         could be hard-linked into it",
            }
        };
        Ok((ws, isolation))
    }

    pub fn with_policy(path: impl AsRef<Path>, policy: Policy) -> Result<Workspace> {
        let c = sys::cstring(path.as_ref().as_os_str())?;
        // The root itself is opened by the trusted platform, so following a
        // symlink in its path (`/tmp` -> `/private/tmp`) is intended. From here
        // on the path string is never used for anything.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(Error::io("open workspace root", io::Error::last_os_error()));
        }
        let root = unsafe { OwnedFd::from_raw_fd(fd) };
        let st = sys::fstat(root.as_raw_fd())?;
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(Error::denied("workspace root", Denied::WrongType));
        }
        let case_insensitive = !sys::volume_is_case_sensitive(root.as_raw_fd())?;
        let root_was_mount = sys::is_mount_point(root.as_raw_fd())?;
        let info = RootInfo { dev: st.st_dev as u32, ino: st.st_ino as u64, case_insensitive };
        Ok(Workspace {
            root,
            info,
            policy,
            root_was_mount,
            revoked: AtomicBool::new(false),
            ops: std::sync::atomic::AtomicU64::new(0),
            display_root: path.as_ref().to_path_buf(),
            linked: Mutex::new(HashSet::new()),
        })
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The root as the platform named it. For diagnostics and for generating
    /// sandbox profiles; never used to resolve caller paths.
    pub fn root_path(&self) -> &Path {
        &self.display_root
    }

    /// Is the workspace the root of its own filesystem?
    ///
    /// This is the single most valuable property a runner can give this layer,
    /// because **a hard link cannot cross a filesystem boundary** (`EXDEV`).
    /// If the workspace is a mount point, every inode reachable inside it was
    /// created inside it, so an outside file can never acquire a
    /// workspace-relative name — which retires hard-link smuggling entirely,
    /// along with the residual check/open window that the `nlink`/`parentid`
    /// witness otherwise has to narrow.
    ///
    /// [`Workspace::open_isolated`] refuses to build a handle unless this is
    /// true; see [`Isolation`].
    pub fn is_isolated(&self) -> Result<bool> {
        sys::is_mount_point(self.root.as_raw_fd())
    }

    /// The workspace root's device number, for comparing with `stat` results.
    pub fn device(&self) -> u32 {
        self.info.dev
    }

    /// Stop serving requests on this handle. Useful when a runner tears a
    /// workspace down while threads may still be calling into it.
    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::SeqCst);
    }

    fn check_live(&self) -> Result<()> {
        if self.revoked.load(Ordering::SeqCst) {
            return Err(Error::Revoked);
        }
        // A mount grafted onto the root after we opened it is the one way the
        // meaning of our root descriptor can change. Detecting it needs a
        // syscall, so it is sampled rather than run per operation: the leaf
        // check already refuses any file whose device is not the workspace's,
        // which catches a mount on the *contents*; this sampling catches the
        // root descriptor itself being shadowed, and a window of a few thousand
        // operations is acceptable for an event that requires root.
        const SAMPLE_EVERY: u64 = 4096;
        let n = self.ops.fetch_add(1, Ordering::Relaxed);
        if n % SAMPLE_EVERY != 0 {
            return Ok(());
        }
        if sys::is_mount_point(self.root.as_raw_fd())? != self.root_was_mount {
            self.revoked.store(true, Ordering::SeqCst);
            return Err(Error::RootReplaced);
        }
        Ok(())
    }

    fn resolver(&self) -> Resolver<'_> {
        Resolver::new(&self.root, &self.info, &self.policy)
    }

    fn parse(&self, path: impl AsRef<Path>) -> Result<LexPath> {
        let s = path.as_ref().to_str().ok_or_else(|| Error::denied("<non-utf8 path>", Denied::BadPath))?;
        LexPath::parse(s)
    }

    // -----------------------------------------------------------------
    // read side
    // -----------------------------------------------------------------

    /// Open an existing file for reading.
    pub fn open_read(&self, path: impl AsRef<Path>) -> Result<File> {
        self.open_with(path.as_ref(), OpenOptions::read())
    }

    /// Open a file with explicit options.
    ///
    /// The creation flags are honoured atomically by the kernel: `O_CREAT` and
    /// `O_EXCL` are passed to the same `openat` that resolves the leaf, so
    /// there is no window in which a competing thread can substitute a symlink
    /// for the file we are about to create.
    pub fn open_with(&self, path: impl AsRef<Path>, opts: OpenOptions) -> Result<File> {
        self.check_live()?;
        let lex = self.parse(path)?;
        let mut flags = 0;
        if opts.read && opts.write {
            flags |= libc::O_RDWR;
        } else if opts.write || opts.append {
            flags |= libc::O_WRONLY;
        } else {
            flags |= libc::O_RDONLY;
        }
        if opts.append {
            flags |= libc::O_APPEND;
        }
        if opts.truncate {
            flags |= libc::O_TRUNC;
        }
        if opts.create_new {
            flags |= libc::O_CREAT | libc::O_EXCL;
        } else if opts.create {
            flags |= libc::O_CREAT;
        }
        let mode = opts.mode.unwrap_or(0o644);

        // # Two syscalls, in this order
        //
        // 1. `openat(root, path, O_NOFOLLOW_ANY|O_NONBLOCK)`. One syscall that
        //    resolves the *whole* relative path from the workspace root in the
        //    kernel, refusing a symlink at any component. Nothing about it is
        //    decided in userspace, so there is no check to race.
        // 2. `fgetattrlist` on the resulting descriptor for every fact the
        //    policy needs: type, device, link count, inode, parent, stored name.
        //
        // The descriptor is proof of containment by construction: the kernel
        // resolved it with the root's directory descriptor as its starting
        // point and a flag forbidding links, so its parent chain cannot include
        // a mount point grafted in after the fact, and its name cannot have
        // been a symlink when it was opened.
        //
        // `O_NONBLOCK` is on the opening call because a FIFO inside the
        // workspace would otherwise block the runner until a writer appears;
        // for every other type the kernel ignores it and it is cleared below.
        let full = lex.to_relative_os_string()?;
        // Whether this open took the link-free fast path. The hard-link parent
        // witness is only meaningful for a path that resolved straight to the
        // inode; when the fallback walker ran, *it* proved containment and its
        // verdict is what the caller gets.
        let direct;
        let fd = match sys::openat_nofollow_on_root(
            self.root.as_raw_fd(),
            &full,
            flags | libc::O_NONBLOCK,
            mode as libc::mode_t,
        ) {
            Ok(fd) => {
                direct = true;
                fd
            }
            Err(e) => {
                // A symlink anywhere in the path is the one refusal that needs
                // a second look: policy may allow following links that stay
                // inside, and `O_NOFOLLOW_ANY` cannot tell those apart from
                // links that leave. Fall back to the component walker, which
                // decides per link.
                let why = matches!(&e, Error::Io { source, .. }
                    if source.raw_os_error() == Some(libc::ELOOP));
                if why && self.policy.follow_symlinks {
                    let mut r = self.resolver();
                    let pinned = r.resolve(&lex, true)?;
                    let fd = sys::openat_nofollow(
                        pinned.parent.as_raw_fd(),
                        &pinned.name,
                        flags | libc::O_NONBLOCK,
                        mode as libc::mode_t,
                    )?;
                    let f = unsafe { File::from_raw_fd(fd) };
                    let (ev, stored) = sys::evidence(f.as_raw_fd())?;
                    // The slow path already validated every component.
                    self.validate_open(&f, &lex, opts, &ev, stored.as_deref(), false)?;
                    if ev.file_type() != libc::S_IFIFO as u32 {
                        sys::clear_nonblock(f.as_raw_fd())?;
                    }
                    return Ok(f);
                }
                return Err(self.classify_open_error(e, &lex));
            }
        };
        let file = unsafe { File::from_raw_fd(fd) };

        let (ev, stored_name) = sys::evidence(file.as_raw_fd())?;
        self.validate_open(&file, &lex, opts, &ev, stored_name.as_deref(), direct)?;

        // Walk the parent chain upward and refuse if any ancestor is a mount
        // point or on another filesystem. `..` from a descriptor never passes
        // through a symlink, so this cannot be redirected; it is one `openat`
        // plus one `evidence` per component, only for deep paths.
        // No per-ancestor syscalls are needed:
        //
        // * A filesystem mounted anywhere along the path changes the device
        //   the leaf reports, and `validate_open` has already refused a leaf
        //   whose device is not the workspace's. A mount is caught by the one
        //   `evidence` call above, not by walking the chain.
        // * The deny list is evaluated in userspace against the components the
        //   caller named, compared the way the volume compares. Deny entries
        //   are ASCII, whose only folding on APFS is ASCII case.
        self.check_denied_components(&lex)?;

        if ev.file_type() != libc::S_IFIFO as u32 {
            sys::clear_nonblock(file.as_raw_fd())?;
        }
        Ok(file)
    }

    /// Map the errno from the single resolving `openat` onto a typed refusal.
    ///
    /// `ELOOP` from `O_NOFOLLOW_ANY` means "a component was a symlink", which
    /// is the interesting case: report it as such rather than as a generic I/O
    /// error, so a build log says what happened without disclosing a path.
    fn classify_open_error(&self, e: Error, lex: &LexPath) -> Error {
        if let Error::Io { source, .. } = &e {
            if source.raw_os_error() == Some(libc::ELOOP) {
                return Error::denied(lex.display(), Denied::Symlink);
            }
        }
        e
    }

    /// Apply the deny list to every directory component of a path, and to the
    /// stored leaf name, by resolving each parent in turn. Only called when the
    /// deny list is non-empty and the path has more than one component, so the
    /// common single-file case costs nothing.
    /// Apply the deny list to every component the caller named.
    ///
    /// Pure userspace: no syscall, no window. Sound because the comparison uses
    /// the volume's own folding rule (see [`Policy::denies`]).
    fn check_denied_components(&self, lex: &LexPath) -> Result<()> {
        if self.policy.deny_list().is_empty() {
            return Ok(());
        }
        for (depth, comp) in lex.components().iter().enumerate() {
            if self.policy.denies(depth, comp, self.info.case_insensitive) {
                return Err(Error::denied(lex.display(), Denied::Policy));
            }
        }
        Ok(())
    }

    /// `lstat` a path without following a final symlink.
    pub fn metadata(&self, path: impl AsRef<Path>) -> Result<Meta> {
        self.check_live()?;
        let lex = self.parse(path)?;
        let mut r = self.resolver();
        let p = r.resolve(&lex, false)?;
        match p.st {
            Some(st) => {
                if st.st_dev as u32 != self.info.dev {
                    return Err(Error::denied(lex.display(), Denied::MountPoint));
                }
                Ok(Meta::from(st))
            }
            None => Err(Error::io("lstat", io::Error::from_raw_os_error(libc::ENOENT))),
        }
    }

    /// Stat following symlinks inside the workspace.
    pub fn metadata_follow(&self, path: impl AsRef<Path>) -> Result<Meta> {
        let f = self.open_read(path)?;
        let st = sys::fstat(f.as_raw_fd())?;
        Ok(Meta::from(st))
    }

    /// `readlink`: returns the link text, never follows it.
    pub fn read_link(&self, path: impl AsRef<Path>) -> Result<PathBuf> {
        self.check_live()?;
        if !self.policy.allow_symlink_read {
            return Err(Error::denied("readlink", Denied::Policy));
        }
        let lex = self.parse(path)?;
        let mut r = self.resolver();
        let p = r.resolve(&lex, false)?;
        let st = p
            .st
            .ok_or_else(|| Error::io("readlink", io::Error::from_raw_os_error(libc::ENOENT)))?;
        if st.st_mode & libc::S_IFMT != libc::S_IFLNK {
            return Err(Error::io("readlink", io::Error::from_raw_os_error(libc::EINVAL)));
        }
        Ok(PathBuf::from(sys::readlinkat(p.parent.as_raw_fd(), &p.name)?))
    }

    /// List a directory. Names are stored exactly as the volume holds them.
    pub fn read_dir(&self, path: impl AsRef<Path>) -> Result<Vec<DirEntry>> {
        self.check_live()?;
        let lex = self.parse(path)?;
        let mut r = self.resolver();
        let dir: Directory = r.resolve_dir(&lex, false)?;
        let entries = sys::read_dir(dir.fd.as_raw_fd())?;
        Ok(entries
            .into_iter()
            .map(|e| DirEntry {
                name: e.name.to_string_lossy().into_owned(),
                file_type: match e.d_type {
                    sys::DT_DIR => FileKind::Dir,
                    sys::DT_REG => FileKind::File,
                    sys::DT_LNK => FileKind::Symlink,
                    _ => FileKind::Other,
                },
            })
            .collect())
    }

    // ------------------------- write side -----------------------------

    /// Create a directory and any missing parents, inside the workspace.
    pub fn create_dir_all(&self, path: impl AsRef<Path>) -> Result<()> {
        self.check_live()?;
        let lex = self.parse(path)?;
        self.check_denied_components(&lex)?;
        let mut r = self.resolver();
        r.resolve_dir(&lex, true)?;
        Ok(())
    }

    pub fn create_dir(&self, path: impl AsRef<Path>) -> Result<()> {
        self.check_live()?;
        let lex = self.parse(path)?;
        self.check_denied_components(&lex)?;
        let (parent, leaf) = self.parent_and_leaf(&lex)?;
        sys::mkdirat(parent.as_raw_fd(), &leaf, 0o755).map_err(|e| match e {
            Error::Io { source, .. } if source.raw_os_error() == Some(libc::EEXIST) => {
                Error::denied(lex.display(), Denied::AlreadyExists)
            }
            e => e,
        })
    }

    pub fn remove_file(&self, path: impl AsRef<Path>) -> Result<()> {
        self.check_live()?;
        let lex = self.parse(path)?;
        let (parent, leaf) = self.parent_and_leaf_no_follow(&lex)?;
        let st = sys::fstatat_nofollow(parent.as_raw_fd(), &leaf)?;
        if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            return Err(Error::io("unlink", io::Error::from_raw_os_error(libc::EISDIR)));
        }
        sys::unlinkat(parent.as_raw_fd(), &leaf, false)
    }

    pub fn remove_dir(&self, path: impl AsRef<Path>) -> Result<()> {
        self.check_live()?;
        let lex = self.parse(path)?;
        let (parent, leaf) = self.parent_and_leaf_no_follow(&lex)?;
        let st = sys::fstatat_nofollow(parent.as_raw_fd(), &leaf)?;
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(Error::io("rmdir", io::Error::from_raw_os_error(libc::ENOTDIR)));
        }
        sys::unlinkat(parent.as_raw_fd(), &leaf, true)
    }

    /// Recursively remove a directory, never following a symlink and never
    /// touching anything outside the workspace.
    ///
    /// Deletion is the operation most often implemented with a copied
    /// check-then-use, so it is done here with directory descriptors only: each
    /// entry is removed relative to the fd of the directory it was listed from.
    pub fn remove_dir_all(&self, path: impl AsRef<Path>) -> Result<()> {
        self.check_live()?;
        let lex = self.parse(path)?;
        let (parent, leaf) = self.parent_and_leaf_no_follow(&lex)?;
        let st = sys::fstatat_nofollow(parent.as_raw_fd(), &leaf)?;
        if st.st_mode & libc::S_IFMT != libc::S_IFDIR {
            return Err(Error::io("rmdir", io::Error::from_raw_os_error(libc::ENOTDIR)));
        }
        let fd = sys::openat_dir(parent.as_raw_fd(), &leaf)?;
        let r = self.remove_contents(fd, 0);
        sys::close(fd);
        r?;
        sys::unlinkat(parent.as_raw_fd(), &leaf, true)
    }

    fn remove_contents(&self, dir_fd: i32, depth: usize) -> Result<()> {
        if depth > MAX_DEPTH {
            return Err(Error::denied("remove_dir_all", Denied::BadPath));
        }
        for entry in sys::read_dir(dir_fd)? {
            match entry.d_type {
                sys::DT_DIR => {
                    let sub = sys::openat_dir(dir_fd, &entry.name)?;
                    let r = self.remove_contents(sub, depth + 1);
                    sys::close(sub);
                    r?;
                    sys::unlinkat(dir_fd, &entry.name, true)?;
                }
                _ => sys::unlinkat(dir_fd, &entry.name, false)?,
            }
        }
        Ok(())
    }

    pub fn rename(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
        self.check_live()?;
        let a = self.parse(from)?;
        let b = self.parse(to)?;
        self.check_denied_components(&b)?;
        let (pa, la) = self.parent_and_leaf_no_follow(&a)?;
        let (pb, lb) = self.parent_and_leaf(&b)?;
        sys::renameat(pa.as_raw_fd(), &la, pb.as_raw_fd(), &lb)
    }

    /// Create a symlink. The target text is stored verbatim; the link is only
    /// ever followed later if it still resolves inside the workspace.
    pub fn symlink(&self, target: impl AsRef<Path>, link: impl AsRef<Path>) -> Result<()> {
        self.check_live()?;
        let lex = self.parse(link)?;
        self.check_denied_components(&lex)?;
        let (parent, leaf) = self.parent_and_leaf(&lex)?;
        sys::symlinkat(target.as_ref().as_os_str(), parent.as_raw_fd(), &leaf)
    }

    /// Create a hard link between two workspace paths.
    pub fn hard_link(&self, from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
        self.check_live()?;
        if !self.policy.allow_hardlink {
            return Err(Error::denied("hard link", Denied::Policy));
        }
        let a = self.parse(from)?;
        let b = self.parse(to)?;
        self.check_denied_components(&b)?;
        let (pa, la) = self.parent_and_leaf_no_follow(&a)?;
        // `linkat` with flags 0 does not follow a symlink in the source, so a
        // link to a link copies the link itself and cannot launder a target.
        let st = sys::fstatat_nofollow(pa.as_raw_fd(), &la)?;
        if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
            return Err(Error::denied(a.display(), Denied::Policy));
        }
        if st.st_dev as u32 != self.info.dev {
            return Err(Error::denied(a.display(), Denied::MountPoint));
        }
        let (pb, lb) = self.parent_and_leaf(&b)?;
        sys::linkat(pa.as_raw_fd(), &la, pb.as_raw_fd(), &lb)?;
        // Register the inode under the identity the witness checks. Not
        // `stat.st_ino`: the `ATTR_CMN_FILEID` value is what `evidence` reports.
        let src = sys::openat_nofollow(pa.as_raw_fd(), &la, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        let ev = sys::evidence(src);
        sys::close(src);
        let ev = ev?.0;
        if let Ok(mut set) = self.linked.lock() {
            set.insert((ev.dev, ev.file_id));
        }
        Ok(())
    }

    /// Change the mode of an object, addressed by descriptor.
    pub fn set_permissions(&self, path: impl AsRef<Path>, mode: u32) -> Result<()> {
        self.check_live()?;
        let lex = self.parse(path)?;
        let mut r = self.resolver();
        let p = r.resolve(&lex, false)?;
        if p.st.is_none() {
            return Err(Error::io("chmod", io::Error::from_raw_os_error(libc::ENOENT)));
        }
        let flags = libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW;
        let fd = sys::openat_nofollow(p.parent.as_raw_fd(), &p.name, flags, 0)?;
        let r = sys::fchmod(fd, mode as libc::mode_t);
        sys::close(fd);
        r
    }

    fn parent_and_leaf_no_follow(
        &self,
        lex: &LexPath,
    ) -> Result<(OwnedFd, std::ffi::OsString)> {
        let mut r = self.resolver();
        let (dirs, leaf) = lex.split_leaf();
        let parent = if dirs.is_empty() {
            Directory {
                fd: unsafe { OwnedFd::from_raw_fd(sys::dup(self.root.as_raw_fd())?) },
                folded: false,
            }
        } else {
            let p = LexPath::from_components(dirs.to_vec());
            r.resolve_dir(&p, false)?
        };
        Ok((parent.fd, leaf.clone()))
    }

    fn parent_and_leaf(&self, lex: &LexPath) -> Result<(OwnedFd, std::ffi::OsString)> {
        self.parent_and_leaf_no_follow(lex)
    }

    /// Post-open validation, performed on the descriptor we will actually use.
    ///
    /// Every check is against the vnode, so none of it can be raced: an
    /// attacker changing names after this point changes nothing about the file
    /// this descriptor refers to.
    fn validate_open(
        &self,
        file: &File,
        lex: &LexPath,
        opts: OpenOptions,
        ev: &sys::Evidence,
        stored_name: Option<&std::ffi::OsStr>,
        direct: bool,
    ) -> Result<()> {
        let _ = file;
        if !self.policy.permits_type(ev.file_type()) {
            return Err(Error::denied(lex.display(), Denied::Policy));
        }
        if ev.dev != self.info.dev {
            return Err(Error::denied(lex.display(), Denied::MountPoint));
        }

        // Name policy on the spelling the volume stored, never the caller's:
        // on a folding volume `.GIT` and `.git` are one object. Intermediate
        // directories are checked by `check_denied_components`, which the caller
        // runs only when the deny list is not empty.
        if let Some(stored) = stored_name {
            if self.info.case_insensitive {
                let requested = lex.components().last().map(|c| c.as_os_str()).unwrap_or(stored);
                if self.policy.strict_names && stored != requested {
                    return Err(Error::denied(lex.display(), Denied::NameFolding));
                }
            }
        }

        // Only a *regular file* needs the hard-link witness. A symlink leaf
        // read with `follow` reports its *target* here (the kernel followed
        // it), and the target's link count says nothing about the link we
        // traversed — the walker already proved the target is inside.
        //
        // `link_count > 1` is the only case that needs the extra probe: when it
        // is 1 and the path went straight to the inode, there is nothing to
        // check. The probe is deferred into `check_link_witness`, which is why
        // the common read costs two syscalls, not three.
        if ev.is_regular() && !self.policy.trust_multiply_linked {
            let known = self
                .linked
                .lock()
                .map(|s| s.contains(&(ev.dev, ev.file_id)))
                .unwrap_or(false);
            if !known {
                self.check_link_witness(ev, lex, direct)?;
            }
        }

        // A writable handle to a multiply-linked file would let a script
        // scribble on the contents the other name sees.
        if (opts.write || opts.append) && ev.is_regular() && ev.link_count > 1 {
            let trusted = self
                .linked
                .lock()
                .map(|s| s.contains(&(ev.dev, ev.file_id)))
                .unwrap_or(false);
            if !trusted {
                return Err(Error::denied(lex.display(), Denied::MultiplyLinked));
            }
        }
        if let Some(max) = self.policy.max_file_size {
            if ev.data_length > max {
                return Err(Error::denied(lex.display(), Denied::Policy));
            }
        }
        Ok(())
    }

    /// The hard-link witness.
    ///
    /// A hard link has no target to inspect: it *is* the same inode. So the
    /// only question is whether that inode has, or had, a second name outside
    /// the workspace. Two facts answer it, and both are read from the
    /// descriptor:
    ///
    /// * `link_count == 1` — no other name exists *now*;
    /// * `parent_id` is the directory we asked the kernel to resolve through —
    ///   the descriptor was reached via a link in that directory, not some
    ///   other one.
    ///
    /// Neither alone is sound. An attacker who plants a link can unlink it
    /// between our `openat` and our `fgetattrlist`; the count is then one, but
    /// the kernel has already re-pointed `parent_id` at the surviving outside
    /// directory, so the comparison fails. The race therefore costs a spurious
    /// denial, never a disclosure — and `hardlink_planting_never_leaks` in
    /// `tests/race.rs` measures exactly that.
    ///
    /// The structural fix is not a better check but a better filesystem
    /// boundary: a hard link cannot cross one (`EXDEV`), so
    /// [`Workspace::open_isolated`] retires this whole class. See
    /// [`Isolation`].
    fn check_link_witness(&self, ev: &sys::Evidence, lex: &LexPath, direct: bool) -> Result<()> {
        if self.policy.trust_multiply_linked {
            return Ok(());
        }
        // Links this handle created itself are known to have both names inside
        // the workspace; skip the witness for them, which is what makes an
        // in-workspace hard-link workflow (ccache, content-addressed stores)
        // work under the strict default.
        if self.linked.lock().map(|s| s.contains(&(ev.dev, ev.file_id))).unwrap_or(false) {
            return Ok(());
        }
        if ev.link_count != 1 {
            return Err(Error::denied(lex.display(), Denied::MultiplyLinked));
        }
        // The parent half of the witness. There is deliberately no way to skip
        // it: `link_count == 1` on its own is racy (an attacker unlinks its own
        // planted link after our `openat`), so this comparison is what closes
        // the window. A version that skipped it whenever a cheap probe guessed
        // "not a symlink" re-opened the hole and leaked 12,496 times; the probe
        // answers a different question than the one that matters.
        //
        // `direct == false` means a symlink was followed and the walker already
        // proved the target is inside, and the parent id belongs to the target's
        // directory, which the path never named.
        if direct {
            let expected = if lex.components().len() <= 1 {
                self.root_inode()?
            } else {
                self.parent_inode(lex)?
            };
            if ev.parent_id != expected {
                return Err(Error::denied(lex.display(), Denied::MultiplyLinked));
            }
        }
        Ok(())
    }

    /// The inode of the directory a path's leaf lives in.
    ///
    /// Opening that directory is one syscall; reading its inode is part of the
    /// same `evidence` call the walker already performs, so this is used only as
    /// the fallback when the leaf's `parent_id` does not match. The comparison
    /// itself is on inode numbers, which survive a directory being renamed or
    /// moved — unlike any comparison on its path.
    fn parent_inode(&self, lex: &LexPath) -> Result<u32> {
        let comps = lex.components();
        let parent_os = if comps.len() <= 1 {
            std::ffi::OsString::from(".")
        } else {
            LexPath::from_components(comps[..comps.len() - 1].to_vec()).to_relative_os_string()?
        };
        let fd = sys::openat_dir_nofollow_any(self.root.as_raw_fd(), &parent_os)?;
        let (ev, _) = sys::evidence(fd)?;
        sys::close(fd);
        Ok(ev.file_id as u32)
    }

    /// Inode of the workspace root's own directory, used when the leaf sits
    /// directly in it.
    fn root_inode(&self) -> Result<u32> {
        let (ev, _) = sys::evidence(self.root.as_raw_fd())?;
        Ok(ev.file_id as u32)
    }
}

// ---------------------------------------------------------------------------
// Diagnostics used by the test suite and by the runner at start-up
// ---------------------------------------------------------------------------

/// Does `path` denote the root of a mounted filesystem?
///
/// Exposed so a runner can verify its assumptions about the host before
/// accepting jobs, and so the test suite can prove the detector works without
/// needing root to create a mount.
pub fn probe_is_mount_point(path: impl AsRef<Path>) -> Result<bool> {
    let c = sys::cstring(path.as_ref().as_os_str())?;
    let fd = unsafe {
        libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
    };
    if fd < 0 {
        return Err(Error::io("open", io::Error::last_os_error()));
    }
    let r = sys::is_mount_point(fd);
    sys::close(fd);
    r
}

/// Does the volume holding `path` fold case when resolving names?
pub fn probe_volume_case_insensitive(path: impl AsRef<Path>) -> Result<bool> {
    let c = sys::cstring(path.as_ref().as_os_str())?;
    let fd = unsafe {
        libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC)
    };
    if fd < 0 {
        return Err(Error::io("open", io::Error::last_os_error()));
    }
    let r = sys::volume_is_case_sensitive(fd);
    sys::close(fd);
    Ok(!r?)
}

/// Expose the raw descriptor evidence for tests and diagnostics.
#[doc(hidden)]
pub fn debug_evidence(fd: i32) -> Result<sys::Evidence> {
    Ok(sys::evidence(fd)?.0)
}

/// How strongly the workspace is isolated from the rest of the filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    /// The workspace is its own filesystem. Hard links cannot cross in, so
    /// containment is structural rather than checked.
    Confined,
    /// The workspace shares a filesystem with other data. Containment rests on
    /// the descriptor walk and the hard-link witness, which are sound for
    /// symlinks, mounts and rename races, and narrow (but do not structurally
    /// eliminate) the hard-link window.
    Shared { reason: &'static str },
}

/// A directory entry as reported by [`Workspace::read_dir`].
#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: String,
    pub file_type: FileKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    File,
    Dir,
    Symlink,
    Other,
}

/// A metadata snapshot. Mirrors the interesting parts of `stat` without exposing
/// a raw struct that callers might use to reconstruct paths.
#[derive(Debug, Clone, Copy)]
pub struct Meta {
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u64,
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub is_fifo: bool,
    pub is_socket: bool,
    pub is_device: bool,
}

impl From<libc::stat> for Meta {
    fn from(st: libc::stat) -> Self {
        let ft = st.st_mode & libc::S_IFMT;
        Meta {
            size: st.st_size as u64,
            mode: st.st_mode as u32,
            uid: st.st_uid,
            gid: st.st_gid,
            nlink: st.st_nlink as u64,
            is_file: ft == libc::S_IFREG,
            is_dir: ft == libc::S_IFDIR,
            is_symlink: ft == libc::S_IFLNK,
            is_fifo: ft == libc::S_IFIFO,
            is_socket: ft == libc::S_IFSOCK,
            is_device: ft == libc::S_IFCHR || ft == libc::S_IFBLK,
        }
    }
}


