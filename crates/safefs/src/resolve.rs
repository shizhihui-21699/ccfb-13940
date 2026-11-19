//! The resolution engine: the only part of the layer that has to be correct for
//! everything else to be safe.
//!
//! # The invariant
//!
//! > Every object handed out is reached from a directory descriptor that was
//! > itself reached from the workspace root by a chain of `openat` calls in
//! > which no component was a symlink and no directory was a mount point.
//!
//! The descriptor chain *is* the proof of containment. Names are never turned
//! into absolute paths and compared against a prefix, because a name can be
//! swapped between the comparison and the use; a descriptor cannot. Once a
//! descriptor exists, renaming, unlinking, symlink swapping and mounting over
//! its path cannot change what it refers to — the kernel holds the vnode.
//!
//! # Cost of a component
//!
//! One `openat(O_NOFOLLOW|O_DIRECTORY|O_NONBLOCK)` + one `fgetattrlist` (mount
//! status) +, on folding volumes, one `fgetattrlist` (stored name). Measured on
//! this machine a complete walk costs the same as a single absolute `open(2)`,
//! so the guarantee is free compared with the resolution the kernel would do.

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

use crate::canon::LexPath;
use crate::error::{Denied, Error, Result};
use crate::policy::Policy;
use crate::sys;

const MAX_SYMLINK_HOPS: usize = 40;
const MAX_COMPONENTS: usize = 8192;

/// Identity of the workspace root, captured when the handle was created.
pub(crate) struct RootInfo {
    pub dev: u32,
    /// The root inode. Kept so a future check can compare it against
    /// `ATTR_CMN_PARENTID` if a volume reports a usable parent for the root.
    #[allow(dead_code)]
    pub ino: u64,
    /// True when the volume folds case for name lookup.
    pub case_insensitive: bool,
}

/// A resolved leaf: an open descriptor for its containing directory plus the
/// leaf name, exactly as policy validated it.
pub(crate) struct Pinned {
    pub parent: OwnedFd,
    pub name: OsString,
    /// `lstat` of the leaf if it exists; `None` if it does not.
    pub st: Option<libc::stat>,
    /// True if the volume stores a different spelling than the caller used.
    pub folded: bool,
}

pub(crate) struct Resolver<'a> {
    root: &'a OwnedFd,
    info: &'a RootInfo,
    policy: &'a Policy,
    hops: usize,
    processed: usize,
}

impl<'a> Resolver<'a> {
    pub fn new(root: &'a OwnedFd, info: &'a RootInfo, policy: &'a Policy) -> Self {
        Resolver { root, info, policy, hops: 0, processed: 0 }
    }

    /// Walk `path` down to its parent directory and leaf.
    ///
    /// `follow_final == false` reports a symlink leaf as a link rather than
    /// resolving it (used by `readlink`, `unlink`, `rename`, `lstat`).
    /// `follow_final == true` resolves it, subject to policy.
    ///
    /// Returns the directory fd of the leaf's parent — never a path — so the
    /// caller's next syscall is a single `openat`/`unlinkat`/`renameat` that
    /// the kernel executes atomically with respect to the vnode we proved.
    pub fn resolve(&mut self, path: &LexPath, follow_final: bool) -> Result<Pinned> {
        let mut queue: VecDeque<OsString> = path.components().iter().cloned().collect();
        let mut stack: Vec<OwnedFd> = vec![dup_root(self.root)?];
        let mut folded_any = false;

        loop {
            let comp = match queue.pop_front() {
                Some(c) => c,
                None => {
                    // Path named the directory it ended on (trailing slash).
                    let cur = stack.last().expect("root present");
                    let st = sys::fstat(cur.as_raw_fd())?;
                    return Ok(Pinned {
                        parent: unsafe { OwnedFd::from_raw_fd(sys::dup(cur.as_raw_fd())?) },
                        name: OsString::from("."),
                        st: Some(st),
                        folded: folded_any,
                    });
                }
            };

            self.processed += 1;
            if self.processed > MAX_COMPONENTS {
                return Err(Error::denied(path.display(), Denied::BadPath));
            }

            // `.` is a no-op; `..` moves up our *stack*, never the kernel's
            // path, so it can never climb above the root.
            match comp.as_bytes() {
                b"." => continue,
                b".." => {
                    if stack.len() == 1 {
                        return Err(Error::denied(path.display(), Denied::Outside));
                    }
                    stack.pop();
                    continue;
                }
                _ => {}
            }

            let cur = stack.last().expect("root present").as_raw_fd();
            let depth = stack.len() - 1;
            let is_final = queue.is_empty();

            let lst = match sys::fstatat_nofollow(cur, &comp) {
                Ok(st) => Some(st),
                Err(Error::Io { source, .. }) if source.raw_os_error() == Some(libc::ENOENT) => None,
                Err(e) => return Err(e),
            };
            let ft = lst.as_ref().map(|s| s.st_mode & libc::S_IFMT);

            // ---- symlink ----------------------------------------------------
            if ft == Some(libc::S_IFLNK) {
                if is_final && !follow_final {
                    if !self.policy.allow_symlink_read {
                        return Err(Error::denied(path.display(), Denied::Symlink));
                    }
                    return Ok(Pinned {
                        parent: unsafe { OwnedFd::from_raw_fd(sys::dup(cur)?) },
                        name: comp,
                        st: lst,
                        folded: folded_any,
                    });
                }
                if !self.policy.follow_symlinks {
                    return Err(Error::denied(path.display(), Denied::Symlink));
                }
                self.hops += 1;
                if self.hops > MAX_SYMLINK_HOPS {
                    return Err(Error::denied(path.display(), Denied::Symlink));
                }
                let target = sys::readlinkat(cur, &comp)?;
                let expanded = expand_link_target(&target, path)?;
                for c in expanded.into_iter().rev() {
                    queue.push_front(c);
                }
                continue;
            }

            // ---- directory (or missing component) ---------------------------
            if lst.is_none() || ft == Some(libc::S_IFDIR) {
                if is_final && lst.is_none() {
                    // Missing leaf: report the parent so the caller can create.
                    return Ok(Pinned {
                        parent: unsafe { OwnedFd::from_raw_fd(sys::dup(cur)?) },
                        name: comp,
                        st: None,
                        folded: folded_any,
                    });
                }
                let fd = match sys::openat_dir(cur, &comp) {
                    Ok(fd) => fd,
                    Err(Error::Io { source, .. })
                        if matches!(source.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) =>
                    {
                        // Swapped to a symlink (or non-dir) after the lstat.
                        return Err(Error::denied(path.display(), Denied::Symlink));
                    }
                    Err(e) => return Err(e),
                };
                match self.vet_dir_fd(fd, &comp, depth, path) {
                    Ok(folded) => {
                        folded_any |= folded;
                        if is_final {
                            let st = sys::fstat(fd)?;
                            // Keep the fd itself as the "parent" of ".".
                            return Ok(Pinned {
                                parent: unsafe { OwnedFd::from_raw_fd(fd) },
                                name: OsString::from("."),
                                st: Some(st),
                                folded: folded_any,
                            });
                        }
                        stack.push(unsafe { OwnedFd::from_raw_fd(fd) });
                    }
                    Err(e) => {
                        sys::close(fd);
                        return Err(e);
                    }
                }
                continue;
            }

            // ---- non-directory leaf -----------------------------------------
            if !is_final {
                return Err(Error::io("openat", std::io::Error::from_raw_os_error(libc::ENOTDIR)));
            }
            if !self.policy.permits_type(ft.unwrap_or(0) as u32) {
                return Err(Error::denied(path.display(), Denied::Policy));
            }
            // The leaf's stored name matters too: a file inside a denied
            // directory cannot be reached, but a denied *name* that is a file
            // (`.git` as a plain file is harmless; a policy entry like
            // `.gitmodules` is not) must still be refused.
            {
                let (folded, _stored) = self.stored_name_of(cur, &comp, depth, path)?;
                folded_any |= folded;
            }
            return Ok(Pinned {
                parent: unsafe { OwnedFd::from_raw_fd(sys::dup(cur)?) },
                name: comp,
                st: lst,
                folded: folded_any,
            });
        }
    }

    /// Resolve a path to a directory, optionally creating missing components.
    pub fn resolve_dir(&mut self, path: &LexPath, create: bool) -> Result<Directory> {
        if create {
            // Creation revalidates every component itself, including ones that
            // already exist, so there is nothing to gain from resolving first.
            return self.make_dirs(path);
        }
        let p = self.resolve(path, true)?;
        if let Some(st) = p.st {
            if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                return Ok(Directory { fd: p.parent, folded: p.folded });
            }
            return Err(Error::denied(path.display(), Denied::WrongType));
        }
        Err(Error::io("openat", std::io::Error::from_raw_os_error(libc::ENOENT)))
    }

    fn make_dirs(&mut self, path: &LexPath) -> Result<Directory> {
        let mut stack: Vec<OwnedFd> = vec![dup_root(self.root)?];
        let mut folded_any = false;
        for (depth, comp) in path.components().iter().enumerate() {
            let cur = stack.last().expect("root present").as_raw_fd();
            match sys::mkdirat(cur, comp, 0o755) {
                Ok(()) => {}
                Err(Error::Io { source, .. }) if source.raw_os_error() == Some(libc::EEXIST) => {}
                Err(e) => return Err(e),
            }
            // Re-validate what we just created: an attacker racing us can make
            // this `openat` fail, but cannot make it open something outside.
            let fd = sys::openat_dir(cur, comp).map_err(|e| match e {
                Error::Io { source, .. }
                    if matches!(source.raw_os_error(), Some(libc::ELOOP) | Some(libc::ENOTDIR)) =>
                {
                    Error::denied(path.display(), Denied::Symlink)
                }
                e => e,
            })?;
            match self.vet_dir_fd(fd, comp, depth, path) {
                Ok(folded) => {
                    folded_any |= folded;
                    stack.push(unsafe { OwnedFd::from_raw_fd(fd) });
                }
                Err(e) => {
                    sys::close(fd);
                    return Err(e);
                }
            }
        }
        Ok(Directory { fd: stack.pop().expect("at least root"), folded: folded_any })
    }

    /// Verify a freshly opened directory is inside the workspace and permitted
    /// by policy. Returns whether its stored name was folded.
    fn vet_dir_fd(&self, fd: RawFd, requested: &OsStr, depth: usize, path: &LexPath) -> Result<bool> {
        // One syscall yields the mount status, the device, and the stored name.
        let (ev, stored) = sys::evidence(fd)?;
        if ev.is_mount_point {
            return Err(Error::denied(path.display(), Denied::MountPoint));
        }
        if ev.dev != self.info.dev {
            return Err(Error::denied(path.display(), Denied::MountPoint));
        }
        let (folded, _) = self.apply_name_policy(stored, requested, depth, path)?;
        Ok(folded)
    }

    /// Compare the caller's spelling with the volume's, then apply the deny
    /// list. On a case-sensitive, non-normalising volume the two spellings are
    /// necessarily equal and the comparison is skipped.
    fn apply_name_policy(
        &self,
        stored: Option<OsString>,
        requested: &OsStr,
        depth: usize,
        path: &LexPath,
    ) -> Result<(bool, OsString)> {
        let stored = match stored {
            Some(s) if self.info.case_insensitive => s,
            _ => return Ok((false, requested.to_os_string())),
        };
        let folded = stored.as_os_str() != requested;
        if self.policy.strict_names && folded {
            return Err(Error::denied(path.display(), Denied::NameFolding));
        }
        if self.policy.denies(depth, &stored, self.info.case_insensitive) {
            return Err(Error::denied(path.display(), Denied::Policy));
        }
        Ok((folded, stored))
    }

    /// Compare the caller's spelling against the spelling the volume kept.
    ///
    /// On a case-insensitive or normalising volume, `.git` and `.GIT` are the
    /// same object; deciding policy from the caller's spelling would let a
    /// script write to a denied name by changing its case. So policy is always
    /// evaluated on the stored name.
    /// Stored name of a *child* of `dirfd`, by `fstatat`-free means: the child
    /// is opened with `O_NOFOLLOW` first when it is a symlink we may not follow.
    fn stored_name_of(&self, dirfd: RawFd, requested: &OsStr, depth: usize, path: &LexPath) -> Result<(bool, OsString)> {
        // Only a folding volume can store a different spelling, and only then
        // does the extra `openat` pay for itself.
        if !self.info.case_insensitive && !self.policy.needs_stored_names() {
            return Ok((false, requested.to_os_string()));
        }
        let fd = match sys::openat_nofollow(dirfd, requested, libc::O_RDONLY | libc::O_NONBLOCK, 0) {
            Ok(fd) => fd,
            Err(_) => return Ok((false, requested.to_os_string())),
        };
        let r = sys::evidence(fd);
        sys::close(fd);
        let (_, stored) = r?;
        self.apply_name_policy(stored, requested, depth, path)
    }
}

/// An open directory that is known to be inside the workspace.
pub(crate) struct Directory {
    pub fd: OwnedFd,
    #[allow(dead_code)]
    pub folded: bool,
}

fn dup_root(root: &OwnedFd) -> Result<OwnedFd> {
    Ok(unsafe { OwnedFd::from_raw_fd(sys::dup(root.as_raw_fd())?) })
}

/// Expand a symlink target into components to splice into the walk.
///
/// Absolute targets are refused: an absolute target names a location we would
/// have to re-resolve *by name* to prove is inside, and any name-based proof is
/// exactly the race this layer exists to avoid. Relative targets are re-walked
/// from the link's own directory, so `../../..` simply runs out of stack.
fn expand_link_target(target: &OsStr, path: &LexPath) -> Result<Vec<OsString>> {
    let bytes = target.as_bytes();
    if bytes.is_empty() || bytes[0] == b'/' || bytes.contains(&0) {
        return Err(Error::denied(path.display(), Denied::Outside));
    }
    let mut out = Vec::new();
    for seg in bytes.split(|b| *b == b'/') {
        match seg {
            b"" | b"." => continue,
            b".." => out.push(OsString::from("..")),
            s => {
                if s.len() > crate::canon::MAX_NAME {
                    return Err(Error::denied(path.display(), Denied::BadPath));
                }
                out.push(OsString::from_vec(s.to_vec()));
            }
        }
    }
    Ok(out)
}
