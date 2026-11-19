//! Error type for the layer.
//!
//! Two rules drive the design:
//!
//! 1. **Fail closed.** Any ambiguity — an unexpected errno, a mount we cannot
//!    rule out, a name we cannot canonicalise — is an error, never a fallback
//!    to the permissive path.
//! 2. **Do not leak host paths.** A denial reports the *caller's* relative path
//!    and a stable reason code; the filesystem's own guess at an absolute path
//!    is never echoed back, because a build script that can make the layer
//!    repeat an outside path is a directory-probing oracle.

use std::fmt;
use std::io;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// A component was a symlink.
    Symlink,
    /// A component resolved outside the workspace.
    Outside,
    /// A component named something the policy forbids (e.g. `.git`).
    Policy,
    /// Reached a mount point, bind mount or other grafted filesystem.
    MountPoint,
    /// The object is reachable through more than one name (hard link), so its
    /// second name cannot be vouched for.
    MultiplyLinked,
    /// A path component was not a directory, or a final component was not the
    /// type of object the operation required.
    WrongType,
    /// The name the volume stores differs from the name requested (case or
    /// Unicode normalisation folding).
    NameFolding,
    /// The path was malformed: empty, absolute, `..`, too long, NUL.
    BadPath,
    /// The target already exists where it must not.
    AlreadyExists,
    /// Generic refusal raised by policy hooks.
    Refused,
}

impl Denied {
    pub fn code(self) -> &'static str {
        match self {
            Denied::Symlink => "symlink",
            Denied::Outside => "outside-workspace",
            Denied::Policy => "policy",
            Denied::MountPoint => "mount-point",
            Denied::MultiplyLinked => "multiply-linked",
            Denied::WrongType => "wrong-type",
            Denied::NameFolding => "name-folding",
            Denied::BadPath => "bad-path",
            Denied::AlreadyExists => "already-exists",
            Denied::Refused => "refused",
        }
    }
}

#[derive(Debug)]
pub enum Error {
    /// The operation touched something the policy forbids.
    Denied { what: String, why: Denied },
    /// The workspace root itself was replaced (renamed/mounted over) since the
    /// handle was created; the only safe response is to stop using it.
    RootReplaced,
    /// The workspace root handle was revoked (explicitly or because the process
    /// forked past the point where handles are shared safely).
    Revoked,
    /// An underlying OS error, with the operation name but no host path.
    Io { op: &'static str, source: io::Error },
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn denied(what: impl Into<String>, why: Denied) -> Error {
        Error::Denied { what: what.into(), why }
    }

    pub fn from_io(e: io::Error) -> Error {
        Error::Io { op: "syscall", source: e }
    }

    pub fn io(op: &'static str, e: io::Error) -> Error {
        Error::Io { op, source: e }
    }

    pub fn invalid_path(msg: &'static str) -> Error {
        Error::Denied { what: msg.to_string(), why: Denied::BadPath }
    }

    /// The permission-style errno a POSIX caller would expect, when there is one.
    pub fn errno(&self) -> i32 {
        match self {
            Error::Denied { .. } => libc::EACCES,
            Error::RootReplaced => libc::ESTALE,
            Error::Revoked => libc::EBADF,
            Error::Io { source, .. } => source.raw_os_error().unwrap_or(libc::EIO),
        }
    }

    pub fn is_not_found(&self) -> bool {
        matches!(self, Error::Io { source: e, .. } if e.raw_os_error() == Some(libc::ENOENT))
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Denied { what, why } => {
                write!(f, "access denied [{}]: {}", why.code(), what)
            }
            Error::RootReplaced => {
                write!(f, "access denied [root-replaced]: workspace root was swapped or mounted over")
            }
            Error::Revoked => write!(f, "access denied [revoked]: workspace handle is no longer valid"),
            Error::Io { op, source } => write!(f, "{op}: {source}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        if e.kind() == io::ErrorKind::NotFound {
            return Error::io("stat", e);
        }
        Error::io("syscall", e)
    }
}
