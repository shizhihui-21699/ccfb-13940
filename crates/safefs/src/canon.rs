//! Lexical path canonicalisation.
//!
//! **Why this exists.** The tempting design is "resolve the path with
//! `std::fs::canonicalize`, check it starts with the workspace prefix, then
//! open it". That design is broken three ways:
//!
//! * the check and the open are two syscalls with an attacker-controlled gap;
//! * `canonicalize` follows symlinks, so a component swapped between the two
//!   resolves differently the second time;
//! * prefix comparison is wrong for `..`, for case-insensitive volumes and for
//!   Unicode-normalising volumes.
//!
//! This module does the *purely lexical* half: it turns caller input into a
//! sequence of components that (a) never contains `..`, `.`, an empty segment,
//! a NUL or a `/`, and (b) never starts at the filesystem root. Everything that
//! needs the filesystem — symlinks, mounts, hard links, name folding — is
//! checked later against pinned directory handles, where races cannot occur.
//!
//! The lexical pass alone is *not* the security boundary; it is the input
//! validation that keeps the syscall layer simple enough to audit.

use std::ffi::OsString;
use std::os::unix::ffi::OsStrExt;

use crate::error::{Denied, Error, Result};

/// Maximum number of components we will walk. Bounded so a malicious deep path
/// cannot make the layer allocate or recurse without limit.
pub const MAX_DEPTH: usize = 256;
/// Maximum length of one component, matching `NAME_MAX` on APFS.
pub const MAX_NAME: usize = 255;

/// A validated, relative, symlink-hostile-at-parse-time path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LexPath {
    components: Vec<OsString>,
    /// The spelling the caller used, kept only for error messages. It is
    /// caller-controlled and never compared against anything.
    original: String,
}

impl LexPath {
    /// Parse caller input.
    ///
    /// Rejected outright: absolute paths, any `..` component, empty paths,
    /// NUL, components longer than `NAME_MAX`, and paths deeper than
    /// [`MAX_DEPTH`].
    ///
    /// Dot components are *dropped* rather than rejected, because `./x` and
    /// `x` are the same file and rejecting the former would break ordinary
    /// build scripts for no security benefit. They are dropped lexically, so
    /// the resulting component list contains only real names.
    pub fn parse(input: &str) -> Result<LexPath> {
        if input.is_empty() {
            return Err(Error::denied("<empty path>", Denied::BadPath));
        }
        let bytes = input.as_bytes();
        if bytes.contains(&0) {
            return Err(Error::denied(input, Denied::BadPath));
        }
        if bytes[0] == b'/' {
            return Err(Error::denied(input, Denied::Outside));
        }
        let mut components = Vec::new();
        for raw in input.split('/') {
            match raw {
                "" | "." => continue,
                ".." => {
                    // Even `a/../b`, which is lexically inside, is refused:
                    // on a volume that folds case or normalises Unicode, `a`
                    // and `A` can be the same directory, and letting `..`
                    // through would then be a way to climb out via a name
                    // the caller does not control.
                    return Err(Error::denied(input, Denied::Outside));
                }
                name => {
                    if name.len() > MAX_NAME {
                        return Err(Error::denied(input, Denied::BadPath));
                    }
                    components.push(OsString::from(name));
                }
            }
        }
        if components.is_empty() {
            return Err(Error::denied(input, Denied::BadPath));
        }
        if components.len() > MAX_DEPTH {
            return Err(Error::denied(input, Denied::BadPath));
        }
        Ok(LexPath { components, original: input.to_string() })
    }

    /// Build a path from components that have already been validated.
    ///
    /// Only the resolver and the public API's own splitting use this; the
    /// components come from a `LexPath` that went through [`LexPath::parse`],
    /// so they are known relative, `..`-free and NUL-free.
    pub(crate) fn from_components(components: Vec<OsString>) -> LexPath {
        debug_assert!(!components.is_empty());
        let original = components
            .iter()
            .map(|c| c.to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        LexPath { components, original }
    }

    pub fn components(&self) -> &[OsString] {
        &self.components
    }

    pub fn is_dir_hint(&self) -> bool {
        self.original.ends_with('/')
    }

    /// Split into every proper ancestor directory and the final leaf name.
    ///
    /// For `a/b/c` this is `(["a", "b"], "c")`. For a single component it is
    /// `([], "a")`. The leaf is the only component that an operation may
    /// create, remove or rename; all ancestors must already exist and be
    /// directories.
    pub fn split_leaf(&self) -> (&[OsString], &OsString) {
        let (leaf, dirs) = self.components.split_last().expect("parse guarantees non-empty");
        (dirs, leaf)
    }

    /// The validated components joined with `/`, as an `OsStr` ready for
    /// `openat`. Empty components never appear, so this cannot produce `//`.
    pub fn to_relative_os_string(&self) -> Result<OsString> {
        let mut out = OsString::new();
        for (i, c) in self.components.iter().enumerate() {
            if i > 0 {
                out.push("/");
            }
            out.push(c);
        }
        if out.is_empty() {
            return Err(Error::denied("<empty path>", Denied::BadPath));
        }
        Ok(out)
    }

    pub fn display(&self) -> &str {
        &self.original
    }

    /// Reject any component listed in a deny list, comparing the way the volume
    /// compares. Case folding is handled conservatively: if the volume is
    /// case-insensitive, comparison is ASCII-case-insensitive, because that is
    /// the smallest folding APFS applies.
    pub fn check_denied(&self, denied_names: &[&str], case_insensitive: bool) -> Result<()> {
        for comp in &self.components {
            let b = comp.as_bytes();
            for d in denied_names {
                let db = d.as_bytes();
                let hit = if case_insensitive {
                    b.eq_ignore_ascii_case(db)
                } else {
                    b == db
                };
                if hit {
                    return Err(Error::denied(self.original.clone(), Denied::Policy));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(p: &str) -> Vec<String> {
        LexPath::parse(p)
            .unwrap()
            .components()
            .iter()
            .map(|c| c.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn accepts_relative() {
        assert_eq!(ok("a/b/c"), ["a", "b", "c"]);
        assert_eq!(ok("./a//b/"), ["a", "b"]);
    }

    #[test]
    fn rejects_escapes() {
        for p in ["/etc/passwd", "..", "a/../../b", "a/..", "", "."] {
            assert!(LexPath::parse(p).is_err(), "{p} should be rejected");
        }
    }

    #[test]
    fn rejects_nul_and_oversize() {
        assert!(LexPath::parse("a\0b").is_err());
        assert!(LexPath::parse(&"x".repeat(256)).is_err());
        let deep = (0..300).map(|i| format!("d{i}")).collect::<Vec<_>>().join("/");
        assert!(LexPath::parse(&deep).is_err());
    }

    #[test]
    fn split_leaf_works() {
        let p = LexPath::parse("a/b/c").unwrap();
        let (dirs, leaf) = p.split_leaf();
        assert_eq!(dirs.len(), 2);
        assert_eq!(leaf.as_bytes(), b"c");
    }
}
