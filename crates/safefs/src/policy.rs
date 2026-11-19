//! Policy: what is allowed, independent of how it is enforced.
//!
//! The resolver only ever asks the policy yes/no questions about objects it has
//! *already proven* are inside the workspace by descriptor, never about
//! caller-supplied strings. That keeps the number of decisions an attacker can
//! influence small and auditable.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

/// Control directories whose contents make the *runner* execute code later.
/// A checked-in `.git/hooks/pre-commit`, or a `.hg/hgrc` with a hooks section,
/// turns a build step into code execution on the runner.
const DEFAULT_DENY_NAMES: &[&str] = &[".git", ".hg", ".svn"];

#[derive(Debug, Clone)]
pub struct Policy {
    /// Follow a symlink whose target resolves inside the workspace.
    pub follow_symlinks: bool,
    /// Permit `readlink`, which reveals a link's target text.
    pub allow_symlink_read: bool,
    /// Permit `link()` between two workspace paths. Refusing it removes the
    /// ability to give an outside inode a second, workspace-relative name,
    /// which is the one containment fact a descriptor walk cannot re-derive.
    pub allow_hardlink: bool,
    /// Trust an inode with more than one name. Off by default: a file whose
    /// link count exceeds one may have its other name outside the workspace,
    /// and there is no path-based way to tell. Links this `Workspace` creates
    /// are registered in-process and are exempt regardless of this flag.
    pub trust_multiply_linked: bool,
    /// Refuse the open when the volume stores a different spelling than the
    /// caller used. Off by default (case-insensitive volumes are common and
    /// tools legitimately rely on folding); on for strict deployments.
    pub strict_names: bool,
    pub allow_device_nodes: bool,
    pub allow_fifo: bool,
    pub allow_socket: bool,
    pub max_file_size: Option<u64>,
    deny_names: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            follow_symlinks: true,
            allow_symlink_read: true,
            allow_hardlink: false,
            trust_multiply_linked: false,
            strict_names: false,
            allow_device_nodes: false,
            allow_fifo: true,
            allow_socket: true,
            max_file_size: None,
            deny_names: DEFAULT_DENY_NAMES.iter().map(|s| s.to_string()).collect(),
        }
    }
}

impl Policy {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn follow_symlinks(mut self, v: bool) -> Self {
        self.follow_symlinks = v;
        self
    }

    pub fn allow_symlink_read(mut self, v: bool) -> Self {
        self.allow_symlink_read = v;
        self
    }

    pub fn allow_hardlink(mut self, v: bool) -> Self {
        self.allow_hardlink = v;
        self
    }

    pub fn trust_multiply_linked(mut self, v: bool) -> Self {
        self.trust_multiply_linked = v;
        self
    }

    pub fn strict_names(mut self, v: bool) -> Self {
        self.strict_names = v;
        self
    }

    pub fn allow_special_files(mut self, devices: bool, fifos: bool, sockets: bool) -> Self {
        self.allow_device_nodes = devices;
        self.allow_fifo = fifos;
        self.allow_socket = sockets;
        self
    }

    pub fn max_file_size(mut self, n: u64) -> Self {
        self.max_file_size = Some(n);
        self
    }

    pub fn deny_name(mut self, name: impl Into<String>) -> Self {
        self.deny_names.push(name.into());
        self
    }

    pub fn allow_name(mut self, name: &str) -> Self {
        self.deny_names.retain(|n| n != name);
        self
    }

    /// Does any policy decision need the volume's stored spelling even on a
    /// case-sensitive volume? Only custom deny entries can, and only because a
    /// normalising volume can still fold them.
    pub fn needs_stored_names(&self) -> bool {
        !self.deny_names.is_empty()
    }

    pub fn deny_list(&self) -> &[String] {
        &self.deny_names
    }

    /// Does the deny list cover this *stored* name?
    ///
    /// `case_insensitive` must come from the volume, not the caller, so a
    /// script cannot dodge a deny-list entry by changing its case.
    pub fn denies(&self, _depth: usize, stored: &OsStr, case_insensitive: bool) -> bool {
        let b = stored.as_bytes();
        self.deny_names.iter().any(|pat| {
            let p = pat.as_bytes();
            if case_insensitive {
                b.eq_ignore_ascii_case(p)
            } else {
                b == p
            }
        })
    }

    /// Is a POSIX file type permitted at all?
    pub fn permits_type(&self, ft: u32) -> bool {
        match ft as u16 {
            libc::S_IFREG | libc::S_IFDIR | libc::S_IFLNK => true,
            libc::S_IFIFO => self.allow_fifo,
            libc::S_IFSOCK => self.allow_socket,
            libc::S_IFCHR | libc::S_IFBLK => self.allow_device_nodes,
            _ => false,
        }
    }
}
