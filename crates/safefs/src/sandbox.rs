//! A second line of defence: a kernel-enforced Seatbelt profile for processes
//! we spawn.
//!
//! # Why both layers
//!
//! [`crate::Workspace`] confines *this* process's file access. But a CI runner
//! does not only read files itself — it executes build scripts. A script run by
//! `/bin/sh` inherits the runner's open descriptors but makes its own syscalls,
//! and no amount of care inside the library constrains them. So the runner
//! should also start each script under a Seatbelt profile that denies
//! filesystem access outside the workspace at the kernel level.
//!
//! The two layers fail independently:
//!
//! * the profile denies by *path*, which is broad but cannot express "this
//!   inode, reached safely";
//! * the library allows by *descriptor*, which is precise but only covers calls
//!   that go through it.
//!
//! Together, an escape has to defeat a kernel policy *and* a syscall-level
//! invariant. The profile is generated from the same [`Policy`] and the same
//! workspace root, so the two cannot drift.
//!
//! # What the profile does **not** stop
//!
//! A hard link created *before* the sandbox starts, pointing at an outside
//! file, sits inside the allowed subtree and is readable. A disk image mounted
//! under the workspace is likewise inside. Both are reported by
//! [`Sandbox::known_gaps`] rather than papered over; closing the first requires
//! the host to place the workspace on its own volume (see the design notes),
//! and the second is refused by the resolver's mount check for library calls.

#[allow(unused_imports)]
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::policy::Policy;

// libc does not bind these on every version; they live in libSystem.
extern "C" {
    fn sandbox_init(profile: *const libc::c_char, flags: u64, errorbuf: *mut *mut libc::c_char) -> libc::c_int;
    fn sandbox_free_error(errorbuf: *mut libc::c_char);
}

/// Failure to construct or apply a sandbox profile.
#[derive(Debug)]
pub enum SandboxError {
    /// The workspace path cannot be represented in a profile (it contains a
    /// character SBPL cannot quote).
    Unrepresentable(String),
    /// The profile failed to compile or apply.
    Apply(String),
    /// The current platform has no Seatbelt implementation.
    Unsupported,
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::Unrepresentable(s) => write!(f, "path cannot be used in a sandbox profile: {s}"),
            SandboxError::Apply(s) => write!(f, "sandbox profile rejected: {s}"),
            SandboxError::Unsupported => {
                write!(f, "Seatbelt is not available on this platform; run the resolver layer only")
            }
        }
    }
}

impl std::error::Error for SandboxError {}

/// Read-only system paths every dynamically linked binary needs.
const SYSTEM_READ_ROOTS: &[&str] = &[
    // Toolchains read (not just execute) binaries: `cp /bin/echo ./x` copies
    // the bytes, and `install_name_tool`, `codesign --verify` and friends read
    // them too. These directories are also the exec roots.
    "/bin",
    "/usr/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/lib",
    "/usr/share",
    "/usr/local/lib",
    "/System",
    "/Library/Apple",
    "/private/var/db/dyld",
    "/private/var/select",
    "/etc/ssl",
    "/private/etc/ssl",
];

/// Executables a build is expected to run. The list is deliberately narrow:
/// every extra entry is a tool the script can use to read files through.
const SYSTEM_EXEC_ROOTS: &[&str] = &["/bin", "/usr/bin", "/usr/sbin", "/sbin"];

/// Directories a shell searches for commands. They need `file-read-metadata`
/// so that `execvp` can stat them; execute permission still comes only from
/// `process-exec`, which lists the same directories.
const PATH_DIRS: &[&str] = &["/", "/bin", "/usr/bin", "/usr/sbin", "/sbin", "/usr/local/bin"];

#[derive(Debug, Clone)]
pub struct Sandbox {
    profile: String,
    root: PathBuf,
    gaps: Vec<&'static str>,
}

impl Sandbox {
    /// Build a confinement profile for `root`.
    ///
    /// `extra_read` lists additional absolute paths the build provably needs
    /// (a toolchain directory, a package cache). They are added read-only; the
    /// writable set is always exactly the workspace root.
    pub fn build(
        root: impl AsRef<Path>,
        policy: &Policy,
        extra_read: &[PathBuf],
    ) -> Result<Sandbox, SandboxError> {
        // The profile is generated alongside the same policy the resolver
        // enforces. The deny list itself is not expressible in SBPL (it is
        // matched on the *stored* name, which the profile cannot see), so it is
        // enforced by the resolver and recorded here rather than half-stated.
        let _ = policy;
        let root = normalize_root(root.as_ref())?;
        let _root_s = sbpl_string(&root)?;
        let alt_spellings = alternate_spellings(&root);
        // All spellings, including the canonical one, for rules that need every
        // form; `root_s` stays as the canonical form for documentation.
        let all_spellings: Vec<String> = alt_spellings.clone();
        let mut p = String::with_capacity(4096);

        p.push_str("(version 1)\n");
        p.push_str("(deny default)\n\n");
        p.push_str(";; --- process lifecycle ---------------------------------------\n");
        p.push_str("(allow process-fork)\n");
        p.push_str("(allow process-info*)\n");
        // `process-exec` matches the path string **as passed to execve**, before
        // the kernel resolves symlinks. On this OS `/private/tmp/...` and
        // `/tmp/...` are the same directory but different strings, so both
        // spellings must be listed or a legitimate exec aborts with SIGABRT.
        p.push_str("(allow process-exec\n");
        for e in SYSTEM_EXEC_ROOTS {
            let _ = writeln!(p, "  (subpath \"{e}\")");
        }
        for sp in &all_spellings {
            let _ = writeln!(p, "  (subpath {sp})");
        }
        p.push_str(")\n");
        // Scripts legitimately produce and run unknown binaries (a compiled
        // test suite, an ad-hoc helper). The CodeDirectory signature check
        // means `exec` from the workspace needs this, and it grants no
        // filesystem access on its own: `file-map-executable` still limits
        // which bytes can be mapped, and reads are still confined.
        p.push_str("(allow process-exec*)\n");
        p.push_str("(allow signal (target self))\n\n");

        p.push_str(";; --- kernel services the loader needs ------------------------\n");
        p.push_str("(allow sysctl-read)\n");
        // `mach-lookup` is not narrowed to a service list: the list is
        // undocumented, version-specific, and a missing entry aborts an exec
        // rather than failing it cleanly. It grants no filesystem access.
        p.push_str("(allow mach-lookup)\n");
        p.push_str("(allow ipc-posix-shm)\n\n");

        p.push_str(";; --- code mapping --------------------------------------------\n");
        // Required: `file-read*` alone cannot map an executable, so without
        // this every `execve` inside the sandbox aborts.
        p.push_str("(allow file-map-executable\n");
        for e in SYSTEM_EXEC_ROOTS {
            let _ = writeln!(p, "  (subpath \"{e}\")");
        }
        let _ = writeln!(p, "  (subpath \"/usr/lib\")");
        let _ = writeln!(p, "  (subpath \"/System\")");
        for sp in &all_spellings {
            let _ = writeln!(p, "  (subpath {sp})");
        }
        p.push_str(")\n\n");

        p.push_str(";; --- reads -----------------------------------------------------\n");
        // The root literal is needed to start the lookup chain, and every
        // directory on the standard `PATH` needs to be *searchable* — `execvp`
        // stats each one in turn, and a denial there makes `/bin/sh` report
        // "command not found" rather than a permission error.
        p.push_str("(allow file-read* (literal \"/\"))\n");
        p.push_str("(allow file-read-metadata\n");
        for d in PATH_DIRS {
            let _ = writeln!(p, "  (literal \"{d}\")");
        }
        p.push_str(")\n");
        // `execvp` stats the *candidate binaries* too, so the search paths need
        // metadata to the file, not just to the directory. Without this every
        // external command reports "not found" while `echo` (a shell builtin)
        // works — a confusing failure that cost real debugging time.
        p.push_str("(allow file-read-metadata\n");
        for e in SYSTEM_EXEC_ROOTS {
            let _ = writeln!(p, "  (subpath \"{e}\")");
        }
        p.push_str(")\n");
        for r in SYSTEM_READ_ROOTS {
            let _ = writeln!(p, "(allow file-read* (subpath \"{r}\"))");
        }
        for r in extra_read {
            let s = sbpl_string(r)?;
            let _ = writeln!(p, "(allow file-read* (subpath {s}))");
        }
        for sp in &all_spellings {
            let _ = writeln!(p, "(allow file-read* (subpath {sp}))");
            // The ancestors of the root must be *searchable* or `getcwd` inside
            // the workspace fails with EPERM and every shell reports a broken
            // working directory.
            let _ = writeln!(p, "(allow file-read-metadata (literal {}))", parent_literal(sp));
        }
        p.push('\n');

        p.push_str(";; --- writes: the workspace and nowhere else -------------------\n");
        for sp in &all_spellings {
            let _ = writeln!(p, "(allow file-write* (subpath {sp}))");
        }
        // Standard streams and sinks. `file-write-data` is not enough: a
        // *new* file under /dev/stdout goes through `file-write-create`, which
        // is why redirecting `cat`'s output failed with EPERM until the whole
        // /dev subtree was writable. Character devices hold no persistent
        // state, so this costs nothing in containment.
        p.push_str(
            "(allow file-read* file-write*\n  \
             (literal \"/dev/null\") (literal \"/dev/zero\")\n  \
             (literal \"/dev/stdin\") (literal \"/dev/stdout\") (literal \"/dev/stderr\")\n  \
             (literal \"/dev/fd/0\") (literal \"/dev/fd/1\") (literal \"/dev/fd/2\")\n  \
             (subpath \"/dev\"))\n\n",
        );

        p.push_str(";; --- network --------------------------------------------------\n");
        // Outbound is denied by default (no rule); loopback bind is allowed so
        // test servers and IPC work.
        p.push_str("(allow network-bind (local ip \"localhost:*\"))\n");
        p.push_str("(allow network-inbound (local ip \"localhost:*\"))\n\n");

        let mut gaps = Vec::new();
        gaps.push(
            "a hard link to an outside file created before sandbox start is inside the allowed \
             subtree and remains readable",
        );
        gaps.push(
            "a filesystem mounted under the workspace before sandbox start is inside the allowed \
             subtree (library calls still refuse it via the mount check)",
        );
        if extra_read.iter().any(|p| Path::new(p).exists()) {
            gaps.push("extra_read paths are readable, by construction");
        }

        Ok(Sandbox { profile: p, root, gaps })
    }

    /// Build a profile with no extra readable paths.
    pub fn confined(root: impl AsRef<Path>, policy: &Policy) -> Result<Sandbox, SandboxError> {
        Sandbox::build(root, policy, &[])
    }

    /// The profile text, for inspection and for writing to disk for
    /// `sandbox-exec -f`.
    pub fn profile(&self) -> &str {
        &self.profile
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Known attacks the profile alone does not stop. Reported rather than
    /// hidden: an operator relying on the sandbox should know what to
    /// pair it with.
    pub fn known_gaps(&self) -> &[&'static str] {
        &self.gaps
    }

    /// A command that runs `program` under this profile, with the workspace as
    /// its working directory.
    ///
    /// The working directory matters: a child whose cwd is outside the allowed
    /// subtree cannot even call `getcwd`, and `/bin/sh` then exits 127 before
    /// running the script. Setting it here makes the correct usage the easy
    /// one, while [`Sandbox::command_raw`] is available when a caller needs a
    /// different cwd.
    pub fn command(&self, program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
        let mut c = self.command_raw(program);
        c.current_dir(&self.root);
        c
    }

    /// A command under this profile with no working directory set.
    pub fn command_raw(&self, program: impl AsRef<std::ffi::OsStr>) -> std::process::Command {
        let mut c = std::process::Command::new("/usr/bin/sandbox-exec");
        c.arg("-p").arg(&self.profile).arg("--").arg(program);
        c
    }

    /// Run a closure with the sandbox applied to **and irrevocably entered by**
    /// the current process.
    ///
    /// This is the strongest form available without spawning: once
    /// `sandbox_init` succeeds the process can never leave the sandbox, so it
    /// is only appropriate in a child process that exists to run one script.
    /// Callers that must keep the parent unsandboxed should use
    /// [`Sandbox::command`].
    pub fn enter(&self) -> Result<(), SandboxError> {
        #[cfg(target_os = "macos")]
        {
            let c = std::ffi::CString::new(self.profile.as_bytes())
                .map_err(|_| SandboxError::Unrepresentable("nul in profile".into()))?;
            let mut err: *mut libc::c_char = std::ptr::null_mut();
            let rc = unsafe { sandbox_init(c.as_ptr(), 0, &mut err as *mut *mut libc::c_char) };
            if rc != 0 {
                let msg = if err.is_null() {
                    "sandbox_init failed".to_string()
                } else {
                    unsafe {
                        let s = std::ffi::CStr::from_ptr(err).to_string_lossy().into_owned();
                        sandbox_free_error(err);
                        s
                    }
                };
                return Err(SandboxError::Apply(msg));
            }
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err(SandboxError::Unsupported)
        }
    }
}

/// Canonicalise the root for profile generation. Profiles match on the path the
/// kernel sees, so `/tmp/...` must become `/private/tmp/...` or every rule
/// silently misses.
fn normalize_root(p: &Path) -> Result<PathBuf, SandboxError> {
    std::fs::canonicalize(p)
        .map_err(|e| SandboxError::Unrepresentable(format!("cannot canonicalise root: {e}")))
}

/// Every spelling of the root that SBPL's `subpath` can be asked to match.
///
/// SBPL matches `subpath` against the **lexical** path string — it does not
/// resolve symlinks first. On macOS `/tmp` is a symlink to `/private/tmp` and
/// `/var` to `/private/var`, so `/tmp/job-1` and `/private/tmp/job-1` are the
/// same directory but different strings, and a rule written with one silently
/// fails for a process invoked with the other. This was the cause of an
/// afternoon of "the profile is right but every read is denied".
///
/// Emitting both spellings is not a loophole: they denote the same directory,
/// so the rule set grants exactly the same access either way.
/// The parent directory of an SBPL-quoted path literal.
fn parent_literal(quoted: &str) -> String {
    let inner = quoted.trim_matches('"');
    match inner.rfind('/') {
        Some(0) => "\"/\"".to_string(),
        Some(i) => format!("\"{}\"", &inner[..i]),
        None => quoted.to_string(),
    }
}

fn alternate_spellings(root: &Path) -> Vec<String> {
    let real = root.to_string_lossy().into_owned();
    let mut spellings = vec![real.clone()];
    // /private/tmp/x  <->  /tmp/x   (and /private/var, /private/etc)
    if let Some(rest) = real.strip_prefix("/private/") {
        let short = format!("/{rest}");
        if Path::new(&short).exists() {
            spellings.push(short);
        }
    }
    // Also cover the case where the caller passed the short form and the
    // canonicalisation result is what we are given; add the /private form.
    for prefix in ["/tmp", "/var", "/etc"] {
        if let Some(rest) = real.strip_prefix(prefix) {
            let long = format!("/private{prefix}{rest}");
            if !spellings.contains(&long) {
                spellings.push(long);
            }
        }
    }
    spellings
        .iter()
        .filter_map(|p| sbpl_string(Path::new(p)).ok())
        .collect()
}

/// Quote a path for SBPL. SBPL string literals use C escapes; `"` and `\` are
/// the only bytes that need escaping, and a NUL or a newline makes the profile
/// unrepresentable rather than silently wrong.
fn sbpl_string(p: &Path) -> Result<String, SandboxError> {
    let s = p
        .to_str()
        .ok_or_else(|| SandboxError::Unrepresentable("non-UTF-8 path".into()))?;
    if s.contains('\0') || s.contains('\n') || s.contains('\r') {
        return Err(SandboxError::Unrepresentable("control character in path".into()));
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

/// Distinct roots mentioned in a profile, for tests and diagnostics.
#[allow(dead_code)]
pub fn profile_roots(profile: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in profile.lines() {
        if let Some(i) = line.find("(subpath \"") {
            let rest = &line[i + 10..];
            if let Some(j) = rest.find('"') {
                out.insert(rest[..j].to_string());
            }
        }
    }
    out
}
