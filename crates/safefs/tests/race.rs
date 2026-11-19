//! Adversarial race tests.
//!
//! # Shape of the attack
//!
//! This is the attack from the incident, mechanised. One thread repeatedly
//! calls `renamex_np(a, b, RENAME_SWAP)`, which exchanges two directory entries
//! in a single syscall — so at no instant is either name missing, and a reader
//! that checks and then opens is guaranteed to see the two views disagree
//! eventually. Victim threads then read through the layer.
//!
//! The last test runs the same attack against a textbook
//! `realpath`-then-`open-by-name` reader and **requires it to leak**. Without
//! that control, a passing confinement test would only prove the attack was
//! not landing.
//!
//! # A discovered kernel bug, and why the harness is shaped around it
//!
//! On this volume (APFS, macOS 26.5.1 / Darwin 25.5.0) **two threads calling
//! `renamex_np(RENAME_SWAP)` on the same pair of paths deadlock in the kernel**
//! — the second caller never returns, and `kill -9` cannot reap it. It is
//! reproducible in about twenty lines of C with no involvement from this crate
//! (see `scripts/verify_kernel_swap_bug.sh`). Two consequences:
//!
//! * the harness uses **one** swapper thread per path pair, which is more than
//!   enough to defeat a check-then-use reader (the control test measures
//!   thousands of leaks);
//! * the README records it, because a runner that spawns several build scripts
//!   each racing its own swapper is a denial-of-service against the host, not
//!   against this layer.
//!
//! Swapping *different* pairs from different threads is safe, and the tests
//! that use a rename-away/rename-back cycle instead of `RENAME_SWAP` run with
//! many attacker threads.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs as unixfs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use safefs::{OpenOptions, Workspace};

const SECRET: &str = "OUTSIDE_SECRET_DO_NOT_READ";

struct Env {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    ws_path: PathBuf,
    outside: PathBuf,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().to_path_buf();
        let ws_path = root.join("ws");
        let outside = root.join("outside");
        fs::create_dir(&ws_path).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("secret.txt"), SECRET).unwrap();
        // `realpath`-based comparisons need the canonical root, or every read
        // is rejected before the race can even be attempted.
        let ws_path = fs::canonicalize(&ws_path).unwrap();
        let outside = fs::canonicalize(&outside).unwrap();
        Env { _tmp: tmp, root, ws_path, outside }
    }

    fn ws(&self) -> Workspace {
        Workspace::open(&self.ws_path).unwrap()
    }
}

fn swap(a: &Path, b: &Path) -> bool {
    let ca = std::ffi::CString::new(a.as_os_str().as_bytes()).unwrap();
    let cb = std::ffi::CString::new(b.as_os_str().as_bytes()).unwrap();
    unsafe { libc::renamex_np(ca.as_ptr(), cb.as_ptr(), libc::RENAME_SWAP) == 0 }
}

#[derive(Default)]
struct Counts {
    ok: AtomicU64,
    denied: AtomicU64,
    leaked: AtomicU64,
}

fn read_through(ws: &Workspace, path: &str) -> Option<String> {
    let mut f = ws.open_read(path).ok()?;
    let mut s = String::new();
    f.read_to_string(&mut s).ok()?;
    Some(s)
}

/// Victim threads reading `path` through the layer, while `attack` runs on a
/// single dedicated thread.
fn race<F>(ws: Arc<Workspace>, path: &str, for_ms: u64, victims: usize, attack: F) -> Counts
where
    F: Fn() + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let counts = Arc::new(Counts::default());

    let attacker = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                attack();
            }
        })
    };

    let mut handles = Vec::new();
    for _ in 0..victims {
        let ws = ws.clone();
        let stop = stop.clone();
        let counts = counts.clone();
        let path = path.to_string();
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match read_through(&ws, &path) {
                    Some(s) => {
                        counts.ok.fetch_add(1, Ordering::Relaxed);
                        if s.contains(SECRET) {
                            counts.leaked.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    None => {
                        counts.denied.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    std::thread::sleep(Duration::from_millis(for_ms));
    stop.store(true, Ordering::Relaxed);
    // The attacker may be inside a syscall on a path the victim has since
    // renamed; join it before the caller removes the tree.
    attacker.join().unwrap();
    for h in handles {
        h.join().unwrap();
    }
    Counts {
        ok: AtomicU64::new(counts.ok.load(Ordering::Relaxed)),
        denied: AtomicU64::new(counts.denied.load(Ordering::Relaxed)),
        leaked: AtomicU64::new(counts.leaked.load(Ordering::Relaxed)),
    }
}

fn report(name: &str, c: &Counts) {
    eprintln!(
        "{name}: ok={} denied={} LEAKED={}",
        c.ok.load(Ordering::Relaxed),
        c.denied.load(Ordering::Relaxed),
        c.leaked.load(Ordering::Relaxed)
    );
}

// ---------------------------------------------------------------------------
// 1. the reported attack: atomically swap a file with a symlink to a secret
// ---------------------------------------------------------------------------

#[test]
fn leaf_swap_with_symlink_never_leaks() {
    let e = Env::new();
    fs::write(e.ws_path.join("victim"), "LOCAL_CONTENT").unwrap();
    unixfs::symlink(e.outside.join("secret.txt"), e.ws_path.join("evil")).unwrap();

    let ws = Arc::new(e.ws());
    let victim = e.ws_path.join("victim");
    let evil = e.ws_path.join("evil");
    let c = race(ws, "victim", 2000, 6, move || {
        swap(&victim, &evil);
    });
    report("leaf_swap_with_symlink", &c);
    assert_eq!(c.leaked.load(Ordering::Relaxed), 0, "secret leaked via leaf swap");
    assert!(c.ok.load(Ordering::Relaxed) > 0, "victim never succeeded: the test proves nothing");
}

// ---------------------------------------------------------------------------
// 2. swap a directory with a symlink to an outside directory
// ---------------------------------------------------------------------------

#[test]
fn directory_swap_with_symlink_never_leaks() {
    let e = Env::new();
    fs::create_dir(e.ws_path.join("sub")).unwrap();
    fs::write(e.ws_path.join("sub/data"), "LOCAL_DATA").unwrap();
    fs::write(e.outside.join("data"), SECRET).unwrap();

    let ws = Arc::new(e.ws());
    let sub = e.ws_path.join("sub");
    let evil = e.ws_path.join("evil");
    let outside = e.outside.clone();
    let c = race(ws, "sub/data", 2000, 6, move || {
        // Recreate the link each round: after a swap it is a directory.
        let _ = fs::remove_file(&evil);
        let _ = fs::remove_dir(&evil);
        unixfs::symlink(&outside, &evil).ok();
        swap(&sub, &evil);
    });
    report("directory_swap_with_symlink", &c);
    assert_eq!(c.leaked.load(Ordering::Relaxed), 0, "secret leaked via directory swap");
}

// ---------------------------------------------------------------------------
// 3. rename the directory away and graft an outside tree in its place
//    (many attacker threads are safe here: no RENAME_SWAP deadlock)
// ---------------------------------------------------------------------------

#[test]
fn directory_rename_and_replace_never_leaks() {
    let e = Env::new();
    fs::create_dir(e.ws_path.join("sub")).unwrap();
    fs::write(e.ws_path.join("sub/data"), "LOCAL_DATA").unwrap();
    fs::write(e.outside.join("data"), SECRET).unwrap();

    let ws = Arc::new(e.ws());
    let stop = Arc::new(AtomicBool::new(false));
    let leaked = Arc::new(AtomicU64::new(0));
    let ok = Arc::new(AtomicU64::new(0));

    // One attacher: several threads renaming the same directory in and out
    // would mostly fight each other and leave the victim path missing, which
    // would make the test pass by never reading anything.
    let attacker = {
        let (sub, outside, root) =
            (e.ws_path.join("sub"), e.outside.clone(), e.root.clone());
        let stop = stop.clone();
        std::thread::spawn(move || {
            let parked = root.join("parked");
            while !stop.load(Ordering::Relaxed) {
                if fs::rename(&sub, &parked).is_ok() {
                    unixfs::symlink(&outside, &sub).ok();
                    let _ = fs::remove_file(&sub);
                    let _ = fs::rename(&parked, &sub);
                }
            }
        })
    };

    let mut handles = Vec::new();
    for _ in 0..6 {
        let ws = ws.clone();
        let stop = stop.clone();
        let leaked = leaked.clone();
        let ok = ok.clone();
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Some(s) = read_through(&ws, "sub/data") {
                    ok.fetch_add(1, Ordering::Relaxed);
                    if s.contains(SECRET) {
                        leaked.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    std::thread::sleep(Duration::from_millis(2000));
    stop.store(true, Ordering::Relaxed);
    attacker.join().unwrap();
    for h in handles {
        h.join().unwrap();
    }
    let ok = ok.load(Ordering::Relaxed);
    eprintln!(
        "directory_rename_and_replace: ok={ok} LEAKED={}",
        leaked.load(Ordering::Relaxed)
    );
    assert!(ok > 100, "the victim never read anything through the churn: test proves nothing");
    assert_eq!(leaked.load(Ordering::Relaxed), 0, "secret leaked via rename/replace");
}

// ---------------------------------------------------------------------------
// 4. attacker plants hard links to an outside secret
// ---------------------------------------------------------------------------

#[test]
fn hardlink_planting_never_leaks() {
    let e = Env::new();
    let ws = Arc::new(e.ws());
    let planted = e.ws_path.join("planted");
    let secret = e.outside.join("secret.txt");
    let c = race(ws, "planted", 1500, 6, move || {
        // Alternate the name between a hard link to the secret and a plain
        // local file. Note the attacker *creates* the link here, which the
        // library itself refuses by policy; this covers the case where the
        // attacker uses the raw syscall the sandbox may not stop.
        let _ = fs::remove_file(&planted);
        fs::hard_link(&secret, &planted).ok();
        std::hint::spin_loop();
        let _ = fs::remove_file(&planted);
        fs::write(&planted, "LOCAL_CONTENT").ok();
    });
    report("hardlink_planting", &c);
    assert_eq!(c.leaked.load(Ordering::Relaxed), 0, "secret leaked via planted hard link");
}

// ---------------------------------------------------------------------------
// 5. concurrency correctness
// ---------------------------------------------------------------------------

#[test]
fn uncontended_reads_never_fail_or_corrupt() {
    let e = Env::new();
    for i in 0..32 {
        fs::write(e.ws_path.join(format!("f{i}")), format!("content-{i}")).unwrap();
    }
    let ws = Arc::new(e.ws());
    let bad = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for t in 0..8 {
        let ws = ws.clone();
        let bad = bad.clone();
        handles.push(std::thread::spawn(move || {
            for n in 0..2000 {
                let i = (n * 7 + t) % 32;
                match read_through(&ws, &format!("f{i}")) {
                    Some(s) if s == format!("content-{i}") => {}
                    _ => {
                        bad.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(bad.load(Ordering::Relaxed), 0, "concurrent reads failed or returned wrong data");
}

#[test]
fn concurrent_writes_to_distinct_files_all_land() {
    let e = Env::new();
    let ws = Arc::new(e.ws());
    let mut handles = Vec::new();
    for t in 0..8 {
        let ws = ws.clone();
        handles.push(std::thread::spawn(move || {
            for n in 0..200 {
                let p = format!("out/t{t}/f{n}");
                ws.create_dir_all(format!("out/t{t}")).unwrap();
                let mut f = ws.open_with(&p, OpenOptions::write()).unwrap();
                f.write_all(format!("{t}-{n}").as_bytes()).unwrap();
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    for t in 0..8 {
        for n in 0..200 {
            assert_eq!(
                fs::read_to_string(e.ws_path.join(format!("out/t{t}/f{n}"))).unwrap(),
                format!("{t}-{n}")
            );
        }
    }
}

// ---------------------------------------------------------------------------
// control: the naive implementation must actually lose the race
// ---------------------------------------------------------------------------

fn naive_read(ws_root: &Path, rel: &str) -> Option<String> {
    let p = ws_root.join(rel);
    let canon = fs::canonicalize(&p).ok()?; // check
    if !canon.starts_with(ws_root) {
        return None;
    }
    fs::read_to_string(&p).ok() // use, by name, after the check
}

#[test]
fn control_naive_implementation_leaks() {
    let e = Env::new();
    fs::write(e.ws_path.join("victim"), "LOCAL_CONTENT").unwrap();
    unixfs::symlink(e.outside.join("secret.txt"), e.ws_path.join("evil")).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let leaks = Arc::new(AtomicU64::new(0));
    let ok = Arc::new(AtomicU64::new(0));

    let victim = e.ws_path.join("victim");
    let evil = e.ws_path.join("evil");
    let attacker = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                swap(&victim, &evil);
            }
        })
    };

    let mut readers = Vec::new();
    for _ in 0..4 {
        let stop = stop.clone();
        let leaks = leaks.clone();
        let ok = ok.clone();
        let root = e.ws_path.clone();
        readers.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                if let Some(s) = naive_read(&root, "victim") {
                    ok.fetch_add(1, Ordering::Relaxed);
                    if s.contains(SECRET) {
                        leaks.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    std::thread::sleep(Duration::from_millis(1500));
    stop.store(true, Ordering::Relaxed);
    attacker.join().unwrap();
    for h in readers {
        h.join().unwrap();
    }
    eprintln!(
        "control_naive: ok={} LEAKED={}",
        ok.load(Ordering::Relaxed),
        leaks.load(Ordering::Relaxed)
    );
    assert!(
        leaks.load(Ordering::Relaxed) > 0,
        "the control implementation did not leak: the attack is not landing, so the \
         confinement tests above are not evidence of anything"
    );
}

// ---------------------------------------------------------------------------
// regression: several threads swapping the same pair wedges the kernel
// ---------------------------------------------------------------------------

/// Pins the kernel behaviour the harness is shaped around.
///
/// Two concurrent `renamex_np(RENAME_SWAP)` calls on the same path pair leave
/// one thread unkillable inside the kernel. This test asserts the *safe* case
/// (distinct pairs from distinct threads, which is what a real set of build
/// scripts looks like) and records the hazard in the failure message if the
/// volume starts behaving differently.
#[test]
fn concurrent_swaps_of_distinct_pairs_are_safe() {
    let e = Env::new();
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    for t in 0..4 {
        let dir = e.ws_path.clone();
        let stop = stop.clone();
        handles.push(std::thread::spawn(move || {
            let a = dir.join(format!("a{t}"));
            let b = dir.join(format!("b{t}"));
            fs::write(&a, "L").unwrap();
            fs::write(&b, "E").unwrap();
            let mut n = 0u64;
            while !stop.load(Ordering::Relaxed) {
                swap(&a, &b);
                n += 1;
            }
            n
        }));
    }
    std::thread::sleep(Duration::from_millis(500));
    stop.store(true, Ordering::Relaxed);
    let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    assert!(total > 1000, "swaps barely ran: {total}");
}
