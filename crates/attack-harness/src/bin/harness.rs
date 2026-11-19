//! `harness` — a reusable adversarial test driver.
//!
//! The library's own test suite covers the attack classes deterministically.
//! This binary exists so an operator can point the same attacks at a *deployed*
//! build, on the host that will actually run it, and get a verdict rather than
//! a pass/fail from a developer's machine:
//!
//! ```text
//! harness self-test                      # run every scenario in a temp workspace
//! harness attack --workspace /srv/ws-42  # attack a specific workspace, report only
//! harness verify-isolation --workspace … # is the strongest guarantee available here?
//! ```
//!
//! Exit status is 0 when no scenario leaked. A leak prints the scenario, the
//! number of successful reads and the number that returned outside data.

use std::fs;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs as unixfs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use safefs::{Isolation, OpenOptions, Policy, Workspace};

const SECRET: &str = "SAFEFS_OUTSIDE_SECRET";

struct Args {
    command: String,
    workspace: Option<PathBuf>,
    seconds: u64,
}

fn parse_args() -> Args {
    let mut command = "self-test".to_string();
    let mut workspace = None;
    let mut seconds = 3;
    let mut it = std::env::args().skip(1);
    if let Some(c) = it.next() {
        command = c;
    }
    while let Some(a) = it.next() {
        match a.as_str() {
            "--workspace" | "-w" => workspace = it.next().map(PathBuf::from),
            "--seconds" | "-s" => seconds = it.next().and_then(|v| v.parse().ok()).unwrap_or(3),
            other => {
                eprintln!("unknown argument {other}");
                std::process::exit(2);
            }
        }
    }
    Args { command, workspace, seconds }
}

struct Outcome {
    name: &'static str,
    ok: u64,
    denied: u64,
    leaked: u64,
}

impl Outcome {
    fn passed(&self) -> bool {
        self.leaked == 0 && self.ok > 0
    }
    fn line(&self) -> String {
        format!(
            "{:<34} {:>8} ok  {:>8} denied  {:>6} LEAKED   {}",
            self.name,
            self.ok,
            self.denied,
            self.leaked,
            if self.passed() { "PASS" } else { "FAIL" }
        )
    }
}

fn swap(a: &Path, b: &Path) -> bool {
    let ca = std::ffi::CString::new(a.as_os_str().as_bytes()).unwrap();
    let cb = std::ffi::CString::new(b.as_os_str().as_bytes()).unwrap();
    unsafe { libc::renamex_np(ca.as_ptr(), cb.as_ptr(), libc::RENAME_SWAP) == 0 }
}

/// Drive `path` from several reader threads while `attack` runs on one thread.
fn drive(
    name: &'static str,
    ws: Arc<Workspace>,
    path: &str,
    secs: u64,
    readers: usize,
    attack: impl Fn() + Send + 'static,
) -> Outcome {
    let stop = Arc::new(AtomicBool::new(false));
    let ok = Arc::new(AtomicU64::new(0));
    let denied = Arc::new(AtomicU64::new(0));
    let leaked = Arc::new(AtomicU64::new(0));

    let attacker = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                attack();
            }
        })
    };

    let mut threads = Vec::new();
    for _ in 0..readers {
        let ws = ws.clone();
        let (stop, ok, denied, leaked) = (stop.clone(), ok.clone(), denied.clone(), leaked.clone());
        let p = path.to_string();
        threads.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                match ws.open_read(&p) {
                    Ok(mut f) => {
                        let mut s = String::new();
                        if f.read_to_string(&mut s).is_ok() {
                            ok.fetch_add(1, Ordering::Relaxed);
                            if s.contains(SECRET) {
                                leaked.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(_) => {
                        denied.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }));
    }

    std::thread::sleep(Duration::from_secs(secs));
    stop.store(true, Ordering::Relaxed);
    attacker.join().unwrap();
    for t in threads {
        t.join().unwrap();
    }
    Outcome {
        name,
        ok: ok.load(Ordering::Relaxed),
        denied: denied.load(Ordering::Relaxed),
        leaked: leaked.load(Ordering::Relaxed),
    }
}

fn prepare(root: &Path) -> (PathBuf, PathBuf) {
    let ws = root.join("ws");
    let outside = root.join("outside");
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret"), SECRET).unwrap();
    (fs::canonicalize(&ws).unwrap(), fs::canonicalize(&outside).unwrap())
}

fn scenarios(ws_path: &Path, outside: &Path, secs: u64) -> Vec<Outcome> {
    let ws = Arc::new(Workspace::open(ws_path).unwrap());
    let mut out = Vec::new();

    // 1. symlink swapped over the leaf between resolution and use
    {
        fs::write(ws_path.join("victim"), "LOCAL").unwrap();
        let evil = ws_path.join("evil1");
        let _ = fs::remove_file(&evil);
        unixfs::symlink(outside.join("secret"), &evil).unwrap();
        let (a, b) = (ws_path.join("victim"), evil);
        out.push(drive("leaf-symlink-swap", ws.clone(), "victim", secs, 4, move || {
            swap(&a, &b);
        }));
    }

    // 2. directory swapped for a symlink
    {
        fs::create_dir_all(ws_path.join("sub2")).unwrap();
        fs::write(ws_path.join("sub2/data"), "LOCAL").unwrap();
        fs::write(outside.join("data"), SECRET).unwrap();
        let (sub, evil) = (ws_path.join("sub2"), ws_path.join("evil2"));
        let outside = outside.to_path_buf();
        out.push(drive("directory-symlink-swap", ws.clone(), "sub2/data", secs, 4, move || {
            let _ = fs::remove_file(&evil);
            unixfs::symlink(&outside, &evil).ok();
            swap(&sub, &evil);
        }));
    }

    // 3. rename-away/rename-back with an outside tree grafted in
    {
        fs::create_dir_all(ws_path.join("sub3")).unwrap();
        fs::write(ws_path.join("sub3/data"), "LOCAL").unwrap();
        let (sub, parked, outside) =
            (ws_path.join("sub3"), ws_path.join("parked3"), outside.to_path_buf());
        out.push(drive("rename-and-replace", ws.clone(), "sub3/data", secs, 4, move || {
            if fs::rename(&sub, &parked).is_ok() {
                unixfs::symlink(&outside, &sub).ok();
                let _ = fs::remove_file(&sub);
                let _ = fs::rename(&parked, &sub);
            }
        }));
    }

    // 4. planted hard links
    {
        let (planted, secret) = (ws_path.join("planted"), outside.join("secret"));
        out.push(drive("hardlink-planting", ws.clone(), "planted", secs, 4, move || {
            let _ = fs::remove_file(&planted);
            fs::hard_link(&secret, &planted).ok();
            std::hint::spin_loop();
            let _ = fs::remove_file(&planted);
            fs::write(&planted, "LOCAL").ok();
        }));
    }

    out
}

fn main() {
    let args = parse_args();
    match args.command.as_str() {
        "self-test" | "attack" => {
            let tmp;
            let (ws_path, outside) = match &args.workspace {
                Some(p) => {
                    let p = fs::canonicalize(p).expect("workspace must exist");
                    tmp = tempfile_like(&p);
                    tmp
                }
                None => {
                    let t = std::env::temp_dir().join(format!("safefs-harness-{}", std::process::id()));
                    fs::remove_dir_all(&t).ok();
                    let pair = prepare(&t);
                    let results = scenarios(&pair.0, &pair.1, args.seconds);
                    report(&results);
                    fs::remove_dir_all(&t).ok();
                    std::process::exit(if results.iter().all(|r| r.passed()) { 0 } else { 1 });
                }
            };
            let results = scenarios(&ws_path, &outside, args.seconds);
            report(&results);
            std::process::exit(if results.iter().all(|r| r.passed()) { 0 } else { 1 });
        }
        "verify-isolation" => {
            let p = args
                .workspace
                .expect("--workspace is required for verify-isolation");
            let (ws, iso) = Workspace::open_isolated(&p, Policy::default()).expect("open workspace");
            println!("workspace: {}", ws.root_path().display());
            println!("device:    {}", ws.device());
            match iso {
                Isolation::Confined => {
                    println!("isolation: CONFINED");
                    println!(
                        "  The workspace is the root of its own filesystem. Hard links cannot\n  \
                         cross a filesystem boundary (EXDEV), so no outside inode can have a\n  \
                         name inside the workspace at all."
                    );
                    std::process::exit(0);
                }
                Isolation::Shared { reason } => {
                    println!("isolation: SHARED");
                    println!("  {reason}");
                    println!(
                        "  Containment still holds for symlinks, mounts and rename races; the\n  \
                         hard-link window is narrowed but not structurally eliminated.\n  \
                         Put the workspace on its own volume (an APFS volume or a disk image)\n  \
                         to close it."
                    );
                    std::process::exit(1);
                }
            }
        }
        other => {
            eprintln!("unknown command {other}; try self-test, attack, verify-isolation");
            std::process::exit(2);
        }
    }
}

/// For `--workspace`, put the secret next to the workspace on the same host
/// filesystem (one level up), so the attack uses real outside data.
fn tempfile_like(ws: &Path) -> (PathBuf, PathBuf) {
    let parent = ws.parent().unwrap_or(ws);
    let outside = parent.join("safefs-harness-outside");
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret"), SECRET).unwrap();
    (ws.to_path_buf(), fs::canonicalize(&outside).unwrap())
}

fn report(results: &[Outcome]) {
    println!(
        "{:<34} {:>10} {:>13} {:>13}",
        "scenario", "reads", "denied", "verdict"
    );
    for r in results {
        println!("{}", r.line());
    }
    let bad = results.iter().filter(|r| !r.passed()).count();
    if bad == 0 {
        println!("\nall scenarios held: no outside data was readable");
    } else {
        println!("\n{bad} scenario(s) FAILED: outside data was readable");
    }
    let _ = OpenOptions::read();
    let _ = Instant::now();
}
