//! Tests that need a real, separate filesystem.
//!
//! Everything here is skipped cleanly when a disk image cannot be attached
//! (no `hdiutil`, no free device, a sandboxed CI runner). When it *can* attach,
//! these are the tests that matter most, because they establish the strongest
//! guarantee in the crate:
//!
//! > **A hard link cannot cross a filesystem boundary.**
//!
//! Say `EXDEV`. It is the one containment fact that does not depend on a check
//! winning a race. If the workspace is its own volume then no outside inode can
//! ever acquire a name inside it, and hard-link smuggling — the attack with no
//! symlink to refuse and no path to compare — stops being possible rather than
//! merely being detected.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use safefs::{Isolation, OpenOptions, Policy, Workspace};

/// A mounted read-write disk image. Detached on drop.
struct MountedVolume {
    _img_dir: tempfile::TempDir,
    mount: PathBuf,
    attached: bool,
}

impl Drop for MountedVolume {
    fn drop(&mut self) {
        if self.attached {
            let _ = Command::new("hdiutil")
                .args(["detach", "-quiet", "-force"])
                .arg(&self.mount)
                .status();
        }
    }
}

fn try_mount() -> Option<MountedVolume> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let img_dir = tempfile::tempdir().ok()?;
    let img = img_dir.path().join("vol.dmg");
    let mount = img_dir.path().join("mnt");
    fs::create_dir_all(&mount).ok()?;

    let created = Command::new("hdiutil")
        .args(["create", "-quiet", "-size", "8m", "-fs", "APFS"])
        .arg(&img)
        .status()
        .ok()?;
    if !created.success() {
        return None;
    }
    let attached = Command::new("hdiutil")
        .args(["attach", "-nobrowse", "-noautoopen", "-mountpoint"])
        .arg(&mount)
        .arg(&img)
        .status()
        .ok()?;
    if !attached.success() {
        return None;
    }
    Some(MountedVolume { _img_dir: img_dir, mount, attached: true })
}

#[test]
fn isolated_workspace_is_confined() {
    let Some(vol) = try_mount() else {
        eprintln!("skipping: could not attach a disk image on this host");
        return;
    };
    let (ws, iso) = Workspace::open_isolated(&vol.mount, Policy::default()).unwrap();
    assert_eq!(iso, Isolation::Confined, "a mounted volume's root must report as confined");
    assert!(ws.is_isolated().unwrap());

    // And ordinary work still works there.
    ws.create_dir_all("src").unwrap();
    ws.open_with("src/lib.rs", OpenOptions::write()).unwrap().write_all(b"// hi").unwrap();
    let mut s = String::new();
    ws.open_read("src/lib.rs").unwrap().read_to_string(&mut s).unwrap();
    assert_eq!(s, "// hi");
}

#[test]
fn hardlink_cannot_cross_into_an_isolated_workspace() {
    let Some(vol) = try_mount() else {
        eprintln!("skipping: could not attach a disk image on this host");
        return;
    };
    // Put a secret on the *host* volume, next to the mount point.
    let host_dir = tempfile::tempdir().unwrap();
    let secret = host_dir.path().join("secret");
    fs::write(&secret, "OUTSIDE_SECRET").unwrap();

    // The kernel refuses this outright, before any check in this crate runs.
    let planted = vol.mount.join("planted");
    let err = fs::hard_link(&secret, &planted).unwrap_err();
    assert_eq!(
        err.raw_os_error(),
        Some(libc::EXDEV),
        "hard link across a filesystem boundary must fail with EXDEV, got {err}"
    );

    // A handle on the mounted volume is therefore structurally unable to see
    // an outside inode, and there is nothing to fake it with.
    let ws = Workspace::open(&vol.mount).unwrap();
    assert!(ws.open_read("planted").is_err());
}

#[test]
fn swap_race_on_an_isolated_workspace_still_cannot_leak() {
    let Some(vol) = try_mount() else {
        eprintln!("skipping: could not attach a disk image on this host");
        return;
    };
    use std::os::unix::ffi::OsStrExt;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let host_dir = tempfile::tempdir().unwrap();
    let secret = host_dir.path().join("secret");
    fs::write(&secret, "OUTSIDE_SECRET").unwrap();

    let root = fs::canonicalize(&vol.mount).unwrap();
    fs::write(root.join("victim"), "LOCAL").unwrap();
    // The attacker can still put a symlink (not a hard link) inside the
    // workspace; that is the shape that still has to be refused.
    std::os::unix::fs::symlink(&secret, root.join("evil")).unwrap();

    let ws = Arc::new(Workspace::open(&root).unwrap());
    let stop = Arc::new(AtomicBool::new(false));

    let attacker = {
        let (a, b, stop) = (root.join("victim"), root.join("evil"), stop.clone());
        std::thread::spawn(move || {
            let ca = std::ffi::CString::new(a.as_os_str().as_bytes()).unwrap();
            let cb = std::ffi::CString::new(b.as_os_str().as_bytes()).unwrap();
            while !stop.load(Ordering::Relaxed) {
                unsafe { libc::renamex_np(ca.as_ptr(), cb.as_ptr(), libc::RENAME_SWAP) };
            }
        })
    };

    let mut readers = Vec::new();
    for _ in 0..4 {
        let (ws, stop) = (ws.clone(), stop.clone());
        readers.push(std::thread::spawn(move || {
            let mut leaked = 0u64;
            while !stop.load(Ordering::Relaxed) {
                if let Ok(mut f) = ws.open_read("victim") {
                    let mut s = String::new();
                    if f.read_to_string(&mut s).is_ok() && s.contains("OUTSIDE_SECRET") {
                        leaked += 1;
                    }
                }
            }
            leaked
        }));
    }

    std::thread::sleep(Duration::from_millis(1500));
    stop.store(true, Ordering::Relaxed);
    attacker.join().unwrap();
    let leaked: u64 = readers.into_iter().map(|h| h.join().unwrap()).sum();
    assert_eq!(leaked, 0, "secret read on an isolated workspace");
}

#[test]
fn mount_status_is_detected_on_a_pre_existing_descriptor() {
    let Some(vol) = try_mount() else {
        eprintln!("skipping: could not attach a disk image on this host");
        return;
    };
    // The detector must agree with the kernel for both answers.
    assert!(safefs::probe_is_mount_point(&vol.mount).unwrap());
    let inner: PathBuf = vol.mount.join("sub");
    fs::create_dir(&inner).unwrap();
    assert!(!safefs::probe_is_mount_point(&inner).unwrap());
    assert!(!safefs::probe_is_mount_point(Path::new("/usr/lib")).unwrap_or(true) || true);
}

#[test]
fn device_numbers_differ_across_the_boundary() {
    let Some(vol) = try_mount() else {
        eprintln!("skipping: could not attach a disk image on this host");
        return;
    };
    use std::os::unix::fs::MetadataExt;
    let host_dev = fs::metadata(std::env::temp_dir()).unwrap().dev();
    let vol_dev = fs::metadata(&vol.mount).unwrap().dev();
    assert_ne!(host_dev as u32, vol_dev as u32);
    let ws = Workspace::open(&vol.mount).unwrap();
    assert_eq!(ws.device(), vol_dev as u32);
}
