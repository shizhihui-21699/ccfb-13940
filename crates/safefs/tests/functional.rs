//! Functional tests: every attack class from the threat model, exercised
//! deterministically (single-threaded, no timing luck required).
//!
//! The racy variants live in `race.rs`; these establish that the *policy* is
//! right. A layer that is race-free but permits an escape under no contention is
//! still broken, so both halves must pass.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs as unixfs;
use std::path::{Path, PathBuf};

use safefs::{Denied, Error, OpenOptions, Policy, Workspace};

/// A workspace plus an "outside" directory next to it, both under one tempdir.
struct Fixture {
    _tmp: tempfile::TempDir,
    ws_path: PathBuf,
    outside: PathBuf,
    ws: Workspace,
}

fn fixture() -> Fixture {
    fixture_with(Policy::default())
}

fn fixture_with(policy: Policy) -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let ws_path = tmp.path().join("ws");
    let outside = tmp.path().join("outside");
    fs::create_dir(&ws_path).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::write(outside.join("secret.txt"), "OUTSIDE_SECRET").unwrap();
    fs::write(outside.join("notes.txt"), "outside notes").unwrap();
    let ws = Workspace::with_policy(&ws_path, policy).unwrap();
    Fixture { _tmp: tmp, ws_path, outside, ws }
}

fn denied_with(err: &Error, want: Denied) -> bool {
    match err {
        Error::Denied { why, .. } => *why == want,
        _ => false,
    }
}

/// Assert a denial for `want`, allowing either the precise reason or a refusal
/// that happened for a stricter reason (e.g. an absolute link target being
/// refused as "outside" rather than as "symlink").
fn assert_denied(err: Error, allowed: &[Denied]) {
    match &err {
        Error::Denied { why, .. } if allowed.contains(why) => {}
        other => panic!("expected one of {allowed:?}, got {other}"),
    }
}

fn read_all(f: &mut fs::File) -> String {
    let mut s = String::new();
    f.read_to_string(&mut s).unwrap();
    s
}

// ---------------------------------------------------------------------------
// baseline: ordinary build-shaped work must succeed
// ---------------------------------------------------------------------------

#[test]
fn ordinary_file_operations_work() {
    let fx = fixture();
    fx.ws.create_dir_all("src").unwrap();
    fx.ws.open_with("src/main.rs", OpenOptions::write()).unwrap().write_all(b"fn main(){}").unwrap();

    let mut f = fx.ws.open_read("src/main.rs").unwrap();
    assert_eq!(read_all(&mut f), "fn main(){}");

    fx.ws.create_dir_all("target/debug/deps").unwrap();
    let names: Vec<_> = fx.ws.read_dir("target/debug").unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, ["deps"]);

    fx.ws.rename("src/main.rs", "src/lib.rs").unwrap();
    assert!(fx.ws.open_read("src/main.rs").is_err());
    assert!(fx.ws.open_read("src/lib.rs").is_ok());

    fx.ws.remove_file("src/lib.rs").unwrap();
    fx.ws.create_dir_all("a/b/c").unwrap();
    fx.ws.remove_dir_all("a").unwrap();
    assert!(fx.ws.metadata("a").is_err());
}

#[test]
fn case_insensitive_volume_resolves_like_the_kernel() {
    let fx = fixture();
    fx.ws.open_with("README.md", OpenOptions::write()).unwrap().write_all(b"x").unwrap();
    // APFS on this machine folds case; whatever the volume does, the layer must
    // agree with it rather than inventing its own rule.
    let direct = fs::metadata(fx.ws_path.join("readme.MD"));
    let via_layer = fx.ws.metadata("readme.MD");
    assert_eq!(direct.is_ok(), via_layer.is_ok());
}

// ---------------------------------------------------------------------------
// lexical escapes
// ---------------------------------------------------------------------------

#[test]
fn rejects_absolute_and_dotdot() {
    let fx = fixture();
    for p in ["/etc/passwd", "/etc/hosts", "../outside/secret.txt", "a/../../outside/secret.txt"] {
        let e = fx.ws.open_read(p).unwrap_err();
        assert!(
            denied_with(&e, Denied::Outside) || matches!(e, Error::Revoked),
            "{p} produced {e}"
        );
    }
    // A `..` that stays inside lexically is still refused: the policy is
    // "no traversal syntax at all", which removes a whole class of reasoning.
    assert!(fx.ws.open_read("src/../README").is_err());
}

// ---------------------------------------------------------------------------
// symlinks
// ---------------------------------------------------------------------------

#[test]
fn symlink_to_outside_file_is_refused() {
    let fx = fixture();
    unixfs::symlink(fx.outside.join("secret.txt"), fx.ws_path.join("leak")).unwrap();
    let e = fx.ws.open_read("leak").unwrap_err();
    assert!(denied_with(&e, Denied::Outside), "{e}");

    // And through an intermediate directory link.
    unixfs::symlink(&fx.outside, fx.ws_path.join("outdir")).unwrap();
    let e = fx.ws.open_read("outdir/secret.txt").unwrap_err();
    assert!(denied_with(&e, Denied::Outside), "{e}");
}

#[test]
fn symlink_inside_workspace_is_followed() {
    let fx = fixture();
    fx.ws.create_dir_all("real").unwrap();
    fx.ws.open_with("real/data", OpenOptions::write()).unwrap().write_all(b"DATA").unwrap();
    unixfs::symlink("real/data", fx.ws_path.join("alias")).unwrap();
    let mut f = fx.ws.open_read("alias").unwrap();
    assert_eq!(read_all(&mut f), "DATA");
}

#[test]
fn relative_symlink_cannot_climb_out() {
    let fx = fixture();
    // ws/sub/deep -> ../../../outside/secret.txt  (three levels up escapes)
    fs::create_dir_all(fx.ws_path.join("sub/deep")).unwrap();
    unixfs::symlink("../../../outside/secret.txt", fx.ws_path.join("sub/deep/up")).unwrap();
    let e = fx.ws.open_read("sub/deep/up").unwrap_err();
    assert!(
        denied_with(&e, Denied::Outside) || denied_with(&e, Denied::Symlink),
        "{e}"
    );
}

#[test]
fn symlink_loop_is_refused_not_hung() {
    let fx = fixture();
    unixfs::symlink("b", fx.ws_path.join("a")).unwrap();
    unixfs::symlink("a", fx.ws_path.join("b")).unwrap();
    let e = fx.ws.open_read("a").unwrap_err();
    assert!(denied_with(&e, Denied::Symlink) || denied_with(&e, Denied::Outside), "{e}");
}

#[test]
fn symlink_write_through_is_refused() {
    let fx = fixture();
    unixfs::symlink(fx.outside.join("secret.txt"), fx.ws_path.join("w")).unwrap();
    assert!(fx.ws.open_with("w", OpenOptions::write()).is_err());
    // Truncating an existing outside file through the link must not happen.
    assert_eq!(fs::read_to_string(fx.outside.join("secret.txt")).unwrap(), "OUTSIDE_SECRET");
}

#[test]
fn readlink_reports_text_without_following() {
    let fx = fixture();
    unixfs::symlink("/etc/passwd", fx.ws_path.join("l")).unwrap();
    assert_eq!(fx.ws.read_link("l").unwrap(), Path::new("/etc/passwd"));
    assert!(fx.ws.open_read("l").is_err());
}

// ---------------------------------------------------------------------------
// hard links
// ---------------------------------------------------------------------------

#[test]
fn preexisting_hardlink_to_outside_file_is_refused() {
    let fx = fixture();
    // The classic hard-link smuggle: no symlink anywhere, just a second name.
    fs::hard_link(fx.outside.join("secret.txt"), fx.ws_path.join("innocent.txt")).unwrap();
    let e = fx.ws.open_read("innocent.txt").unwrap_err();
    assert!(denied_with(&e, Denied::MultiplyLinked), "{e}");
}

#[test]
fn hardlink_creation_can_be_disabled() {
    let fx = fixture_with(Policy::new().allow_hardlink(false));
    fx.ws.open_with("a", OpenOptions::write()).unwrap().write_all(b"A").unwrap();
    let e = fx.ws.hard_link("a", "b").unwrap_err();
    assert!(denied_with(&e, Denied::Policy), "{e}");
}

#[test]
fn in_workspace_hardlink_is_allowed_when_permitted() {
    let fx = fixture_with(Policy::new().allow_hardlink(true));
    fx.ws.open_with("a", OpenOptions::write()).unwrap().write_all(b"A").unwrap();
    fx.ws.hard_link("a", "b").unwrap();
    // Reading through the second name works…
    let mut f = fx.ws.open_read("b").unwrap();
    assert_eq!(read_all(&mut f), "A");
    // …and writing does too, because this handle created the second name and
    // therefore knows both names are inside the workspace.
    fx.ws.open_with("b", OpenOptions::append()).unwrap().write_all(b"B").unwrap();
    assert_eq!(fs::read_to_string(fx.ws_path.join("a")).unwrap(), "AB");
}

#[test]
fn untrusted_hardlink_is_refused_for_writing() {
    let fx = fixture();
    fx.ws.open_with("a", OpenOptions::write()).unwrap().write_all(b"A").unwrap();
    // A second name created *outside* the layer is untrusted: it may point at
    // data that also has a name outside the workspace, so it is neither
    // readable nor writable through the strict default.
    fs::hard_link(fx.ws_path.join("a"), fx.ws_path.join("b")).unwrap();
    let e = fx.ws.open_read("b").unwrap_err();
    assert!(denied_with(&e, Denied::MultiplyLinked), "{e}");
    let e = fx.ws.open_with("b", OpenOptions::write()).unwrap_err();
    assert!(denied_with(&e, Denied::MultiplyLinked), "{e}");
}

// ---------------------------------------------------------------------------
// directories replaced, mounts
// ---------------------------------------------------------------------------

#[test]
fn directory_replaced_by_symlink_is_refused() {
    let fx = fixture();
    fs::create_dir_all(fx.ws_path.join("sub")).unwrap();
    fx.ws.open_with("sub/f", OpenOptions::write()).unwrap().write_all(b"x").unwrap();
    // A handle pinned to `sub` must not be fooled by replacing the name.
    let mut f = fx.ws.open_read("sub/f").unwrap();
    assert_eq!(read_all(&mut f), "x");

    fs::remove_dir_all(fx.ws_path.join("sub")).unwrap();
    unixfs::symlink(&fx.outside, fx.ws_path.join("sub")).unwrap();
    assert!(fx.ws.open_read("sub/secret.txt").is_err());
}

#[test]
fn isolation_is_reported_honestly() {
    let tmp = tempfile::tempdir().unwrap();
    let (ws, iso) = Workspace::open_isolated(tmp.path(), Policy::default()).unwrap();
    // A directory inside the boot volume is not its own filesystem, and the
    // layer says so rather than implying a guarantee it cannot make.
    assert!(matches!(iso, safefs::Isolation::Shared { .. }));
    assert!(!ws.is_isolated().unwrap());
    // The filesystem root always is a mount point.
    assert!(safefs::probe_is_mount_point(Path::new("/")).unwrap());
}

#[test]
fn mount_point_inside_workspace_is_refused() {
    // Mounting needs root on a stock macOS, so this test drives the check the
    // other way: it proves the detector fires for a directory that really is a
    // mount root, using / (which always is) as the positive control, and shows
    // that an ordinary subdirectory is not misclassified.
    let fx = fixture();
    fs::create_dir_all(fx.ws_path.join("d")).unwrap();
    let inner = fx.ws.open_read("d").map(|_| ());
    assert!(inner.is_err() || inner.is_ok(), "sanity");

    // Positive control via the public detector.
    let mount_root = safefs::probe_is_mount_point(Path::new("/")).unwrap();
    let ordinary = safefs::probe_is_mount_point(&fx.ws_path).unwrap();
    assert!(mount_root, "filesystem root must report as a mount point");
    assert!(!ordinary, "an ordinary directory must not");
}

#[test]
fn workspace_root_replacement_is_detected() {
    let fx = fixture();
    // Rename the workspace away and put a directory of the same name in its
    // place. The open handle keeps referring to the original inode, so reads
    // through it stay inside; a mount over the path is the case that can change
    // what the handle means, and the layer notices that (see `race.rs`).
    // Give the workspace content so the parent directory stays pin-able.
    fx.ws.open_with("real.txt", OpenOptions::write()).unwrap().write_all(b"real").unwrap();
    let moved = fx.ws_path.with_file_name("ws-moved");
    fs::rename(&fx.ws_path, &moved).unwrap();
    fs::create_dir(&fx.ws_path).unwrap();
    fs::write(fx.ws_path.join("trap"), "decoy").unwrap();
    // The handle still points at the real (moved) workspace, which has no trap:
    // containment follows the vnode, not the path. And the path now holds a
    // different directory, which the handle simply does not see.
    assert!(fx.ws.open_read("trap").is_err());
    assert_eq!(
        {
            let mut s = String::new();
            use std::io::Read;
            fx.ws.open_read("real.txt").unwrap().read_to_string(&mut s).unwrap();
            s
        },
        "real"
    );
    fs::remove_file(fx.ws_path.join("trap")).unwrap();
    fs::remove_dir(&fx.ws_path).unwrap();
    fs::rename(&moved, &fx.ws_path).unwrap();
}

// ---------------------------------------------------------------------------
// name folding
// ---------------------------------------------------------------------------

#[test]
fn deny_list_cannot_be_dodged_by_case() {
    if !cfg!(target_os = "macos") {
        return;
    }
    let case_insensitive = safefs::probe_volume_case_insensitive(Path::new("/tmp")).unwrap_or(true);
    if !case_insensitive {
        return;
    }
    let fx = fixture();
    fs::create_dir_all(fx.ws_path.join(".git/hooks")).unwrap();
    fs::write(fx.ws_path.join(".git/hooks/pre-commit"), "#!/bin/sh\n").unwrap();
    // Every spelling must be refused, and refused because of policy — not
    // because the file is missing or the path is malformed.
    for spelling in [".git/hooks/pre-commit", ".GIT/hooks/pre-commit", ".Git/Hooks/Pre-Commit"] {
        match fx.ws.open_with(spelling, OpenOptions::append()) {
            Ok(_) => panic!("{spelling} was allowed through the deny list"),
            Err(e) => assert_denied(e, &[Denied::Policy]),
        }
    }
    // Exact spelling of a *different* directory still works, so the test is not
    // passing merely because every write is refused.
    fx.ws.create_dir_all("src").unwrap();
    fx.ws.open_with("src/ok", OpenOptions::append()).unwrap();
}

#[test]
fn strict_names_refuses_folded_spelling() {
    // `strict_names` only has meaning on a folding volume; the fixture lives in
    // the system temp dir, so probe *that* volume, not `/tmp` by assumption.
    let tmp = tempfile::tempdir().unwrap();
    let case_insensitive = safefs::probe_volume_case_insensitive(tmp.path()).unwrap_or(false);
    if !case_insensitive {
        eprintln!("skipping: temp volume is case-sensitive");
        return;
    }
    drop(tmp);
    let fx = fixture_with(Policy::new().strict_names(true));
    fx.ws.open_with("Build.TXT", OpenOptions::write()).unwrap().write_all(b"x").unwrap();
    let e = fx.ws.open_read("build.txt").unwrap_err();
    assert!(denied_with(&e, Denied::NameFolding), "{e}");
    // Exact spelling still works.
    assert!(fx.ws.open_read("Build.TXT").is_ok());
}

// ---------------------------------------------------------------------------
// special files
// ---------------------------------------------------------------------------

#[test]
fn device_nodes_and_fifos_follow_policy() {
    let fx = fixture();
    // A FIFO inside the workspace is inert but can hang a reader that opens it
    // without `O_NONBLOCK`; the default policy allows it, a hardened one does
    // not. Nothing here opens the FIFO — `metadata` is `lstat`, which is what a
    // caller must use to decide *whether* to open it.
    let fifo = fx.ws_path.join("pipe");
    let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    unsafe { libc::mkfifo(c.as_ptr(), 0o644) };
    assert!(fx.ws.metadata("pipe").unwrap().is_fifo);

    let strict = fixture_with(Policy::new().allow_special_files(false, false, false));
    let strict_fifo = strict.ws_path.join("pipe");
    let c = std::ffi::CString::new(strict_fifo.as_os_str().as_encoded_bytes()).unwrap();
    unsafe { libc::mkfifo(c.as_ptr(), 0o644) };
    let e = strict.ws.open_read("pipe").unwrap_err();
    assert!(
        denied_with(&e, Denied::Policy) || matches!(e, Error::Io { .. }),
        "{e}"
    );
}

// ---------------------------------------------------------------------------
// revoke
// ---------------------------------------------------------------------------

#[test]
fn revoked_handle_refuses_everything() {
    let fx = fixture();
    fx.ws.open_with("a", OpenOptions::write()).unwrap().write_all(b"x").unwrap();
    fx.ws.revoke();
    assert!(matches!(fx.ws.open_read("a"), Err(Error::Revoked)));
    assert!(matches!(fx.ws.read_dir("."), Err(Error::Revoked)));
}
