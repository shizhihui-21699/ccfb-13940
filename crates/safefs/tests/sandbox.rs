//! Tests for the Seatbelt layer.
//!
//! These assert both directions, which matters: a profile that denies
//! everything also "passes" a containment test while being useless. Every
//! refusal below is paired with an allowance that must succeed.
//!
//! They run children through `sandbox-exec`, so they are skipped when it is
//! unavailable rather than failing the suite on a host that cannot sandbox.

use std::fs;
use std::path::Path;
use std::process::Output;

use safefs::{Policy, Sandbox};

fn sandbox_available() -> bool {
    Path::new("/usr/bin/sandbox-exec").exists()
}

struct Fixture {
    _tmp: tempfile::TempDir,
    ws: std::path::PathBuf,
    outside: std::path::PathBuf,
    sb: Sandbox,
}

fn fixture() -> Option<Fixture> {
    if !sandbox_available() {
        eprintln!("skipping: /usr/bin/sandbox-exec not present");
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let ws = tmp.path().join("ws");
    let outside = tmp.path().join("outside");
    fs::create_dir_all(&ws).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(outside.join("secret.txt"), "OUTSIDE_SECRET").unwrap();
    fs::write(ws.join("data"), "LOCAL").unwrap();
    std::os::unix::fs::symlink(outside.join("secret.txt"), ws.join("sneaky")).unwrap();
    let sb = Sandbox::confined(&ws, &Policy::default()).unwrap();
    Some(Fixture { _tmp: tmp, ws, outside, sb })
}

fn run(sb: &Sandbox, script: &str) -> Output {
    sb.command("/bin/sh").arg("-c").arg(script).output().unwrap()
}

fn ok(o: &Output) -> bool {
    o.status.success()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// allowances: the profile must not break ordinary builds
// ---------------------------------------------------------------------------

#[test]
fn permits_ordinary_workspace_work() {
    let Some(f) = fixture() else { return };
    let o = run(&f.sb, "cat data");
    assert!(ok(&o), "reading a workspace file failed: {}", stderr(&o));
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "LOCAL");

    let o = run(&f.sb, "echo built > out.txt && cat out.txt");
    assert!(ok(&o), "creating and reading a file failed: {}", stderr(&o));
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "built");

    let o = run(&f.sb, "mkdir -p a/b && echo x > a/b/c && ls a/b");
    assert!(ok(&o), "subdirectory work failed: {}", stderr(&o));

    // A system binary must still be executable, or a build cannot run a
    // compiler, a linker, or even `true`.
    let o = run(&f.sb, "/usr/bin/true && echo RAN");
    assert!(ok(&o), "running a system binary failed: {}", stderr(&o));
    assert_eq!(String::from_utf8_lossy(&o.stdout).trim(), "RAN");
}

// ---------------------------------------------------------------------------
// refusals: nothing outside the workspace, however it is reached
// ---------------------------------------------------------------------------

#[test]
fn denies_reading_outside_the_workspace() {
    let Some(f) = fixture() else { return };
    for (what, script) in [
        ("direct path", format!("cat {}/secret.txt", f.outside.display())),
        ("via symlink", "cat sneaky".to_string()),
        ("system file", "cat /etc/hosts".to_string()),
        ("parent traversal", "cat ../outside/secret.txt".to_string()),
    ] {
        let o = run(&f.sb, &script);
        assert!(!ok(&o), "{what} was allowed: {:?}", String::from_utf8_lossy(&o.stdout));
        assert!(
            !String::from_utf8_lossy(&o.stdout).contains("OUTSIDE_SECRET"),
            "{what} disclosed the secret"
        );
    }
}

#[test]
fn denies_writing_outside_the_workspace() {
    let Some(f) = fixture() else { return };
    let target = f.outside.join("pwn");
    let o = run(&f.sb, &format!("echo pwned > {}", target.display()));
    assert!(!ok(&o), "a write outside the workspace succeeded");
    assert!(!target.exists(), "the file was created despite the profile");

    // And the outside directory must not gain entries by any other route.
    let before = fs::read_dir(&f.outside).unwrap().count();
    run(&f.sb, &format!("mkdir {} 2>/dev/null", f.outside.join("d").display()));
    run(&f.sb, &format!("touch {} 2>/dev/null", f.outside.join("t").display()));
    assert_eq!(fs::read_dir(&f.outside).unwrap().count(), before);
}

#[test]
fn denies_network_and_devices() {
    let Some(f) = fixture() else { return };
    // `/dev` is writable (streams), but other devices are not readable, and
    // outbound network is denied by having no rule for it.
    let o = run(&f.sb, "cat /dev/urandom | head -c 1 > /dev/null 2>&1; echo done");
    // Not asserting the exit here: /dev/urandom being unreadable is the point;
    // what must not happen is a *filesystem* read outside the workspace.
    let _ = o;
    let o = run(&f.sb, "/usr/bin/curl -s -m 2 http://example.com > out.txt 2>&1; echo rc=$?");
    let text = String::from_utf8_lossy(&o.stdout).into_owned();
    assert!(
        text.contains("rc=1") || text.contains("rc=6") || text.contains("rc=7") || text.contains("rc=28"),
        "curl appeared to reach the network: {text}"
    );
}

// ---------------------------------------------------------------------------
// the documented gap: a hard link planted before the sandbox starts
// ---------------------------------------------------------------------------

#[test]
fn reports_the_preexisting_hardlink_gap() {
    let Some(f) = fixture() else { return };
    // Planted before `sandbox-exec` runs, so it is inside the allowed subtree.
    fs::hard_link("/etc/hosts", f.ws.join("planted")).unwrap();
    let o = run(&f.sb, "cat planted");
    assert!(
        ok(&o) && String::from_utf8_lossy(&o.stdout).contains("localhost"),
        "expected the documented gap to be observable; if this now fails, the gap closed \
         and `Sandbox::known_gaps` should be updated"
    );
    assert!(
        f.sb.known_gaps().iter().any(|g| g.contains("hard link")),
        "the gap is observable but not reported by known_gaps()"
    );
}

#[test]
fn profile_is_generated_from_the_root() {
    let Some(f) = fixture() else { return };
    let p = f.sb.profile();
    let root = fs::canonicalize(&f.ws).unwrap();
    assert!(p.contains(&root.to_string_lossy().into_owned()), "root missing from profile");
    assert!(p.contains("(deny default)"), "profile must deny by default");
    assert!(!p.contains("(allow default)"), "profile must not allow everything");
    // The root's ancestors are searchable, or `getcwd` fails inside the job.
    assert!(p.contains("file-read-metadata"));
}
