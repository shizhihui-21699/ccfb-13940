# safefs — TOCTOU-free workspace confinement for macOS CI

A Rust file-access layer for a build platform that executes untrusted
contributed scripts. The requirement it exists to meet:

> A script may read and write files inside its own workspace directory, and must
> be unable to touch **anything** outside it — at **any** interleaving of
> threads, not merely in the common case.

The security test that motivated it: a script creates a symlink inside the
workspace, waits for the platform to finish checking the path, and swaps the
link for one pointing at a system credential file in the instant before it is
opened.

---

## 1. Why the obvious implementation is broken

The naive design is two syscalls with a userspace check between them:

```rust
let real = fs::canonicalize(user_path)?;      // syscall 1: resolve
if !real.starts_with(workspace) { deny() }    // userspace: compare strings
let f = File::open(user_path)?;               // syscall 2: resolve *again*
```

Every assumption in that snippet is false under an attacker's control:

| Assumption | How it fails |
|---|---|
| The two syscalls resolve the same object | A `renamex_np(RENAME_SWAP)` between them exchanges two directory entries atomically; the second resolution sees a different inode |
| The path has no links | A symlink at any component redirects resolution |
| "Starts with workspace" means contained | `..`, and on a folding volume `WORKSPACE` vs `workspace` |
| Content has one name | A hard link gives an outside inode a workspace-relative name with no target to inspect |
| The path names a directory | A filesystem mounted over a subdirectory changes what the name means |
| Adding a lock helps | The attacker's threads and ours interleave at syscall granularity; any check-then-use window is exploitable |

**The measured reality.** `tests/race.rs::control_naive_implementation_leaks`
runs the code above against a single swapping thread. In one run it read the
secret **966 times** out of 45,154 successful reads. That test is kept, and it
is required to fail-loudly complain if it ever stops leaking, because without a
working attack the containment tests would prove nothing.

## 2. The design: a descriptor is the proof, not a string

> **Invariant.** Every file handed out was opened by the kernel from a
> directory descriptor for the workspace root, in a single `openat` that refuses
> symlinks at every component. Policy then reads its facts from that descriptor.

Two properties make this race-free:

* **The kernel performs the whole resolution.** `O_NOFOLLOW_ANY` (macOS 10.16+)
  makes a single `openat` refuse a symlink at *any* component, not just the
  last. There is no userspace loop, so there is no window.
* **A descriptor cannot be retargeted.** Once opened, renaming, unlinking,
  symlink-swapping or mounting over the path changes nothing about what the
  descriptor refers to.

That leaves the questions a descriptor alone cannot answer, each closed with a
kernel fact rather than a check:

### Symlinks
`O_NOFOLLOW_ANY` refuses them outright on the fast path. Relative links *inside*
the workspace are still allowed, via a component walker that follows a link only
after re-walking its target from the link's own directory — so `../../..`
simply runs out of stack and is refused. Absolute link targets are refused
outright: proving one is inside needs a name-based proof, which is exactly the
race we exist to avoid.

### Hard links
A hard link has no target. The witness is a *pair* of descriptor facts:

1. `link_count == 1` — no other name exists now;
2. `ATTR_CMN_PARENTID` equals the inode of the directory the path named.

Fact 1 alone is **not sound** — this was found by the harness, not by reasoning:
the attacker unlinks its own planted link between our `openat` and our
`fstat`, so the count reads 1 while the descriptor still points at outside data.
That bug leaked 4017 times before it was fixed. Fact 2 closes it: when the
workspace name disappears the kernel re-points `parentid` at the surviving
outside directory, so the comparison fails. The race then costs a spurious
*denial*, never a disclosure.

The structural fix is better than any check, and the layer offers it:
**a hard link cannot cross a filesystem boundary (`EXDEV`)**. If the workspace
is its own volume, no outside inode can ever have a name inside it.
`Workspace::open_isolated` checks this and reports [`Isolation::Confined`] when
it holds. `tests/isolation.rs` mounts a real APFS image and asserts `EXDEV`.

### Directories replaced / mounts
`workspace_root_replacement_is_detected` and the mount tests cover a directory
swapped for a symlink, a tree renamed away and grafted over, and a filesystem
mounted inside the workspace. Mounts are detected with
`ATTR_DIR_MOUNTSTATUS` on the descriptor, which stays accurate even for a
descriptor opened *before* the mount appeared.

### Case- and Unicode-folding volumes
APFS folds case (and normalisation) by default. Deciding policy from the
caller's spelling lets a script write `.GIT/hooks/pre-commit` and reach
`.git/hooks/pre-commit`. The layer reads the name the volume actually stored
(`ATTR_CMN_NAME`) and evaluates the deny list against **that**, with
`_PC_CASE_SENSITIVE` deciding whether ASCII-case-insensitive comparison applies.

### Cost
Two syscalls per read in the common case: one resolving `openat`, one
`fgetattrlist` for every fact policy needs (type, device, link count, inode,
parent, stored name). Measured numbers are in §5.

## 3. The second layer: Seatbelt

The library confines *this* process. A CI runner also executes build scripts,
which make their own syscalls, so the runner should additionally start each
script under a kernel Seatbelt profile that denies filesystem access outside the
workspace. `safefs::Sandbox` generates that profile from the same `Policy` and
the same root, so the two layers cannot drift.

The layers fail independently: the profile denies by *path* (broad, but cannot
express "this inode, reached safely"); the library allows by *descriptor*
(precise, but only covers calls that go through it).

`sandbox.known_gaps()` reports what the profile alone does not stop — notably a
hard link created *before* the sandbox starts, which sits inside the allowed
subtree. That is the same gap the isolation check closes structurally.

## 4. What is verified, and how

| Suite | Command | What it proves |
|---|---|---|
| Unit | `cargo test -p safefs --lib` | Lexical validation; the packed attribute layout still matches `fstat` |
| Functional | `cargo test -p safefs --test functional` | 21 deterministic attack cases pass or are refused |
| Race | `cargo test -p safefs --test race --release -- --nocapture` | Atomic swaps under load; **control leaks, implementation does not** |
| Isolation | `cargo test -p safefs --test isolation --release` | Real APFS image: `EXDEV`, mount detection, `Isolation::Confined` |
| Sandbox | `cargo test -p safefs --test sandbox` | The Seatbelt profile allows ordinary work and refuses every outside access |
| Harness | `cargo run -p attack-harness --bin harness -- self-test` | The same attacks against a deployed workspace |

Latest run (macOS 26.5.1, Darwin 25.5.0, APFS; 40 tests, all passing):

```
leaf-symlink-swap        84050 ok    61918 denied      0 LEAKED   PASS
directory-symlink-swap   43463 ok    80252 denied      0 LEAKED   PASS
directory-rename-replace 19949 ok        —  denied      0 LEAKED   PASS
hardlink-planting         4425 ok   425043 denied      0 LEAKED   PASS

control (naive canonicalize+open):  60527 ok   1186 LEAKED   ← the attack works

sandbox (Seatbelt):
  allow read/write/create inside ....... OK
  deny read outside .................... EPERM
  deny follow outbound symlink ......... EPERM
  deny write outside ................... EPERM
  deny read /etc/hosts ................. EPERM
  pre-existing hard link ............... readable  ← documented gap
```

## 5. Performance

Full tables and method in [`docs/BENCH.md`](docs/BENCH.md). Headline numbers on
this machine (macOS 26.5.1, APFS, Apple silicon):

| | `std::fs` | `safefs` | overhead |
|---|---:|---:|---:|
| single-file read | 6.7 µs | 13.6 µs | +103% |
| 3-component path | 7.2 µs | 14.6 µs | +103% |
| create+write | 146.7 ms / 5k | 195.6 ms / 5k | +33% |
| read throughput, 4 threads | — | 115,898 ops/s | scales positively |

That is **two syscalls where `std::fs` uses one**. The second call is the
`fgetattrlist` that returns every fact policy needs at once; it is the price of
any check performed at open time, and the design exists to make it *one* call
rather than six. Depth does not matter: the kernel resolves the entire relative
path in a single `openat`.

An intermediate version that reopened each ancestor to check for mounts cost
40.8 µs/op and was removed — the leaf's device check already catches mounts
anywhere along the path.

## 6. Deployment checklist

1. **Put each workspace on its own volume** — an APFS volume or an attachable
   disk image. This is the single highest-value step: it turns hard-link
   smuggling from "detected by a race-prone witness" into "impossible by
   `EXDEV`". Verify with `harness verify-isolation --workspace …`; it exits 0
   only for `Isolation::Confined`.
2. **Run build scripts under the Seatbelt profile** from `safefs::Sandbox`, not
   the library alone.
3. **Call `Workspace::revoke`** when a job is torn down, so threads still
   running cannot use the handle.
4. Read the known gaps in `Sandbox::known_gaps()` and decide per deployment.

## 7. Bugs this work found in itself

Two of the fixes above came from the harness catching the layer being wrong,
not from reasoning, and both are worth recording because they are the mistakes
anyone reimplementing this will make:

* **The `nlink` witness alone leaked.** Reading `st_nlink == 1` after `openat`
  looks like proof that no second name exists — but the attacker unlinks its own
  planted link between the `openat` and the `fstat`, so the count is back to
  one while the descriptor still points at outside data. **4,017 leaks.** The
  `ATTR_CMN_PARENTID` comparison closes it.
* **A "cheap symlink probe" reopened the hole.** Skipping the parent check when
  a follow-up `openat(O_NOFOLLOW)` suggested the leaf was not a symlink
  **re-leaked 12,496 times**: the probe answers a different question than the
  one that matters. The parent comparison is now unconditional for direct
  resolution; there is no bypass.

## 8. A kernel bug this work found

Two threads calling `renamex_np(RENAME_SWAP)` on the **same** pair of paths
deadlock the APFS kernel in this OS build; the second caller never returns, and
`kill -9` cannot reap it. It reproduces in about twenty lines of C with no
involvement from this crate:

```
$ scripts/verify_kernel_swap_bug.sh
reproduced: concurrent RENAME_SWAP on one path pair deadlocks the kernel
```

The test harness is shaped around it (one swapper per path pair, which is more
than enough — see the control's leak count), and the README says so rather than
pretending the suite is oblivious. Swapping *different* pairs from different
threads is fine, which is what a set of independent build scripts does.
