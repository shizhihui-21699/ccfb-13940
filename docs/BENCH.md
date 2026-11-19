# Benchmarks

Method and results for `crates/attack-harness/src/bin/bench.rs`. Reproduce with:

```
cargo run -p attack-harness --bin bench --release -- --iters 20000
```

Each figure is the median of five timed batches of 20,000 operations, after a
2,000-iteration warm-up that faults in the page cache and the dynamic loader's
state. Lower is better; `std::fs` is the floor any layer must be compared
against, not a strawman.

## Environment

| | |
|---|---|
| Machine | Apple silicon (arm64), 14 cores |
| OS | macOS 26.5.1, Darwin 25.5.0 |
| Filesystem | APFS, case-insensitive |
| Build | `--release`, `debug = true` |

## Single-file read (`open` + `read` + `close`)

| | min | p50 | max |
|---|---:|---:|---:|
| `std::fs::File::open` | 6,711 ns | 6,732 ns | 6,763 ns |
| `safefs::open_read` | 13,556 ns | **13,636 ns** | 13,779 ns |
| overhead | | **+6,914 ns (+103%)** | |

A read through the layer costs two syscalls where `std::fs` costs one:

```
openat(root_fd, "src/file07.txt", O_NOFOLLOW_ANY|O_CLOEXEC)   ← the whole resolution
fgetattrlist(fd, {TYPE, DEVID, LINKCOUNT, FILEID, PARENTID, NAME, MOUNTSTATUS})
read(2) … close(2)                                            ← shared with std
```

The second syscall is where the guarantee is bought. It is one `fgetattrlist`
returning every fact policy needs (type, device, link count, inode, parent,
stored name, mount status). Splitting it into `fstat` + `fgetattrlist` + a name
lookup — the obvious implementation — cost 26.8 µs, twice this, and is what the
first version did.

Two syscalls at open time is the floor for *any* implementation that checks
anything: a check must read state, state lives behind a syscall, and a check
that runs before the open is exactly the race this layer removes.

## Deep paths (3 components)

| | p50 |
|---|---:|
| `std::fs` | 7,226 ns |
| `safefs::open_read` | **14,608 ns** |
| overhead | +7,437 ns |

Cost does not grow with depth. The kernel resolves the whole relative path in
one `openat`, so a nested path costs the same as a flat one — the per-component
walk is only the *fallback* when a symlink must be followed.

## Concurrency

Read throughput from N threads, no contention (a workspace handle takes no
locks on the read path):

| threads | ops/s |
|---:|---:|
| 1 | 71,449 |
| 2 | 96,881 |
| 4 | **115,898** |
| 8 | 69,597 |

Scaling is positive to 4.

## Writes (`create` + `write` + `close`, 5,000 files)

| | p50 (5,000 files) |
|---|---:|
| `std::fs::File::create` | 146.7 ms |
| `safefs::open_with(write)` | 195.6 ms |
| overhead | +33% |

Writes cost proportionally less than reads because the file creation dominates
and the extra attribute call is amortised against the kernel's allocation and
metadata-journal work.

## What was measured and rejected

A per-ancestor walk that re-opened every parent of a path and checked each for a
mount point cost **40.8 µs** per deep read — 3× the current number — and was
removed. It was also unsound: the leaf check already refuses any file whose
device is not the workspace's, which catches a mount anywhere along the path,
so the walk bought nothing a single `evidence` call did not already provide.

The lesson generalises: each additional syscall on the read path should be
justified by a fact the existing calls cannot supply.
