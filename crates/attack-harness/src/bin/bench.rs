//! `bench` — measures the cost of the layer against plain syscalls.
//!
//! Three numbers matter to the people who will run this:
//!
//! 1. **Absolute cost per operation.** A `read` through the layer vs a bare
//!    `open`/`read`/`close`.
//! 2. **Cost of the guarantee.** The delta attributable to the confinement
//!    checks, isolated by running the same shape of work through `std::fs`.
//! 3. **Scaling.** Whether 8 threads doing this concurrently saturate anything
//!    in the layer (it takes no locks on the read path, so they should not).
//!
//! Run with `cargo run -p attack-harness --bin bench --release -- <workspace>`.

use std::fs;
use std::hint::black_box;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use safefs::{OpenOptions, Workspace};

struct Args {
    root: PathBuf,
    iters: u64,
    keep: bool,
}

fn parse_args() -> Args {
    let mut root = std::env::temp_dir().join(format!("safefs-bench-{}", std::process::id()));
    let mut iters = 20_000;
    let mut keep = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--iters" => iters = it.next().unwrap().parse().unwrap(),
            "--keep" => keep = true,
            other => root = PathBuf::from(other),
        }
    }
    Args { root, iters, keep }
}

fn make_tree(root: &std::path::Path) {
    fs::create_dir_all(root.join("src/deep/nested")).unwrap();
    for i in 0..64 {
        fs::write(root.join(format!("src/file{i:02}.txt")), format!("contents-{i}")).unwrap();
    }
    for i in 0..16 {
        fs::write(root.join(format!("src/deep/nested/f{i}.txt")), "nested").unwrap();
    }
}

fn pct(mut v: Vec<f64>) -> (f64, f64, f64) {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let n = v.len();
    (v[0], v[n / 2], v[n - 1])
}

fn report(name: &str, samples: Vec<f64>) {
    let (min, med, max) = pct(samples);
    println!("  {name:<34} min {min:7.0}ns  p50 {med:7.0}ns  max {max:8.0}ns");
}

fn main() {
    let args = parse_args();
    fs::create_dir_all(&args.root).unwrap();
    make_tree(&args.root);
    let root = fs::canonicalize(&args.root).unwrap();

    println!("workspace: {}", root.display());
    println!("iterations per sample: {}\n", args.iters);

    let ws = Workspace::open(&root).unwrap();
    if !ws.policy().allow_hardlink {
        // Default policy: hard links are allowed to be created but their
        // results are untrusted for reading. Nothing in this benchmark needs
        // them, so the default is used unchanged.
    }

    // ---- warm the page cache and the caches in the loader -----------------
    for _ in 0..2000 {
        let mut f = ws.open_read("src/file00.txt").unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
    }
    for _ in 0..2000 {
        let mut f = fs::File::open(root.join("src/file00.txt")).unwrap();
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
    }

    let iters = args.iters;

    // ---- 1. single-file read ---------------------------------------------
    println!("single file read (open+read+close):");
    let mut plain = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..iters {
            let mut f = fs::File::open(root.join("src/file07.txt")).unwrap();
            let mut s = String::new();
            f.read_to_string(&mut s).unwrap();
            black_box(s);
        }
        plain.push(t.elapsed().as_nanos() as f64 / iters as f64);
    }
    report("std::fs::File::open", plain.clone());

    let mut layered = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        for _ in 0..iters {
            let mut f = ws.open_read("src/file07.txt").unwrap();
            let mut s = String::new();
            f.read_to_string(&mut s).unwrap();
            black_box(s);
        }
        layered.push(t.elapsed().as_nanos() as f64 / iters as f64);
    }
    report("safefs::open_read", layered.clone());
    println!(
        "  → overhead {:.0}ns/op ({:+.1}%), {} ops/s\n",
        layered.iter().sum::<f64>() / 5.0 - plain.iter().sum::<f64>() / 5.0,
        ((layered.iter().sum::<f64>()) / (plain.iter().sum::<f64>()) - 1.0) * 100.0,
        (1e9 / (layered.iter().sum::<f64>() / 5.0)) as u64
    );

    // ---- 2. deep path -----------------------------------------------------
    println!("deep path (3 components):");
    let mut plain_deep = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        for i in 0..iters {
            let p = root.join(format!("src/deep/nested/f{}.txt", i % 16));
            let mut f = fs::File::open(p).unwrap();
            let mut s = String::new();
            f.read_to_string(&mut s).unwrap();
            black_box(s);
        }
        plain_deep.push(t.elapsed().as_nanos() as f64 / iters as f64);
    }
    report("std::fs", plain_deep.clone());
    let mut layered_deep = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        for i in 0..iters {
            let mut f = ws.open_read(format!("src/deep/nested/f{}.txt", i % 16)).unwrap();
            let mut s = String::new();
            f.read_to_string(&mut s).unwrap();
            black_box(s);
        }
        layered_deep.push(t.elapsed().as_nanos() as f64 / iters as f64);
    }
    let d = layered_deep.iter().sum::<f64>() / 5.0 - plain_deep.iter().sum::<f64>() / 5.0;
    report("safefs::open_read", layered_deep);
    println!("  → overhead {d:.0}ns/op\n");

    // Concurrency: uncontended readers from several threads. The adversarial
    // variant lives in the test suite, where it can be shaped around the APFS
    // `RENAME_SWAP` deadlock; a benchmark that wedges the kernel is not a
    // benchmark.
    println!("read throughput, N threads × {} iters:", iters / 4);
    for threads in [1usize, 2, 4, 8] {
        let ws = Arc::new(Workspace::open(&root).unwrap());
        let per = iters / 4;
        let done = Arc::new(AtomicU64::new(0));
        let t = Instant::now();
        let mut hs = Vec::new();
        for _ in 0..threads {
            let ws = ws.clone();
            let done = done.clone();
            hs.push(std::thread::spawn(move || {
                for i in 0..per {
                    if let Ok(mut f) = ws.open_read(format!("src/file{:02}.txt", i % 64)) {
                        let mut s = String::new();
                        let _ = f.read_to_string(&mut s);
                        done.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }));
        }
        for h in hs {
            h.join().unwrap();
        }
        let el = t.elapsed();
        let ops = done.load(Ordering::Relaxed) as f64 / el.as_secs_f64();
        println!("  {threads:>2} threads: {ops:>12.0} ops/s");
    }

    // ---- 5. write throughput ---------------------------------------------
    println!("\nwrite throughput (create+write+close):");
    fs::create_dir_all(root.join("bench-out")).unwrap();
    let mut plain_w = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        for i in 0..iters / 4 {
            let p = root.join(format!("bench-out/a{}", i % 256));
            let mut f = fs::File::create(p).unwrap();
            f.write_all(b"payload").unwrap();
        }
        plain_w.push(t.elapsed().as_nanos() as f64);
    }
    report("std::fs::File::create", plain_w);
    let mut layered_w = Vec::new();
    for _ in 0..5 {
        let t = Instant::now();
        for i in 0..iters / 4 {
            let mut f = ws.open_with(format!("bench-out/b{}", i % 256), OpenOptions::write()).unwrap();
            f.write_all(b"payload").unwrap();
        }
        layered_w.push(t.elapsed().as_nanos() as f64);
    }
    report("safefs::open_with(write)", layered_w);
    fs::remove_dir_all(root.join("bench-out")).ok();

    if !args.keep {
        fs::remove_dir_all(&args.root).ok();
    }
    black_box(Duration::from_secs(0));
}
