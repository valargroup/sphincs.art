//! Requested live heap for the two small 192-bit forest configurations.
//! Run with `--check` to enforce the signing budget. Stack, static data and allocator overhead
//! are excluded; this is not a device RAM qualification. Each signature is also verified.
use sha2::{Digest as _, Sha256};
use sphincs::level192::{self as scheme, Config, HashFn, Shape, Variant};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use std::time::Instant;

struct TrackingAllocator;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn allocated(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Relaxed) + bytes;
    PEAK.fetch_max(live, Relaxed);
}

// All pointers/layouts are forwarded unchanged to System. Only successful allocations are
// counted; realloc records the logical live size, not allocator-internal copy overlap.
unsafe impl GlobalAlloc for TrackingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            allocated(layout.size());
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }
    unsafe fn realloc(&self, pointer: *mut u8, old: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, old, size) };
        if !result.is_null() {
            if size >= old.size() {
                allocated(size - old.size());
            } else {
                LIVE.fetch_sub(old.size() - size, Relaxed);
            }
        }
        result
    }
}
#[global_allocator]
static ALLOCATOR: TrackingAllocator = TrackingAllocator;

fn reset_peak() {
    PEAK.store(LIVE.load(Relaxed), Relaxed);
}

fn option<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|arg| arg == name).map(|position| {
        args.get(position + 1)
            .expect("missing option value")
            .as_str()
    })
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let check = args.iter().any(|arg| arg == "--check");
    let cache_levels: usize = option(&args, "--cache-levels")
        .unwrap_or("0")
        .parse()
        .expect("integer cache level");
    let precompute_level: Option<usize> = option(&args, "--precompute-level")
        .map(|value| value.parse().expect("integer precomputation level"));
    let precompute_budget: usize = option(&args, "--precompute-budget")
        .unwrap_or("2097152")
        .parse()
        .expect("integer precomputation budget");
    let hash_filter = option(&args, "--hash");
    assert!(
        hash_filter.is_none_or(|name| HashFn::ALL.iter().any(|hash| hash.name() == name)),
        "unknown hash"
    );
    assert!(cache_levels <= 8, "cache level exceeds the kept height");
    println!(
        "hash,shape,run,keygen_peak_bytes,key_heap_bytes,sign_peak_bytes,sign_ns,sha256,sha512,keccak,serialize_peak_bytes,signature_bytes,signature_capacity,signature_sha256,cache_levels,precompute_level,precompute_bytes,prepare_peak_bytes,prepare_ns,prepare_sha256,prepare_sha512,prepare_keccak,resident_bytes"
    );
    for hash in HashFn::ALL {
        if hash_filter.is_some_and(|name| hash.name() != name) {
            continue;
        }
        for (name, shape) in [
            ("pruned-h20-b8", Shape::Pruned { b: 8 }),
            ("layered-8-6-6", Shape::Layered),
        ] {
            if precompute_level.is_some() && shape == Shape::Layered {
                continue;
            }
            let cfg = Config::new(hash, 20, shape, Variant::Forest);
            for run in 0u8..=3 {
                let message = [run + 40; 32];
                let baseline = LIVE.load(Relaxed);
                reset_peak();
                let (sk, pk) = scheme::key_gen_with_cache(
                    &cfg,
                    &[run; 32],
                    scheme::TreeCache::Recompute {
                        levels: cache_levels,
                    },
                );
                let keygen_peak = PEAK.load(Relaxed) - baseline;
                let key_heap = LIVE.load(Relaxed) - baseline;
                reset_peak();
                let before = scheme::hash_counts();
                let start = Instant::now();
                let prepared = precompute_level
                    .map(|level| scheme::prepare_forest(&sk, level, precompute_budget).unwrap());
                let prepare_ns = start.elapsed().as_nanos();
                let prepare_counts = scheme::hash_counts() - before;
                let prepare_peak = PEAK.load(Relaxed) - baseline;
                let precompute_bytes = prepared
                    .as_ref()
                    .map_or(0, |prepared| prepared.cache_bytes());
                let resident_bytes = LIVE.load(Relaxed) - baseline;
                reset_peak();
                let before = scheme::hash_counts();
                let start = Instant::now();
                let sig = if let Some(prepared) = &prepared {
                    prepared.sign(&message)
                } else {
                    scheme::sign(&sk, &message)
                }
                .unwrap();
                let elapsed = start.elapsed().as_nanos();
                let sign_counts = scheme::hash_counts() - before;
                let sign_peak = PEAK.load(Relaxed) - baseline;
                let retained = LIVE.load(Relaxed);
                reset_peak();
                sig.write_to(&mut std::io::sink()).unwrap();
                assert_eq!(PEAK.load(Relaxed), retained, "streaming allocated a buffer");
                reset_peak();
                let bytes = sig.to_bytes();
                let serialize_peak = PEAK.load(Relaxed) - baseline;
                assert_eq!(bytes.len(), cfg.sig_size());
                scheme::verify(&cfg, &pk, &message, &sig).unwrap();
                if check {
                    if precompute_level.is_none() {
                        assert_eq!(
                            precompute_bytes, 0,
                            "normal signing prepared a public cache"
                        );
                        assert_eq!(
                            resident_bytes, key_heap,
                            "default preparation retained extra memory"
                        );
                        assert_eq!(
                            prepare_peak, key_heap,
                            "default preparation allocated temporary memory"
                        );
                        assert_eq!(
                            prepare_counts,
                            scheme::HashCounts::default(),
                            "default preparation performed hash work"
                        );
                    }
                    let full_budget = match shape {
                        Shape::Pruned { .. } => 24 * 1024,
                        Shape::Layered => 28 * 1024,
                    };
                    let removed_nodes: usize =
                        (0..cache_levels).map(|level| 1 << (8 - level)).sum();
                    let budget = full_budget - removed_nodes * scheme::N + precompute_bytes;
                    assert!(
                        sign_peak <= budget,
                        "signing heap exceeds {budget} bytes: {sign_peak}"
                    );
                    assert_eq!(bytes.capacity(), bytes.len(), "serialization overallocates");
                }
                if run != 0 {
                    let digest = Sha256::digest(&bytes);
                    let fingerprint: String = digest.iter().map(|b| format!("{b:02x}")).collect();
                    println!(
                        "{},{name},{run},{keygen_peak},{key_heap},{sign_peak},{elapsed},{},{},{},{serialize_peak},{},{},{fingerprint},{cache_levels},{},{precompute_bytes},{prepare_peak},{prepare_ns},{},{},{},{resident_bytes}",
                        hash.name(),
                        sign_counts.sha256,
                        sign_counts.sha512,
                        sign_counts.keccak,
                        bytes.len(),
                        bytes.capacity(),
                        precompute_level.unwrap_or(4),
                        prepare_counts.sha256,
                        prepare_counts.sha512,
                        prepare_counts.keccak,
                    );
                }
                drop(bytes);
                drop(sig);
                drop(prepared);
                drop(sk);
                assert_eq!(
                    LIVE.load(Relaxed),
                    baseline,
                    "operation retained allocations"
                );
            }
        }
    }
}
