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

fn main() {
    let check = std::env::args().any(|arg| arg == "--check");
    println!(
        "hash,shape,run,keygen_peak_bytes,key_heap_bytes,sign_peak_bytes,sign_ns,sha256,sha512,keccak,serialize_peak_bytes,signature_bytes,signature_capacity,signature_sha256"
    );
    for hash in HashFn::ALL {
        for (name, shape) in [
            ("pruned-h20-b8", Shape::Pruned { b: 8 }),
            ("layered-8-6-6", Shape::Layered),
        ] {
            let cfg = Config::new(hash, 20, shape, Variant::Forest);
            for run in 0u8..=3 {
                let message = [run + 40; 32];
                let baseline = LIVE.load(Relaxed);
                reset_peak();
                let (sk, pk) = scheme::key_gen(&cfg, &[run; 32]);
                let keygen_peak = PEAK.load(Relaxed) - baseline;
                let key_heap = LIVE.load(Relaxed) - baseline;
                reset_peak();
                let before = scheme::hash_counts();
                let start = Instant::now();
                let sig = scheme::sign(&sk, &message).unwrap();
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
                    let budget = match shape {
                        Shape::Pruned { .. } => 24 * 1024,
                        Shape::Layered => 28 * 1024,
                    };
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
                        "{},{name},{run},{keygen_peak},{key_heap},{sign_peak},{elapsed},{},{},{},{serialize_peak},{},{},{fingerprint}",
                        hash.name(),
                        sign_counts.sha256,
                        sign_counts.sha512,
                        sign_counts.keccak,
                        bytes.len(),
                        bytes.capacity()
                    );
                }
                drop(bytes);
                drop(sig);
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
