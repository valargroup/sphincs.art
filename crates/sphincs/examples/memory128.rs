//! Requested heap during 128-bit signing, including the retained key and output signature.
//! Excludes stack, static storage and allocator overhead; this is not hardware qualification.
use sphincs::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

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
    let profile = std::env::args().any(|arg| arg == "--profile");
    let check = std::env::args().any(|arg| arg == "--check");
    let levels: usize = std::env::args()
        .position(|arg| arg == "--cache-levels")
        .map_or(0, |i| {
            std::env::args()
                .nth(i + 1)
                .expect("missing cache levels")
                .parse()
                .expect("integer cache levels")
        });
    assert!(levels <= 8, "cache levels exceed smallest kept tree");
    println!("hash,shape,run,key_heap,sign_peak,compressions,bytes,fingerprint");
    for hash in HashFn::ALL {
        for (name, shape) in [
            ("pruned", Shape::Pruned { b: 8 }),
            ("layered", Shape::Layered),
        ] {
            let cfg = Config::new(hash, 20, shape);
            for run in 0..3u8 {
                let (sk, pk) =
                    key_gen_with_cache(&cfg, &[run + 1; 32], TreeCache::Recompute { levels });
                let resident = LIVE.load(Relaxed);
                reset_peak();
                let before = compressions();
                let m = [run + 40; MESSAGE_LEN];
                let sig = sign(&sk, &m);
                let count = compressions() - before;
                let peak = PEAK.load(Relaxed);
                if check {
                    assert!(peak <= 32 * 1024, "signing heap regression");
                }
                reset_peak();
                let before_write = LIVE.load(Relaxed);
                sig.write_to(std::io::sink()).unwrap();
                assert_eq!(
                    PEAK.load(Relaxed),
                    before_write,
                    "streaming writer allocated"
                );
                verify(&cfg, &pk, &m, &sig).unwrap();
                let bytes = sig.to_bytes();
                let fingerprint = keccak::hash(&bytes)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>();
                println!(
                    "{hash:?},{name},{run},{resident},{peak},{count},{},{fingerprint}",
                    bytes.len()
                );
                if profile && hash == HashFn::Sha256 && name == "pruned" && run == 0 {
                    let start = std::time::Instant::now();
                    while start.elapsed().as_secs() < 8 {
                        std::hint::black_box(sign(&sk, &m));
                    }
                }
            }
        }
    }
}
