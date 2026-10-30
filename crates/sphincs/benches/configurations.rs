//! Sequential CPU measurements. The Python runner records machine and commit provenance.
use sphincs::{self as legacy, level192 as new};
use std::{hint::black_box, time::Instant};

fn option(args: &[String], name: &str, default: &str) -> String {
    args.windows(2)
        .find(|p| p[0] == name)
        .map(|p| p[1].clone())
        .unwrap_or_else(|| default.into())
}
fn selected(list: &str, item: &str) -> bool {
    list.split(',').any(|v| v == item)
}
fn counts(c: new::HashCounts) -> String {
    format!(
        "{{\"sha256\":{},\"sha512\":{},\"keccak\":{}}}",
        c.sha256, c.sha512, c.keccak
    )
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|s| s == "--help") {
        println!(
            "configurations --families 128,192 --hashes Keccak-256,BLAKE2s,SHA-256,SHAKE256,SHA2 --heights 20,22,24,26,28 --shapes pruned,layered --variants forest,fors --kept-height 0 --cache-levels 0 --runs 3 --messages 3 --verify-iters 1000"
        );
        return;
    }
    let families = option(&args, "--families", "128,192");
    let hashes = option(
        &args,
        "--hashes",
        "Keccak-256,BLAKE2s,SHA-256,SHAKE256,SHA2",
    );
    let heights = option(&args, "--heights", "20,22,24,26,28");
    let shapes = option(&args, "--shapes", "pruned,layered");
    let variants = option(&args, "--variants", "forest,fors");
    let kept_height: usize = option(&args, "--kept-height", "0")
        .parse()
        .expect("integer kept height");
    let cache_levels: usize = option(&args, "--cache-levels", "0")
        .parse()
        .expect("integer cache level");
    assert!(
        cache_levels == 0 || families == "192",
        "partial cache requires family 192"
    );
    let runs: usize = option(&args, "--runs", "3").parse().expect("integer runs");
    let messages: usize = option(&args, "--messages", "3")
        .parse()
        .expect("integer messages");
    let verify_iters: usize = option(&args, "--verify-iters", "1000")
        .parse()
        .expect("integer iterations");
    assert!(runs > 0 && messages > 0 && verify_iters > 0);
    for h in legacy::HEIGHTS {
        if !selected(&heights, &h.to_string()) {
            continue;
        }
        for (shape_name, shape) in [
            (
                "pruned",
                legacy::Shape::Pruned {
                    b: if kept_height == 0 {
                        (h / 2).max(12)
                    } else {
                        kept_height
                    },
                },
            ),
            ("layered", legacy::Shape::Layered),
        ] {
            if !selected(&shapes, shape_name) {
                continue;
            }
            if selected(&families, "192") {
                for hash in new::HashFn::ALL {
                    if !selected(&hashes, hash.name()) {
                        continue;
                    }
                    for variant in new::Variant::ALL {
                        if !selected(&variants, variant.name()) {
                            continue;
                        }
                        let cfg = new::Config::new(hash, h, shape, variant);
                        for run in 0..=runs {
                            let seed = std::array::from_fn(|i| (i + run * 37 + h) as u8);
                            let before = new::hash_counts();
                            let start = Instant::now();
                            let (sk, pk) = new::key_gen_with_cache(
                                &cfg,
                                black_box(&seed),
                                new::TreeCache::Recompute {
                                    levels: cache_levels,
                                },
                            );
                            let keygen = start.elapsed().as_nanos();
                            let key_counts = new::hash_counts() - before;
                            let mut signing = Vec::new();
                            let mut signing_counts = Vec::new();
                            let mut last = None;
                            for m in 0..messages {
                                let message: Vec<u8> =
                                    (0..32).map(|i| (i + run * 19 + m * 47) as u8).collect();
                                let before = new::hash_counts();
                                let start = Instant::now();
                                let sig = new::sign(black_box(&sk), black_box(&message))
                                    .expect("signing exhausted");
                                signing.push(start.elapsed().as_nanos());
                                signing_counts.push(counts(new::hash_counts() - before));
                                new::verify(&cfg, &pk, &message, &sig).expect("signature rejected");
                                last = Some((message, sig));
                            }
                            let (message, sig) = last.unwrap();
                            let before = new::hash_counts();
                            new::verify(&cfg, &pk, &message, &sig).unwrap();
                            let verify_counts = new::hash_counts() - before;
                            assert_eq!(verify_counts, cfg.verify_counts(message.len()));
                            let start = Instant::now();
                            for _ in 0..verify_iters {
                                new::verify(
                                    black_box(&cfg),
                                    black_box(&pk),
                                    black_box(&message),
                                    black_box(&sig),
                                )
                                .unwrap();
                            }
                            let verification = start.elapsed().as_nanos() / verify_iters as u128;
                            if run == 0 {
                                continue;
                            }
                            println!(
                                "{{\"family\":192,\"hash\":\"{}\",\"variant\":\"{}\",\"h\":{},\"shape\":\"{}\",\"b\":{},\"run\":{},\"message_bytes\":32,\"signature_bytes\":{},\"keygen_ns\":{},\"sign_ns\":{:?},\"verify_ns\":{},\"verify_iterations\":{},\"keygen_counts\":{},\"sign_counts\":[{}],\"verify_counts\":{},\"cache_levels\":{}}}",
                                hash.name(),
                                variant.name(),
                                h,
                                shape_name,
                                cfg.kept(),
                                run,
                                cfg.sig_size(),
                                keygen,
                                signing,
                                verification,
                                verify_iters,
                                counts(key_counts),
                                signing_counts.join(","),
                                counts(verify_counts),
                                cache_levels
                            );
                        }
                    }
                }
            }
            if selected(&families, "128") && selected(&variants, "forest") {
                for hash in legacy::HashFn::ALL {
                    if !selected(&hashes, hash.name()) {
                        continue;
                    }
                    let cfg = legacy::Config::new(hash, h, shape);
                    for run in 0..=runs {
                        let seed = std::array::from_fn(|i| (i + run * 37 + h) as u8);
                        let before = legacy::compressions();
                        let start = Instant::now();
                        let (sk, pk) = legacy::key_gen(&cfg, black_box(&seed));
                        let keygen = start.elapsed().as_nanos();
                        let key_counts = legacy::compressions() - before;
                        let mut signing = Vec::new();
                        let mut signing_counts = Vec::new();
                        let mut last = None;
                        for m in 0..messages {
                            let message = std::array::from_fn(|i| (i + run * 19 + m * 47) as u8);
                            let before = legacy::compressions();
                            let start = Instant::now();
                            let sig = legacy::sign(black_box(&sk), black_box(&message));
                            signing.push(start.elapsed().as_nanos());
                            signing_counts.push(legacy::compressions() - before);
                            legacy::verify(&cfg, &pk, &message, &sig).unwrap();
                            last = Some((message, sig));
                        }
                        let (message, sig) = last.unwrap();
                        let start = Instant::now();
                        for _ in 0..verify_iters {
                            legacy::verify(
                                black_box(&cfg),
                                black_box(&pk),
                                black_box(&message),
                                black_box(&sig),
                            )
                            .unwrap();
                        }
                        let verification = start.elapsed().as_nanos() / verify_iters as u128;
                        if run == 0 {
                            continue;
                        }
                        println!(
                            "{{\"family\":128,\"hash\":\"{}\",\"variant\":\"forest\",\"h\":{},\"shape\":\"{}\",\"b\":{},\"run\":{},\"message_bytes\":32,\"signature_bytes\":{},\"keygen_ns\":{},\"sign_ns\":{:?},\"verify_ns\":{},\"verify_iterations\":{},\"keygen_compressions\":{},\"sign_compressions\":{:?},\"verify_compressions\":{}}}",
                            hash.name(),
                            h,
                            shape_name,
                            cfg.kept(),
                            run,
                            cfg.sig_size(),
                            keygen,
                            signing,
                            verification,
                            verify_iters,
                            key_counts,
                            signing_counts,
                            cfg.verify_compressions()
                        );
                    }
                }
            }
        }
    }
}
