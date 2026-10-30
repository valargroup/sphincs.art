use super::scheme::{
    bits, digest_midstate, forest_marks, fors_marks, randomizer, sign_with_limits,
};
use super::*;

fn config(hash: HashFn, variant: Variant) -> Config {
    Config::new(hash, 20, Shape::Pruned { b: 8 }, variant)
}

#[test]
fn packed_encoding_matches_expanded_digits() {
    fn reference(digest: &Digest) -> Option<[u8; V]> {
        let digits: [u8; V] = std::array::from_fn(|i| (digest[i / 4] >> (2 * (i % 4))) & 3);
        (digits
            .iter()
            .map(|&digit| usize::from(digit))
            .sum::<usize>()
            == TARGET_SUM)
            .then_some(digits)
    }
    let mut accepted = 0;
    for suffix in 0..=u16::MAX {
        let mut digest = [0xaa; N];
        digest[N - 2..].copy_from_slice(&suffix.to_le_bytes());
        for _ in 0..3 {
            let expected = reference(&digest);
            accepted += usize::from(expected.is_some());
            assert_eq!(codeword(&digest), expected);
            digest.rotate_left(8);
        }
    }
    assert!(accepted > 0 && accepted < 3 * 65536);
    for (low_digit, valid) in [(1, false), (2, true), (3, false)] {
        let mut digest = [0xaa; N];
        digest[N - 2..].copy_from_slice(&[3, 3]);
        digest[0] = (digest[0] & !3) | low_digit;
        assert_eq!(
            codeword(&digest).is_some(),
            valid,
            "sum below, at and above the target"
        );
    }
}

#[test]
fn cache_policies_preserve_keys_and_signatures() {
    for hash in HashFn::ALL {
        for variant in Variant::ALL {
            for (h, shape) in [
                (20, Shape::Pruned { b: 8 }),
                (28, Shape::Pruned { b: 8 }),
                (20, Shape::Layered),
            ] {
                let cfg = Config::new(hash, h, shape, variant);
                let seed = [19; 32];
                let before = hash_counts();
                let (full, public) = key_gen(&cfg, &seed);
                let keygen_counts = hash_counts() - before;
                let message = b"cache policy must preserve every signature byte";
                let expected = sign(&full, message).unwrap().to_bytes();
                for levels in [0, 2, cfg.kept()] {
                    let before = hash_counts();
                    let (small, small_public) =
                        key_gen_with_cache(&cfg, &seed, TreeCache::Recompute { levels });
                    assert_eq!(hash_counts() - before, keygen_counts);
                    assert_eq!(small_public, public);
                    let signature = sign(&small, message).unwrap();
                    assert_eq!(signature.to_bytes(), expected, "{cfg:?}, {levels}");
                    verify(&cfg, &public, message, &signature).unwrap();
                }
            }
        }
    }
    let cfg = config(HashFn::Sha2, Variant::Forest);
    assert!(
        std::panic::catch_unwind(|| {
            key_gen_with_cache(&cfg, &[0; 32], TreeCache::Recompute { levels: 9 })
        })
        .is_err()
    );
}

#[test]
fn recomputed_paths_match_full_tree_at_all_offsets() {
    for hash in HashFn::ALL {
        let pp = Pp::new(&config(hash, Variant::Forest), [17; N]);
        let seed = [23; 32];
        for start in [0, 40, 120] {
            let key = OtsKey {
                layer: 1,
                tree: 19,
                leaf: 0,
            };
            let leaves =
                || (start..start + 8).map(|leaf| wots_leaf(&pp, &seed, &OtsKey { leaf, ..key }));
            let full = XmssTree::from_leaves(
                &pp,
                key.layer,
                key.tree,
                7,
                3,
                u64::from(start),
                0,
                leaves(),
                vec![[29; N]; 4],
            );
            for cached_from in 0..=3 {
                let small = XmssTree::from_leaves(
                    &pp,
                    key.layer,
                    key.tree,
                    7,
                    3,
                    u64::from(start),
                    cached_from,
                    leaves(),
                    vec![[29; N]; 4],
                );
                assert_eq!(small.root(), full.root());
                for leaf in start..start + 8 {
                    assert_eq!(
                        small.path(&pp, &seed, u64::from(leaf)),
                        full.path(&pp, &seed, u64::from(leaf))
                    );
                }
            }
        }
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn configuration_sizes_and_rejections() {
    for h in HEIGHTS {
        for hash in HashFn::ALL {
            for variant in Variant::ALL {
                for shape in [Shape::Layered, Shape::Pruned { b: h }]
                    .into_iter()
                    .chain(PRUNED.into_iter().map(|b| Shape::Pruned { b }))
                {
                    let cfg = Config::new(hash, h, shape, variant);
                    assert_eq!(cfg.layers().iter().sum::<usize>(), h);
                    let bytes = vec![0; cfg.sig_size()];
                    assert_eq!(
                        Signature::from_bytes(&cfg, &bytes).unwrap().to_bytes(),
                        bytes
                    );
                    assert!(Signature::from_bytes(&cfg, &bytes[..bytes.len() - 1]).is_none());
                    assert!(Signature::from_bytes(&cfg, &[bytes, vec![0]].concat()).is_none());
                }
            }
        }
    }
    for (variant, pruned, layered) in [
        (Variant::Forest, 9244, 13860),
        (Variant::Fors, 12676, 17292),
    ] {
        assert_eq!(
            Config::new(HashFn::Shake256, 24, Shape::Pruned { b: 12 }, variant).sig_size(),
            pruned
        );
        assert_eq!(
            Config::new(HashFn::Shake256, 24, Shape::Layered, variant).sig_size(),
            layered
        );
    }
    for (h, b) in [(19, 8), (30, 12), (20, 21), (22, 11)] {
        assert!(
            std::panic::catch_unwind(|| Config::new(
                HashFn::Sha2,
                h,
                Shape::Pruned { b },
                Variant::Forest
            ))
            .is_err()
        );
    }
    assert!(PublicKey::from_bytes(&[0; 47]).is_none());
    assert!(PublicKey::from_bytes(&[0; 49]).is_none());
}

#[test]
fn randomizers_and_digest_fields_cross_word_boundaries() {
    assert_eq!(randomizer(&[255; N], &[1; N], 1), {
        let mut x = [1; N];
        x[0] = 0;
        x
    });
    assert_eq!(randomizer(&[0; N], &[255; N], 5), {
        let mut x = [255; N];
        x[0] = 251;
        x
    });
    let mut one = [0; N];
    one[0] = 1;
    let mut expected = [0; N];
    expected[..8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(randomizer(&[0; N], &one, u64::MAX), expected);
    for h in HEIGHTS {
        for pos in 0..h + FORS_TREES * FORS_HEIGHT {
            let mut data = [0; 64];
            data[pos / 8] = 1 << (pos % 8);
            assert_eq!(bits(&data, 0, h), if pos < h { 1 << pos } else { 0 });
            let marks = fors_marks(&data, h);
            for (t, mark) in marks.iter().enumerate() {
                assert_eq!(
                    *mark,
                    if (h + t * 10..h + (t + 1) * 10).contains(&pos) {
                        1 << ((pos - h) % 10)
                    } else {
                        0
                    }
                );
            }
            let marks = forest_marks(&data, h);
            let mut rebuilt = [0; 64];
            let mut put = |offset: usize, width: usize, value: usize| {
                for i in 0..width {
                    rebuilt[(offset + i) / 8] |= (((value >> i) & 1) as u8) << ((offset + i) % 8);
                }
            };
            put(0, h, bits(&data, 0, h));
            for (c, mark) in marks.iter().enumerate() {
                put(h + c * 26, 4, mark.super_child);
                for j in 0..2 {
                    put(h + c * 26 + 4 + j * 11, 3, mark.child[j]);
                    put(h + c * 26 + 7 + j * 11, 8, mark.word[j] as usize);
                }
            }
            if pos < h + COORDS * 26 {
                assert_eq!(rebuilt, data);
            } else {
                assert_eq!(rebuilt, [0; 64]);
            }
        }
    }
}

#[test]
fn seeds_bind_every_configuration_choice() {
    let seed = [42; 32];
    let base = config(HashFn::Shake256, Variant::Forest);
    let root = configured_seed(&base, &seed);
    for cfg in [
        config(HashFn::Sha2, Variant::Forest),
        config(HashFn::Shake256, Variant::Fors),
        Config::new(
            HashFn::Shake256,
            22,
            Shape::Pruned { b: 8 },
            Variant::Forest,
        ),
        Config::new(
            HashFn::Shake256,
            20,
            Shape::Pruned { b: 10 },
            Variant::Forest,
        ),
        Config::new(HashFn::Shake256, 20, Shape::Layered, Variant::Forest),
    ] {
        assert_ne!(configured_seed(&cfg, &seed), root);
    }
    let legacy = crate::Config::new(crate::HashFn::Keccak256, 20, Shape::Pruned { b: 8 });
    assert_ne!(root, crate::configured_seed(&legacy, &seed));
}

#[test]
fn raw_messages_and_tampering() {
    for hash in HashFn::ALL {
        for variant in Variant::ALL {
            let cfg = config(hash, variant);
            let (sk, pk) = key_gen(&cfg, &[3; 32]);
            assert_eq!(PublicKey::from_bytes(&pk.to_bytes()), Some(pk));
            for message in [vec![], vec![0; 32], vec![0; 64], vec![7; 137], vec![8; 257]] {
                let sig = sign(&sk, &message).unwrap();
                assert_eq!(sig, sign(&sk, &message).unwrap());
                let before = hash_counts();
                assert_eq!(verify(&cfg, &pk, &message, &sig), Ok(()));
                assert_eq!(hash_counts() - before, cfg.verify_counts(message.len()));
                let bytes = sig.to_bytes();
                assert_eq!(bytes.len(), cfg.sig_size());
                assert_eq!(Signature::from_bytes(&cfg, &bytes).unwrap(), sig);
                let mut wrong = message.clone();
                wrong.push(0);
                assert!(verify(&cfg, &pk, &wrong, &sig).is_err());
                for offset in [
                    0,
                    N,
                    N + N * 11,
                    N + variant.opening_values() * N,
                    bytes.len() - 1,
                ] {
                    let mut damaged = bytes.clone();
                    damaged[offset] ^= 1;
                    let parsed = Signature::from_bytes(&cfg, &damaged).unwrap();
                    assert!(
                        verify(&cfg, &pk, &message, &parsed).is_err(),
                        "changed byte {offset}"
                    );
                }
                let mut other = pk;
                other.root[0] ^= 1;
                assert!(verify(&cfg, &other, &message, &sig).is_err());
                other = pk;
                other.public_param[0] ^= 1;
                assert!(verify(&cfg, &other, &message, &sig).is_err());
                for other in HashFn::ALL.into_iter().filter(|&x| x != hash) {
                    assert!(verify(&config(other, variant), &pk, &message, &sig).is_err());
                }
                let other = if variant == Variant::Fors {
                    Variant::Forest
                } else {
                    Variant::Fors
                };
                assert_eq!(
                    verify(&config(hash, other), &pk, &message, &sig),
                    Err(VerifyError::Malformed)
                );
            }
            assert_eq!(
                sign_with_limits(&sk, b"message", 0, 0),
                Err(SignError::RandomizerExhausted)
            );
            assert_eq!(
                sign_with_limits(&sk, b"message", MAX_ENCODING_ATTEMPTS, 0),
                Err(SignError::EncodingExhausted)
            );
        }
    }
}

/// This matrix constructs the real trees and crosses both variants with both backends and every height.
#[test]
fn every_height_and_shape_signs_and_verifies() {
    for hash in HashFn::ALL {
        for variant in Variant::ALL {
            for h in HEIGHTS {
                for shape in [Shape::Pruned { b: (h / 2).max(12) }, Shape::Layered] {
                    let cfg = Config::new(hash, h, shape, variant);
                    let (sk, pk) = key_gen(&cfg, &[h as u8; 32]);
                    let sig = sign(&sk, b"full configuration matrix").unwrap();
                    let before = hash_counts();
                    assert_eq!(
                        verify(&cfg, &pk, b"full configuration matrix", &sig),
                        Ok(())
                    );
                    assert_eq!(hash_counts() - before, cfg.verify_counts(25), "{cfg:?}");
                    assert_eq!(sig.to_bytes().len(), cfg.sig_size());
                    for layer in 0..sig.layers.len() {
                        let mut bad = sig.clone();
                        bad.layers[layer].wots[V - 1][N - 1] ^= 1;
                        assert!(verify(&cfg, &pk, b"full configuration matrix", &bad).is_err());
                        let mut bad = sig.clone();
                        bad.layers[layer].path[0][0] ^= 1;
                        assert!(verify(&cfg, &pk, b"full configuration matrix", &bad).is_err());
                    }
                    assert!(
                        verify(
                            &Config::new(hash, if h == 20 { 22 } else { 20 }, shape, variant),
                            &pk,
                            b"full configuration matrix",
                            &sig
                        )
                        .is_err()
                    );
                }
            }
        }
    }
}

#[test]
fn fors_addresses_are_injective() {
    let mut addresses = std::collections::HashSet::new();
    for tree in 0..FORS_TREES {
        for pair in 0..1 << (FORS_HEIGHT - 1) {
            for side in 0..2 {
                assert!(addresses.insert(address(
                    &fors_secret_tweak((1 << 28) - 1, tree, pair).step(side)
                )));
            }
        }
        for leaf in 0..1 << FORS_HEIGHT {
            assert!(addresses.insert(address(&tweak(
                TWEAK_FORS_LEAF,
                ((tree << FORS_HEIGHT) + leaf) as u32,
                (1 << 28) - 1
            ))));
        }
        for level in 0..FORS_HEIGHT - 1 {
            for node in 0..1 << (FORS_HEIGHT - level - 1) {
                assert!(addresses.insert(address(&fors_node_tweak(
                    (1 << 28) - 1,
                    tree,
                    level,
                    node
                ))));
            }
        }
    }
}

#[test]
fn public_key_and_randomizer_binding_are_explicit() {
    let cfg = config(HashFn::Sha2, Variant::Fors);
    let pp = Pp::new(&cfg, [3; N]);
    let pk = PublicKey {
        root: [4; N],
        public_param: [3; N],
    };
    let a = digest_midstate(&pp, &pk, b"x").finish::<64>(&[0; N]);
    assert_ne!(a, digest_midstate(&pp, &pk, b"x\0").finish::<64>(&[0; N]));
    assert_ne!(
        a,
        digest_midstate(&pp, &PublicKey { root: [5; N], ..pk }, b"x").finish::<64>(&[0; N])
    );
}

#[test]
fn hashes_match_independent_python_vectors() {
    for line in include_str!("hash_vectors.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        let hash = if fields[0] == "SHA2" {
            HashFn::Sha2
        } else {
            HashFn::Shake256
        };
        let pp = Pp::new(&config(hash, Variant::Forest), [3; N]);
        let got = match fields[1] {
            "chain" => th(&pp, &tweak(TWEAK_CHAIN, 7, 11).step(2).at(1, 3), &[9; N]).to_vec(),
            "node" => th_digests(&pp, &tweak(TWEAK_NODE, 2, 3), &[[4; N], [5; N]]).to_vec(),
            "pair" => th_pair(&pp, &tweak(TWEAK_PRF, 3, 7), &[11; 32])
                .as_flattened()
                .to_vec(),
            "randomizer" => randomizer_material(&pp, &[13; 32], b"raw message\0bytes").to_vec(),
            _ => panic!("unknown vector"),
        };
        assert_eq!(hex(&got), fields[2], "{} {}", fields[0], fields[1]);
    }
}

#[test]
fn signatures_match_independently_verified_vectors() {
    use sha2::{Digest as _, Sha512};
    for line in include_str!("signature_vectors.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        let hash = if fields[0] == "SHA2" {
            HashFn::Sha2
        } else {
            HashFn::Shake256
        };
        let variant = if fields[1] == "fors" {
            Variant::Fors
        } else {
            Variant::Forest
        };
        let cfg = config(hash, variant);
        let (sk, pk) = key_gen(&cfg, &[3; 32]);
        let sig = sign(&sk, b"independent 192-bit reference\0message").unwrap();
        assert_eq!(hex(&pk.to_bytes()), fields[2]);
        assert_eq!(hex(&Sha512::digest(sig.to_bytes())), fields[3]);
    }
}

#[test]
fn streamed_forest_openings_cover_every_branch() {
    for hash in HashFn::ALL {
        let pp = Pp::new(&config(hash, Variant::Forest), [17; N]);
        let idx = (1 << 28) - 1;
        #[cfg(feature = "forest-precompute")]
        let caches: Vec<_> = (0..TOP_HEIGHT)
            .map(|level| {
                let mut nodes = Vec::new();
                precompute_instance(&pp, &[29; 32], idx, level, &mut nodes);
                nodes
            })
            .collect();
        let mut expected = None;
        for selected in 0..forest::SUPERS {
            let marks = std::array::from_fn(|c| CoordMark {
                super_child: selected,
                child: [
                    (c + selected) % forest::CHILDREN,
                    (c + selected + 3) % forest::CHILDREN,
                ],
                word: [
                    (selected * 17 + c * 19) as u8,
                    (255 - selected * 11 - c * 3) as u8,
                ],
            });
            #[cfg(feature = "forest-precompute")]
            let before = hash_counts();
            let (key, opening) = forest_sign(&pp, &[29; 32], idx, &marks);
            #[cfg(feature = "forest-precompute")]
            let full_counts = hash_counts() - before;
            assert_eq!(forest_recover(&pp, idx, &marks, &opening), key);
            #[cfg(feature = "forest-precompute")]
            for (level, nodes) in caches.iter().enumerate() {
                let before = hash_counts();
                let (cached_key, cached_opening) =
                    forest_sign_precomputed(&pp, &[29; 32], idx, &marks, Some((level, nodes)));
                let cached_counts = hash_counts() - before;
                assert_eq!(cached_key, key);
                assert_eq!(
                    cached_opening, opening,
                    "{hash:?}, level {level}, selected {selected}"
                );
                if hash == HashFn::Sha2 {
                    assert_eq!(
                        full_counts - cached_counts,
                        HashCounts {
                            sha256: [172800, 161280, 138240, 92160][level],
                            sha512: [8280, 7812, 6732, 4500][level],
                            keccak: 0,
                        }
                    );
                }
            }
            if let Some(previous) = expected {
                assert_eq!(
                    key, previous,
                    "the selected opening must not change the key"
                );
            }
            expected = Some(key);
        }
    }
}

#[test]
#[cfg(feature = "forest-precompute")]
fn prepared_forest_matches_normal_signing_and_checks_its_budget() {
    for hash in HashFn::ALL {
        let cfg = config(hash, Variant::Forest);
        let (secret, public) =
            key_gen_with_cache(&cfg, &[3; 32], TreeCache::Recompute { levels: 2 });
        let message = b"independent 192-bit reference\0message";
        let expected = sign(&secret, message).unwrap().to_bytes();
        for (level, bytes) in [(0, 1179648), (3, 147456)] {
            let before = hash_counts();
            assert!(matches!(prepare_forest(&secret, level, bytes - 1),
                Err(ForestPrecomputeError::CacheBudgetExceeded { required_bytes }) if required_bytes == bytes));
            assert_eq!(
                hash_counts(),
                before,
                "budget failures must precede preparation"
            );
            let prepared = prepare_forest(&secret, level, bytes).unwrap();
            let setup = hash_counts() - before;
            if hash == HashFn::Sha2 {
                assert_eq!(
                    setup,
                    HashCounts {
                        sha256: 47185920,
                        sha512: if level == 0 { 2260992 } else { 2304000 },
                        keccak: 0
                    }
                );
            }
            assert_eq!(prepared.cache_bytes(), bytes);
            let signature = prepared.sign(message).unwrap();
            assert_eq!(signature.to_bytes(), expected);
            verify(&cfg, &public, message, &signature).unwrap();
            assert!(verify(&cfg, &public, b"changed", &signature).is_err());
        }
        assert!(matches!(
            prepare_forest(&secret, TOP_HEIGHT, usize::MAX),
            Err(ForestPrecomputeError::InvalidLevel)
        ));
    }
    for cfg in [
        config(HashFn::Sha2, Variant::Fors),
        Config::new(HashFn::Sha2, 20, Shape::Layered, Variant::Forest),
    ] {
        let (secret, _) = key_gen(&cfg, &[3; 32]);
        assert!(matches!(
            prepare_forest(&secret, 0, usize::MAX),
            Err(ForestPrecomputeError::UnsupportedConfiguration)
        ));
    }
}

#[test]
fn streamed_layer_paths_match_the_cached_tree() {
    for hash in HashFn::ALL {
        let pp = Pp::new(&config(hash, Variant::Forest), [17; N]);
        for height in [0, 1, 3, 9] {
            let key = OtsKey {
                layer: 1,
                tree: 19,
                leaf: 0,
            };
            let leaves =
                (0..1u32 << height).map(|leaf| wots_leaf(&pp, &[23; 32], &OtsKey { leaf, ..key }));
            let reference = XmssTree::from_leaves(
                &pp,
                key.layer,
                key.tree,
                height,
                height,
                0,
                0,
                leaves,
                Vec::new(),
            );
            let selected: Vec<_> = if height <= 3 {
                (0..1u32 << height).collect()
            } else {
                vec![
                    0,
                    1,
                    (1 << (height - 1)) - 1,
                    1 << (height - 1),
                    (1 << height) - 2,
                    (1 << height) - 1,
                ]
            };
            for leaf in selected {
                let (root, path) = layer_path(&pp, &[23; 32], &OtsKey { leaf, ..key }, height);
                assert_eq!(root, reference.root());
                assert_eq!(path, reference.path(&pp, &[23; 32], u64::from(leaf)));
            }
        }
    }
}

#[test]
fn signature_writer_handles_short_writes_and_errors() {
    use std::io::{self, Write};
    struct ShortWriter(Vec<u8>);
    impl Write for ShortWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = bytes.len().min(7);
            self.0.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct FailingWriter;
    impl Write for FailingWriter {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::ErrorKind::BrokenPipe.into())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    for variant in Variant::ALL {
        for shape in [Shape::Pruned { b: 8 }, Shape::Layered] {
            let cfg = Config::new(HashFn::Sha2, 20, shape, variant);
            let expected: Vec<_> = (0..cfg.sig_size()).map(|i| i as u8).collect();
            let signature = Signature::from_bytes(&cfg, &expected).unwrap();
            assert_eq!(signature.encoded_len(), expected.len());
            let mut writer = ShortWriter(Vec::new());
            signature.write_to(&mut writer).unwrap();
            assert_eq!(writer.0, expected);
            let mut small_buffer = [0; N - 1];
            assert_eq!(
                signature
                    .write_to(&mut small_buffer.as_mut_slice())
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::WriteZero
            );
            assert_eq!(
                signature.write_to(&mut FailingWriter).unwrap_err().kind(),
                io::ErrorKind::BrokenPipe
            );
        }
    }
}
