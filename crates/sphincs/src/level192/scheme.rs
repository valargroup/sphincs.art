//! Key generation, raw-message signing, verification and exact-length serialization.
use super::*;

#[cfg(feature = "forest-precompute")]
mod prepared;
#[cfg(feature = "forest-precompute")]
pub use prepared::{ForestPrecomputeError, PreparedForest, prepare_forest};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub root: Digest,
    pub public_param: PublicParam,
}
impl PublicKey {
    pub fn to_bytes(&self) -> [u8; PUB_KEY_SIZE] {
        let mut bytes = [0; PUB_KEY_SIZE];
        bytes[..N].copy_from_slice(&self.root);
        bytes[N..].copy_from_slice(&self.public_param);
        bytes
    }
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != PUB_KEY_SIZE {
            return None;
        }
        Some(Self {
            root: bytes[..N].try_into().ok()?,
            public_param: bytes[N..].try_into().ok()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Opening {
    Forest(Box<ForestOpening>),
    Fors(Box<[ForsOpening; FORS_TREES]>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LayerSignature {
    pub counter: u32,
    pub wots: [Digest; V],
    pub path: Vec<Digest>,
}

/// A signature's family, hash and configuration are supplied out of band to the verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub(super) randomizer: Randomizer,
    pub(super) opening: Opening,
    pub(super) layers: Vec<LayerSignature>,
}
impl Signature {
    /// Exact serialized length, including the randomizer, opening and every authenticated layer.
    pub fn encoded_len(&self) -> usize {
        let opening_values = match &self.opening {
            Opening::Forest(_) => Variant::Forest.opening_values(),
            Opening::Fors(_) => Variant::Fors.opening_values(),
        };
        N + opening_values * N
            + self
                .layers
                .iter()
                .map(|layer| COUNTER_LEN + V * N + layer.path.len() * N)
                .sum::<usize>()
    }

    /// Writes the existing wire format without allocating a second signature buffer.
    /// A writer error is returned unchanged; the destination may already contain a partial signature.
    pub fn write_to<W: std::io::Write + ?Sized>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.randomizer)?;
        match &self.opening {
            Opening::Forest(open) => {
                for coord in open.iter() {
                    for sub in &coord.sub {
                        writer.write_all(sub.values.as_flattened())?;
                        writer.write_all(sub.path.as_flattened())?;
                    }
                    writer.write_all(coord.top.as_flattened())?;
                }
            }
            Opening::Fors(open) => {
                for tree in open.iter() {
                    writer.write_all(&tree.secret)?;
                    writer.write_all(tree.path.as_flattened())?;
                }
            }
        }
        for layer in &self.layers {
            writer.write_all(&layer.counter.to_le_bytes())?;
            writer.write_all(layer.wots.as_flattened())?;
            writer.write_all(layer.path.as_flattened())?;
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.encoded_len());
        self.write_to(&mut out)
            .expect("writing to a Vec cannot fail");
        out
    }
    pub fn from_bytes(cfg: &Config, bytes: &[u8]) -> Option<Self> {
        if bytes.len() != cfg.sig_size() {
            return None;
        }
        let mut at = 0;
        let mut take = |n| {
            let start = at;
            at += n;
            &bytes[start..at]
        };
        let randomizer = take(N).try_into().ok()?;
        let opening = match cfg.variant {
            Variant::Forest => Opening::Forest(Box::new(std::array::from_fn(|_| CoordOpening {
                sub: std::array::from_fn(|_| SubOpening {
                    values: std::array::from_fn(|_| take(N).try_into().unwrap()),
                    path: std::array::from_fn(|_| take(N).try_into().unwrap()),
                }),
                top: std::array::from_fn(|_| take(N).try_into().unwrap()),
            }))),
            Variant::Fors => Opening::Fors(Box::new(std::array::from_fn(|_| ForsOpening {
                secret: take(N).try_into().unwrap(),
                path: std::array::from_fn(|_| take(N).try_into().unwrap()),
            }))),
        };
        let layers = cfg
            .layers()
            .iter()
            .map(|&height| LayerSignature {
                counter: u32::from_le_bytes(take(4).try_into().unwrap()),
                wots: std::array::from_fn(|_| take(N).try_into().unwrap()),
                path: (0..height).map(|_| take(N).try_into().unwrap()).collect(),
            })
            .collect();
        Some(Self {
            randomizer,
            opening,
            layers,
        })
    }
}

#[derive(Clone)]
pub struct SecretKey {
    cfg: Config,
    pp: Pp,
    master: MasterSecret,
    top: XmssTree,
}
impl SecretKey {
    pub fn cfg(&self) -> &Config {
        &self.cfg
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            root: self.top.root(),
            public_param: self.pp.bytes(),
        }
    }
}

/// Binds the family and all key-generation choices before deriving any one-time secrets.
pub fn configured_seed(cfg: &Config, seed: &MasterSecret) -> MasterSecret {
    let (shape, b) = match cfg.shape {
        Shape::Pruned { b } => (0, b),
        Shape::Layered => (1, cfg.h),
    };
    seed_hash(
        cfg.hash,
        &[
            DOMAIN,
            b" configured seed",
            &[cfg.hash.id(), cfg.variant.id(), cfg.h as u8, shape, b as u8],
            seed,
        ],
    )
}
/// Controls retained tree memory without changing keys, signatures, or signing-use limits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TreeCache {
    /// Retain every node of the kept subtree for signing without leaf recomputation.
    #[default]
    Full,
    /// Omit the bottom `levels` of nodes and regenerate their authentication paths when signing.
    /// Each signature regenerates `2^levels` leaves; `levels` must not exceed the kept height.
    Recompute { levels: usize },
}

pub fn key_gen(cfg: &Config, seed: &MasterSecret) -> (SecretKey, PublicKey) {
    key_gen_with_cache(cfg, seed, TreeCache::Full)
}

/// Generates the same key as `key_gen`, retaining only the requested tree nodes.
/// The cache policy is an implementation choice and is deliberately absent from seed derivation.
/// Panics if the omitted levels exceed the configuration's kept height.
pub fn key_gen_with_cache(
    cfg: &Config,
    seed: &MasterSecret,
    cache: TreeCache,
) -> (SecretKey, PublicKey) {
    let uncached_levels = match cache {
        TreeCache::Full => 0,
        TreeCache::Recompute { levels } => levels,
    };
    assert!(uncached_levels <= cfg.kept(), "cache exceeds kept height");
    let master = configured_seed(cfg, seed);
    let public_param = th(
        &Pp::new(cfg, [0; N]),
        &tweak(TWEAK_PARAMETER, 0, 0),
        &master,
    );
    let pp = Pp::new(cfg, public_param);
    let layers = cfg.layers();
    let (layer, height, b) = (layers.len() - 1, *layers.last().unwrap(), cfg.kept());
    let start = (u64::from_le_bytes(public_param[..8].try_into().unwrap())
        & ((1 << (height - b)) - 1))
        << b;
    let leaves = (0..1u64 << b).map(|j| {
        wots_leaf(
            &pp,
            &master,
            &OtsKey {
                layer,
                tree: 0,
                leaf: (start + j) as u32,
            },
        )
    });
    let surrogates = (b..height)
        .map(|level| th(&pp, &tweak(TWEAK_SURROGATE, level as u32, 0), &master))
        .collect();
    let top = XmssTree::from_leaves(
        &pp,
        layer,
        0,
        height,
        b,
        start,
        uncached_levels,
        leaves,
        surrogates,
    );
    let sk = SecretKey {
        cfg: *cfg,
        pp,
        master,
        top,
    };
    let pk = sk.public_key();
    (sk, pk)
}

/// A length-delimited raw message and the entire public key are bound before the randomizer.
pub(super) fn digest_midstate(pp: &Pp, pk: &PublicKey, message: &[u8]) -> Midstate {
    Midstate::new(
        pp,
        &tweak(TWEAK_MSG, 0, 0),
        &[
            &pk.to_bytes(),
            &(message.len() as u64).to_le_bytes(),
            message,
        ],
    )
}
pub(super) fn bits(digest: &[u8], offset: usize, width: usize) -> usize {
    assert!(width <= 32 && offset + width <= digest.len() * 8);
    (0..width).fold(0, |n, i| {
        n | (usize::from((digest[(offset + i) / 8] >> ((offset + i) % 8)) & 1) << i)
    })
}
pub(super) fn forest_marks(digest: &[u8; 64], h: usize) -> [CoordMark; COORDS] {
    std::array::from_fn(|c| {
        let base = h + c * 26;
        CoordMark {
            super_child: bits(digest, base, 4),
            child: std::array::from_fn(|j| bits(digest, base + 4 + j * 11, 3)),
            word: std::array::from_fn(|j| bits(digest, base + 7 + j * 11, 8) as u8),
        }
    })
}
pub(super) fn fors_marks(digest: &[u8; 64], h: usize) -> [usize; FORS_TREES] {
    std::array::from_fn(|t| bits(digest, h + t * FORS_HEIGHT, FORS_HEIGHT))
}

/// Addition of `i * step` modulo 2^192. The bytewise carry also covers 64-bit attempt indices.
pub(super) fn randomizer(base: &Randomizer, step: &Randomizer, i: u64) -> Randomizer {
    let mut carry = 0u128;
    std::array::from_fn(|j| {
        let sum = u128::from(base[j]) + u128::from(step[j]) * u128::from(i) + carry;
        carry = sum >> 8;
        sum as u8
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignError {
    RandomizerExhausted,
    EncodingExhausted,
}

/// Signs raw message bytes deterministically, without preparing or allocating a public forest cache.
/// Signature-use limits are the caller's responsibility.
pub fn sign(sk: &SecretKey, message: &[u8]) -> Result<Signature, SignError> {
    sign_with_limits(sk, message, MAX_ENCODING_ATTEMPTS, MAX_ENCODING_ATTEMPTS)
}
pub(super) fn sign_with_limits(
    sk: &SecretKey,
    message: &[u8],
    randomizer_limit: u64,
    encoding_limit: u64,
) -> Result<Signature, SignError> {
    sign_with_precomputed(
        sk,
        message,
        randomizer_limit,
        encoding_limit,
        #[cfg(feature = "forest-precompute")]
        None,
    )
}

fn sign_with_precomputed(
    sk: &SecretKey,
    message: &[u8],
    randomizer_limit: u64,
    encoding_limit: u64,
    #[cfg(feature = "forest-precompute")] prepared: Option<&PreparedForest<'_>>,
) -> Result<Signature, SignError> {
    let (cfg, pp) = (&sk.cfg, &sk.pp);
    let layers = cfg.layers();
    let top = layers.len() - 1;
    let material = randomizer_material(pp, &sk.master, message);
    let base: Randomizer = material[..N].try_into().unwrap();
    let mut step: Randomizer = material[N..].try_into().unwrap();
    step[0] |= 1;
    let state = digest_midstate(pp, &sk.public_key(), message);
    let (rho, digest, idx) = (0..randomizer_limit)
        .find_map(|i| {
            let rho = randomizer(&base, &step, i);
            let digest = state.finish::<64>(&rho);
            let idx = bits(&digest, 0, cfg.h) as u64;
            sk.top
                .contains(idx >> cfg.below(top))
                .then_some((rho, digest, idx))
        })
        .ok_or(SignError::RandomizerExhausted)?;
    let (opening, mut payload) = match cfg.variant {
        Variant::Forest => {
            let marks = forest_marks(&digest, cfg.h);
            #[cfg(feature = "forest-precompute")]
            let (key, opening) = if let Some(prepared) = prepared {
                forest_sign_precomputed(pp, &sk.master, idx, &marks, Some(prepared.instance(idx)))
            } else {
                forest_sign(pp, &sk.master, idx, &marks)
            };
            #[cfg(not(feature = "forest-precompute"))]
            let (key, opening) = forest_sign(pp, &sk.master, idx, &marks);
            (
                Opening::Forest(opening),
                key.as_flattened().as_flattened().to_vec(),
            )
        }
        Variant::Fors => {
            let (key, opening) = fors_sign(pp, &sk.master, idx, &fors_marks(&digest, cfg.h));
            (
                Opening::Fors(opening),
                key.as_flattened().as_flattened().to_vec(),
            )
        }
    };
    let mut signed = Vec::with_capacity(layers.len());
    for (layer, &height) in layers.iter().enumerate() {
        let key = OtsKey::at(layer, height, idx >> cfg.below(layer));
        let (counter, wots) = wots_sign_limited(pp, &sk.master, &key, &payload, encoding_limit)
            .ok_or(SignError::EncodingExhausted)?;
        let path = if layer == top {
            sk.top.path(pp, &sk.master, u64::from(key.leaf))
        } else {
            let (root, path) = layer_path(pp, &sk.master, &key, height);
            payload = root.to_vec();
            path
        };
        signed.push(LayerSignature {
            counter,
            wots,
            path,
        });
    }
    Ok(Signature {
        randomizer: rho,
        opening,
        layers: signed,
    })
}

pub fn verify(
    cfg: &Config,
    pk: &PublicKey,
    message: &[u8],
    sig: &Signature,
) -> Result<(), VerifyError> {
    let layers = cfg.layers();
    if sig.layers.len() != layers.len()
        || sig
            .layers
            .iter()
            .zip(&layers)
            .any(|(s, &h)| s.path.len() != h)
    {
        return Err(VerifyError::Malformed);
    }
    let pp = Pp::new(cfg, pk.public_param);
    let digest = digest_midstate(&pp, pk, message).finish::<64>(&sig.randomizer);
    let idx = bits(&digest, 0, cfg.h) as u64;
    let mut payload = match (&sig.opening, cfg.variant) {
        (Opening::Forest(open), Variant::Forest) => {
            forest_recover(&pp, idx, &forest_marks(&digest, cfg.h), open)
                .as_flattened()
                .as_flattened()
                .to_vec()
        }
        (Opening::Fors(open), Variant::Fors) => {
            fors_recover(&pp, idx, &fors_marks(&digest, cfg.h), open)
                .as_flattened()
                .as_flattened()
                .to_vec()
        }
        _ => return Err(VerifyError::Malformed),
    };
    for (layer, signed) in sig.layers.iter().enumerate() {
        let key = OtsKey::at(layer, layers[layer], idx >> cfg.below(layer));
        let leaf = wots_recover(&pp, &key, &payload, signed.counter, &signed.wots)
            .ok_or(VerifyError::InadmissibleEncoding)?;
        payload = tree_fold(&pp, &key, leaf, &signed.path).to_vec();
    }
    if payload == pk.root {
        Ok(())
    } else {
        Err(VerifyError::RootMismatch)
    }
}
