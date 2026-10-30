//! Typed hash domains and operation accounting for the experimental family.
//!
//! Every addressed input is DOMAIN || variant || P || address || payload. The fixed-size fields
//! and the length of raw messages make the transcript unambiguous. SHA2 uses SHA-256 for secret
//! derivation and chain/leaf steps, SHA-512 for multi-node hashes and encodings. These are the
//! Category 3 primitive choices, not a claim to implement the SLH-DSA transcript.

use super::*;
use core::ops::{Add, AddAssign, Mul, Sub};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest as ShaDigest, Sha256, Sha512};
use shake::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};
#[cfg(any(test, feature = "hash-counts"))]
use std::cell::Cell;

pub(crate) const DOMAIN: &[u8] = b"leanSPHINCS-192-v1";
pub(crate) const PREFIX_LEN: usize = DOMAIN.len() + 1 + N + 16;
pub(crate) use crate::{
    TWEAK_CHAIN, TWEAK_CHILD_LEAF, TWEAK_ENC, TWEAK_FCHAIN, TWEAK_FOREST_PRF, TWEAK_LEAF,
    TWEAK_MSG, TWEAK_NODE, TWEAK_PARAMETER, TWEAK_PRF, TWEAK_RANDOMIZER, TWEAK_SUB_NODE,
    TWEAK_SUPER_CHILD, TWEAK_SURROGATE, TWEAK_TOP_NODE,
};
pub(crate) const TWEAK_FORS_PRF: u8 = 20;
pub(crate) const TWEAK_FORS_LEAF: u8 = 21;
pub(crate) const TWEAK_FORS_NODE: u8 = 22;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashFn {
    Shake256,
    Sha2,
}

impl HashFn {
    pub const ALL: [Self; 2] = [Self::Shake256, Self::Sha2];
    pub const fn name(self) -> &'static str {
        match self {
            Self::Shake256 => "SHAKE256",
            Self::Sha2 => "SHA2",
        }
    }
    pub(crate) const fn id(self) -> u8 {
        match self {
            Self::Shake256 => 0,
            Self::Sha2 => 1,
        }
    }
}

/// Logical primitive operations, including setup, final padding and SHAKE squeezing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HashCounts {
    pub sha256: u64,
    pub sha512: u64,
    pub keccak: u64,
}
impl AddAssign for HashCounts {
    fn add_assign(&mut self, rhs: Self) {
        self.sha256 += rhs.sha256;
        self.sha512 += rhs.sha512;
        self.keccak += rhs.keccak;
    }
}
impl Add for HashCounts {
    type Output = Self;
    fn add(mut self, rhs: Self) -> Self {
        self += rhs;
        self
    }
}
impl Sub for HashCounts {
    type Output = Self;
    fn sub(self, r: Self) -> Self {
        Self {
            sha256: self.sha256 - r.sha256,
            sha512: self.sha512 - r.sha512,
            keccak: self.keccak - r.keccak,
        }
    }
}
impl Mul<u64> for HashCounts {
    type Output = Self;
    fn mul(self, n: u64) -> Self {
        Self {
            sha256: self.sha256 * n,
            sha512: self.sha512 * n,
            keccak: self.keccak * n,
        }
    }
}
#[cfg(any(test, feature = "hash-counts"))]
thread_local! { static COUNTS: Cell<HashCounts> = const { Cell::new(HashCounts { sha256:0, sha512:0, keccak:0 }) }; }
/// Returns diagnostic operations on this thread; available with the `hash-counts` feature.
#[cfg(any(test, feature = "hash-counts"))]
pub fn hash_counts() -> HashCounts {
    COUNTS.with(Cell::get)
}
#[cfg(any(test, feature = "hash-counts"))]
fn count(n: HashCounts) {
    COUNTS.with(|c| c.set(c.get() + n));
}
#[cfg(not(any(test, feature = "hash-counts")))]
#[inline]
fn count(_: HashCounts) {}

#[derive(Clone, Copy)]
pub(crate) enum Primitive {
    Small,
    Wide,
}

fn cost(hash: HashFn, kind: Primitive, len: usize, output: usize) -> HashCounts {
    match (hash, kind) {
        (HashFn::Shake256, _) => HashCounts {
            keccak: (len / 136 + 1 + output.saturating_sub(1) / 136) as u64,
            ..Default::default()
        },
        (HashFn::Sha2, Primitive::Small) => HashCounts {
            sha256: (len + 9).div_ceil(64) as u64,
            ..Default::default()
        },
        (HashFn::Sha2, Primitive::Wide) => HashCounts {
            sha512: (len + 17).div_ceil(128) as u64,
            ..Default::default()
        },
    }
}
pub(crate) fn operation_cost(
    hash: HashFn,
    kind: Primitive,
    payload: usize,
    output: usize,
) -> HashCounts {
    cost(hash, kind, PREFIX_LEN + payload, output)
}
fn kind(tw: &Tweak) -> Primitive {
    match address(tw)[7] & 31 {
        TWEAK_PRF | TWEAK_FOREST_PRF | TWEAK_FORS_PRF | TWEAK_CHAIN | TWEAK_FCHAIN
        | TWEAK_FORS_LEAF => Primitive::Small,
        _ => Primitive::Wide,
    }
}

#[derive(Clone)]
pub(crate) struct Pp {
    hash: HashFn,
    variant: Variant,
    bytes: PublicParam,
}
impl Pp {
    pub(crate) fn new(cfg: &Config, bytes: PublicParam) -> Self {
        Self {
            hash: cfg.hash,
            variant: cfg.variant,
            bytes,
        }
    }
    pub(crate) fn bytes(&self) -> PublicParam {
        self.bytes
    }
}

#[derive(Clone)]
enum State {
    Small(Sha256),
    Wide(Sha512),
    Shake(Shake256),
}
impl State {
    fn new(hash: HashFn, kind: Primitive) -> Self {
        match (hash, kind) {
            (HashFn::Shake256, _) => Self::Shake(Shake256::default()),
            (HashFn::Sha2, Primitive::Small) => Self::Small(Sha256::new()),
            (HashFn::Sha2, Primitive::Wide) => Self::Wide(Sha512::new()),
        }
    }
    fn update(&mut self, bytes: &[u8]) {
        match self {
            Self::Small(h) => ShaDigest::update(h, bytes),
            Self::Wide(h) => ShaDigest::update(h, bytes),
            Self::Shake(h) => Update::update(h, bytes),
        }
    }
    fn finish<const L: usize>(self) -> [u8; L] {
        let mut out = [0; L];
        match self {
            Self::Small(h) => out.copy_from_slice(&h.finalize()[..L]),
            Self::Wide(h) => out.copy_from_slice(&h.finalize()[..L]),
            Self::Shake(h) => h.finalize_xof().read(&mut out),
        }
        out
    }
}

/// Packs the fixed-width addressed transcript before handing it to the hash provider.
fn addressed_prefix(pp: &Pp, tw: &Tweak) -> [u8; PREFIX_LEN] {
    let mut prefix = [0; PREFIX_LEN];
    prefix[..DOMAIN.len()].copy_from_slice(DOMAIN);
    prefix[DOMAIN.len()] = pp.variant.id();
    prefix[DOMAIN.len() + 1..PREFIX_LEN - 16].copy_from_slice(&pp.bytes);
    prefix[PREFIX_LEN - 16..].copy_from_slice(&address(tw));
    prefix
}

/// Hashes a single addressed payload without cloning a state intended for repeated searches.
fn addressed_hash<const L: usize>(pp: &Pp, tw: &Tweak, payload: &[u8]) -> [u8; L] {
    let kind = kind(tw);
    let mut state = State::new(pp.hash, kind);
    state.update(&addressed_prefix(pp, tw));
    state.update(payload);
    count(cost(pp.hash, kind, PREFIX_LEN + payload.len(), L));
    state.finish()
}

/// A cached prefix: accounting charges whole input blocks once, and each completed tail separately.
#[derive(Clone)]
pub(crate) struct Midstate {
    state: State,
    hash: HashFn,
    kind: Primitive,
    rest: usize,
}
impl Midstate {
    pub(crate) fn new(pp: &Pp, tw: &Tweak, parts: &[&[u8]]) -> Self {
        let kind = kind(tw);
        let mut state = State::new(pp.hash, kind);
        state.update(&addressed_prefix(pp, tw));
        let mut len = PREFIX_LEN;
        for part in parts {
            state.update(part);
            len += part.len();
        }
        let block = match (pp.hash, kind) {
            (HashFn::Shake256, _) => 136,
            (HashFn::Sha2, Primitive::Small) => 64,
            _ => 128,
        };
        let whole = (len / block) as u64;
        count(match (pp.hash, kind) {
            (HashFn::Shake256, _) => HashCounts {
                keccak: whole,
                ..Default::default()
            },
            (HashFn::Sha2, Primitive::Small) => HashCounts {
                sha256: whole,
                ..Default::default()
            },
            _ => HashCounts {
                sha512: whole,
                ..Default::default()
            },
        });
        Self {
            state,
            hash: pp.hash,
            kind,
            rest: len % block,
        }
    }
    pub(crate) fn finish<const L: usize>(&self, tail: &[u8]) -> [u8; L] {
        count(cost(self.hash, self.kind, self.rest + tail.len(), L));
        let mut h = self.state.clone();
        h.update(tail);
        h.finish()
    }
}

pub(crate) fn th(pp: &Pp, tw: &Tweak, payload: &[u8]) -> Digest {
    addressed_hash(pp, tw, payload)
}
pub(crate) fn th_digests(pp: &Pp, tw: &Tweak, values: &[Digest]) -> Digest {
    addressed_hash(pp, tw, values.as_flattened())
}

/// SHAKE can emit a pair directly; SHA-256 derives the two 24-byte secrets at distinct addresses.
pub(crate) fn th_pair(pp: &Pp, tw: &Tweak, payload: &[u8]) -> [Digest; 2] {
    match pp.hash {
        HashFn::Shake256 => {
            let out: [u8; 48] = addressed_hash(pp, tw, payload);
            [out[..N].try_into().unwrap(), out[N..].try_into().unwrap()]
        }
        HashFn::Sha2 => [th(pp, &tw.step(0), payload), th(pp, &tw.step(1), payload)],
    }
}

/// Derivation outside an addressed call, used only to bind the master seed to its configuration.
pub(crate) fn seed_hash(hash: HashFn, parts: &[&[u8]]) -> MasterSecret {
    let mut h = State::new(hash, Primitive::Wide);
    for part in parts {
        h.update(part);
    }
    count(cost(
        hash,
        Primitive::Wide,
        parts.iter().map(|p| p.len()).sum(),
        32,
    ));
    h.finish()
}

/// Secret deterministic start and odd step. HMAC avoids a secret-prefix SHA2 MAC on raw messages.
pub(crate) fn randomizer_material(pp: &Pp, seed: &MasterSecret, message: &[u8]) -> [u8; 48] {
    let addr = address(&tweak(TWEAK_RANDOMIZER, 0, 0));
    let len = (message.len() as u64).to_le_bytes();
    let parts: [&[u8]; 6] = [DOMAIN, &[pp.variant.id()], &pp.bytes, &addr, &len, message];
    match pp.hash {
        HashFn::Sha2 => {
            let mut h = Hmac::<Sha512>::new_from_slice(seed).expect("HMAC accepts any key length");
            for part in parts {
                Mac::update(&mut h, part);
            }
            // 128-byte ipad and opad, inner padding, and a 64-byte inner result.
            let bytes: usize = parts.iter().map(|p| p.len()).sum();
            count(HashCounts {
                sha512: 1 + (bytes + 17).div_ceil(128) as u64 + 2,
                ..Default::default()
            });
            h.finalize().into_bytes()[..48].try_into().unwrap()
        }
        HashFn::Shake256 => {
            let mut h = State::new(pp.hash, Primitive::Wide);
            h.update(seed);
            for part in parts {
                h.update(part);
            }
            count(cost(
                pp.hash,
                Primitive::Wide,
                32 + parts.iter().map(|p| p.len()).sum::<usize>(),
                48,
            ));
            h.finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primitive_backends_match_published_nist_vectors() {
        // NIST's "abc" samples, including the full primitive outputs before truncation:
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA256.pdf
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512.pdf
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
        let mut small = State::new(HashFn::Sha2, Primitive::Small);
        small.update(b"abc");
        assert_eq!(
            hex(&small.finish::<32>()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let mut wide = State::new(HashFn::Sha2, Primitive::Wide);
        wide.update(b"abc");
        assert_eq!(
            hex(&wide.finish::<64>()),
            concat!(
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a",
                "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
            )
        );
        // First 192 output bytes of NIST's empty-message SHAKE256 sample. This crosses the
        // 136-byte rate boundary, exercising an additional squeeze permutation.
        // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHAKE256_Msg0.pdf
        let shake = State::new(HashFn::Shake256, Primitive::Wide);
        assert_eq!(
            hex(&shake.finish::<192>()),
            concat!(
                "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
                "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be",
                "141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853",
                "349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86",
                "f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d6",
                "77231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5c"
            )
        );
        assert_eq!(cost(HashFn::Shake256, Primitive::Wide, 0, 192).keccak, 2);
    }
}
