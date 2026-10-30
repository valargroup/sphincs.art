//! Experimental 24-byte leanSphincs, targeting the Category 3 convention.
//!
//! These are not SLH-DSA parameter sets. The 128-bit family's Lean proofs do not apply here.
//! Callers must assess the documented attack models and signature-use limits before use.
//! The forest and FORS variants share the same WOTS+C, Merkle, and signing implementation.

mod forest;
mod fors;
mod hashing;
mod scheme;
mod tree;
mod wots;

pub use crate::{HEIGHTS, OtsKey, PRUNED, Shape, VerifyError};
use crate::{Tweak, address, codeword_table, layered_heights, tweak};
use forest::*;
use fors::*;
use hashing::*;
pub use hashing::{HashCounts, HashFn, hash_counts};
pub use scheme::{
    PublicKey, SecretKey, SignError, Signature, TreeCache, configured_seed, key_gen,
    key_gen_with_cache, sign, verify,
};
use tree::*;
use wots::*;

pub const N: usize = 24;
pub const V: usize = 96;
pub const TARGET_SUM: usize = 182;
pub const COORDS: usize = 12;
pub const FORS_TREES: usize = 37;
pub const FORS_HEIGHT: usize = 10;
pub const PUB_KEY_SIZE: usize = 48;
pub const MASTER_SECRET_LEN: usize = 32;
pub const RANDOMIZER_LEN: usize = N;
pub const COUNTER_LEN: usize = 4;
pub const MAX_ENCODING_ATTEMPTS: u64 = 1 << 32;
pub const W: usize = 2;
pub const CHAIN_LEN: usize = 4;
pub const TOP_HEIGHT: usize = 4;
pub const SUBS: usize = 2;
pub const SUB_HEIGHT: usize = 3;
pub const CHILD_CHAINS: usize = 6;
pub const CHAIN_TOP: usize = 4;
pub const CODEWORD_SUM: usize = 5;
pub type Digest = [u8; N];
pub type MasterSecret = [u8; MASTER_SECRET_LEN];
pub type PublicParam = [u8; N];
pub type Randomizer = [u8; N];

/// The few-time signature authenticated by the bottom WOTS+C key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Variant {
    Forest,
    Fors,
}

impl Variant {
    pub const ALL: [Self; 2] = [Self::Forest, Self::Fors];
    pub const fn name(self) -> &'static str {
        match self {
            Self::Forest => "forest",
            Self::Fors => "fors",
        }
    }
    pub(crate) const fn id(self) -> u8 {
        match self {
            Self::Forest => 0,
            Self::Fors => 1,
        }
    }
    pub const fn opening_values(self) -> usize {
        match self {
            Self::Forest => COORDS * VALUES_PER_COORD,
            Self::Fors => FORS_TREES * (1 + FORS_HEIGHT),
        }
    }
    pub const fn key_values(self) -> usize {
        match self {
            Self::Forest => COORDS * 2,
            Self::Fors => FORS_TREES * 2,
        }
    }
}

/// One supported configuration. Arbitrary parameter combinations are not accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Config {
    hash: HashFn,
    h: usize,
    shape: Shape,
    variant: Variant,
}

impl Config {
    /// Panics for an unsupported height or kept subtree. `b = h` denotes the full tree.
    pub fn new(hash: HashFn, h: usize, shape: Shape, variant: Variant) -> Self {
        assert!(HEIGHTS.contains(&h), "unsupported total height");
        if let Shape::Pruned { b } = shape {
            assert!(
                b <= h && (b == h || PRUNED.contains(&b)),
                "unsupported kept height"
            );
        }
        Self {
            hash,
            h,
            shape,
            variant,
        }
    }
    pub fn hash(&self) -> HashFn {
        self.hash
    }
    pub fn h(&self) -> usize {
        self.h
    }
    pub fn shape(&self) -> Shape {
        self.shape
    }
    pub fn variant(&self) -> Variant {
        self.variant
    }
    pub fn layers(&self) -> Vec<usize> {
        match self.shape {
            Shape::Pruned { .. } => vec![self.h],
            Shape::Layered => layered_heights(self.h).iter().rev().copied().collect(),
        }
    }
    pub fn kept(&self) -> usize {
        match self.shape {
            Shape::Pruned { b } => b,
            Shape::Layered => layered_heights(self.h)[0],
        }
    }
    pub fn below(&self, layer: usize) -> usize {
        self.layers()[..layer].iter().sum()
    }
    pub fn sig_size(&self) -> usize {
        N + self.variant.opening_values() * N
            + self.layers().len() * (COUNTER_LEN + V * N)
            + self.h * N
    }

    /// Compression/permutation counts for a valid verification of this many raw message bytes.
    /// SHA-256 and SHA-512 compressions remain separate: they are not equal units of work.
    pub fn verify_counts(&self, message_len: usize) -> HashCounts {
        let mut counts = HashCounts::default();
        let mut add =
            |kind, bytes, times| counts += operation_cost(self.hash, kind, bytes, 24) * times;
        match self.variant {
            Variant::Forest => {
                add(Primitive::Small, N, (COORDS * SUBS * CODEWORD_SUM) as u64);
                add(Primitive::Wide, CHILD_CHAINS * N, (COORDS * SUBS) as u64);
                add(
                    Primitive::Wide,
                    2 * N,
                    (COORDS * (SUBS * (SUB_HEIGHT - 1) + TOP_HEIGHT - 1)) as u64,
                );
                add(Primitive::Wide, 4 * N, COORDS as u64);
            }
            Variant::Fors => {
                add(Primitive::Small, N, FORS_TREES as u64);
                add(
                    Primitive::Wide,
                    2 * N,
                    (FORS_TREES * (FORS_HEIGHT - 1)) as u64,
                );
            }
        }
        for (layer, height) in self.layers().iter().enumerate() {
            let message = if layer == 0 {
                self.variant.key_values() * N
            } else {
                N
            };
            add(Primitive::Wide, message + COUNTER_LEN, 1);
            add(
                Primitive::Small,
                N,
                (V * (CHAIN_LEN - 1) - TARGET_SUM) as u64,
            );
            add(Primitive::Wide, V * N, 1);
            add(Primitive::Wide, 2 * N, *height as u64);
        }
        counts
            + operation_cost(
                self.hash,
                Primitive::Wide,
                PUB_KEY_SIZE + 8 + message_len + N,
                64,
            )
    }
}

#[cfg(test)]
mod tests;
