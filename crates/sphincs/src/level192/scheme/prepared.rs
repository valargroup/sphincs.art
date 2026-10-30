//! Optional public forest precomputation, generated locally and immutably bound to its signing key.
use super::{SecretKey, SignError, Signature, sign_with_precomputed};
use crate::level192::forest::{SUPERS, precompute_instance};
use crate::level192::{COORDS, Digest, MAX_ENCODING_ATTEMPTS, N, Shape, TOP_HEIGHT, Variant};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForestPrecomputeError {
    UnsupportedConfiguration,
    InvalidLevel,
    SizeOverflow,
    CacheBudgetExceeded { required_bytes: usize },
    AllocationFailed,
}

impl fmt::Display for ForestPrecomputeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedConfiguration => {
                formatter.write_str("precomputation requires a single-tree forest key")
            }
            Self::InvalidLevel => {
                formatter.write_str("public forest cache level must be between 0 and 3")
            }
            Self::SizeOverflow => {
                formatter.write_str("public forest cache size exceeds the platform address space")
            }
            Self::CacheBudgetExceeded { required_bytes } => write!(
                formatter,
                "public forest cache requires {required_bytes} bytes"
            ),
            Self::AllocationFailed => formatter.write_str("public forest cache allocation failed"),
        }
    }
}
impl std::error::Error for ForestPrecomputeError {}

/// Owns public tree nodes and borrows the exact key that generated them.
///
/// The cache contains no chain secrets and cannot be imported, modified, or paired with another
/// key through this API. External or mutable cache storage would require separate authentication
/// before permitting the reused WOTS key to sign the recovered forest key.
pub struct PreparedForest<'key> {
    key: &'key SecretKey,
    level: usize,
    first: u64,
    nodes: Vec<Digest>,
}

impl PreparedForest<'_> {
    /// Bytes of public node values retained, excluding the handle and allocator overhead.
    pub fn cache_bytes(&self) -> usize {
        self.nodes.len() * N
    }

    /// Produces the same deterministic signature as `sign` with less forest-generation work.
    /// Signing-use limits and search exhaustion behavior remain unchanged.
    pub fn sign(&self, message: &[u8]) -> Result<Signature, SignError> {
        sign_with_precomputed(
            self.key,
            message,
            MAX_ENCODING_ATTEMPTS,
            MAX_ENCODING_ATTEMPTS,
            Some(self),
        )
    }

    pub(super) fn instance(&self, index: u64) -> (usize, &[Digest]) {
        let width = COORDS * (SUPERS >> self.level);
        let first = (index - self.first) as usize * width;
        (self.level, &self.nodes[first..first + width])
    }
}

/// Precomputes public coordinate-tree nodes for every retained forest instance.
///
/// Level 0 caches sixteen super-child roots per coordinate and minimizes signing work; level 3
/// caches two coordinate tops and uses less storage. For kept height 8 these require 1,179,648
/// and 147,456 bytes respectively. All levels build every retained forest during preparation.
/// `max_cache_bytes` bounds the logical node buffer, excluding allocator overhead and the handle.
/// Unsupported configurations and insufficient budgets fail before any forest is built.
pub fn prepare_forest(
    key: &SecretKey,
    level: usize,
    max_cache_bytes: usize,
) -> Result<PreparedForest<'_>, ForestPrecomputeError> {
    if key.cfg.variant() != Variant::Forest || !matches!(key.cfg.shape(), Shape::Pruned { .. }) {
        return Err(ForestPrecomputeError::UnsupportedConfiguration);
    }
    if level >= TOP_HEIGHT {
        return Err(ForestPrecomputeError::InvalidLevel);
    }
    let count = (1usize << key.cfg.kept())
        .checked_mul(COORDS * (SUPERS >> level))
        .ok_or(ForestPrecomputeError::SizeOverflow)?;
    let bytes = count
        .checked_mul(N)
        .ok_or(ForestPrecomputeError::SizeOverflow)?;
    if bytes > max_cache_bytes {
        return Err(ForestPrecomputeError::CacheBudgetExceeded {
            required_bytes: bytes,
        });
    }
    let mut nodes = Vec::new();
    nodes
        .try_reserve_exact(count)
        .map_err(|_| ForestPrecomputeError::AllocationFailed)?;
    let kept = key.top.kept_leaves();
    for instance in kept.clone() {
        precompute_instance(&key.pp, &key.master, instance, level, &mut nodes);
    }
    debug_assert_eq!(nodes.len(), count);
    Ok(PreparedForest {
        key,
        level,
        first: kept.start,
        nodes,
    })
}
