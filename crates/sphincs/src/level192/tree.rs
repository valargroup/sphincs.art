//! The Merkle tree engine shared by both 192-bit variants.

use super::*;

/// The node `j` of level `level` (counted from the one-time leaves) of tree `tree` at layer `layer`.
pub(super) fn xmss_node(
    pp: &Pp,
    layer: usize,
    tree: u32,
    level: usize,
    j: u64,
    left: &Digest,
    right: &Digest,
) -> Digest {
    th_digests(
        pp,
        &tweak(TWEAK_NODE, level as u32, j as u32).at(layer, tree),
        &[*left, *right],
    )
}

/// A tree of one layer: its kept subtree's levels and the surrogates above it.
#[derive(Clone, Debug)]
pub(super) struct XmssTree {
    layer: usize,
    tree: u32,
    height: usize,
    /// Height of the kept subtree; `b = height` keeps the whole tree.
    b: usize,
    /// The first leaf of the kept subtree.
    start: u64,
    /// Bottom levels are regenerated on demand; stored levels begin at `cached_from`.
    cached_from: usize,
    levels: Vec<Vec<Digest>>,
    /// The siblings of the path at levels `b..height`, surrogates (no secret below them).
    surrogates: Vec<Digest>,
    root: Digest,
}

impl XmssTree {
    /// `start` must be a multiple of `2^b`.
    pub(super) fn from_leaves(
        pp: &Pp,
        layer: usize,
        tree: u32,
        height: usize,
        b: usize,
        start: u64,
        cached_from: usize,
        leaves: impl IntoIterator<Item = Digest>,
        surrogates: Vec<Digest>,
    ) -> Self {
        assert!(cached_from <= b && b <= height && start.is_multiple_of(1 << b));
        assert_eq!(surrogates.len(), height - b);
        let levels = crate::bounded::cached_levels(
            b,
            start,
            cached_from,
            leaves,
            |level, index, left, right| xmss_node(pp, layer, tree, level, index, left, right),
        );
        let root =
            surrogates
                .iter()
                .enumerate()
                .fold(levels[b - cached_from][0], |node, (t, sibling)| {
                    let level = b + t;
                    let j = start >> level;
                    let (left, right) = if j & 1 == 0 {
                        (node, *sibling)
                    } else {
                        (*sibling, node)
                    };
                    xmss_node(pp, layer, tree, level + 1, j >> 1, &left, &right)
                });
        Self {
            layer,
            tree,
            height,
            b,
            start,
            cached_from,
            levels,
            surrogates,
            root,
        }
    }

    pub(super) fn root(&self) -> Digest {
        self.root
    }

    pub(super) fn contains(&self, leaf: u64) -> bool {
        leaf >> self.b == self.start >> self.b
    }

    #[cfg(feature = "forest-precompute")]
    pub(super) fn kept_leaves(&self) -> core::ops::Range<u64> {
        self.start..self.start + (1u64 << self.b)
    }

    /// The authentication path of a leaf, which must be kept.
    pub(super) fn path(&self, pp: &Pp, master: &MasterSecret, leaf: u64) -> Vec<Digest> {
        assert!(self.contains(leaf));
        let local = (leaf - self.start) as usize;
        let mut path = Vec::with_capacity(self.height);
        if self.cached_from != 0 {
            let key = OtsKey {
                layer: self.layer,
                tree: self.tree,
                leaf: leaf as u32,
            };
            let (_, lower) = subtree_path(pp, master, &key, self.cached_from);
            path.extend_from_slice(&lower);
        }
        path.extend((self.cached_from..self.height).map(|level| {
            if level < self.b {
                self.levels[level - self.cached_from][(local >> level) ^ 1]
            } else {
                self.surrogates[level - self.b]
            }
        }));
        path
    }
}

/// `Tree.fold`: the node the leaf of a one-time key and its path reach.
pub(super) fn tree_fold(pp: &Pp, key: &OtsKey, leaf: Digest, path: &[Digest]) -> Digest {
    let e = u64::from(key.leaf);
    path.iter()
        .enumerate()
        .fold(leaf, |current, (level, sibling)| {
            let (left, right) = if (e >> level) & 1 == 0 {
                (current, *sibling)
            } else {
                (*sibling, current)
            };
            xmss_node(
                pp,
                key.layer,
                key.tree,
                level + 1,
                e >> (level + 1),
                &left,
                &right,
            )
        })
}

/// Builds a root and one authentication path with one pending left node per height.
/// Every leaf is generated once; completed subtrees are discarded after saving any needed sibling.
pub(super) fn layer_path(
    pp: &Pp,
    master: &MasterSecret,
    key: &OtsKey,
    height: usize,
) -> (Digest, Vec<Digest>) {
    assert!(height <= crate::MAX_H && u64::from(key.leaf) < 1u64 << height);
    subtree_path(pp, master, key, height)
}

/// Regenerates the aligned subtree containing `key.leaf`, keeping only its path and pending nodes.
fn subtree_path(
    pp: &Pp,
    master: &MasterSecret,
    key: &OtsKey,
    height: usize,
) -> (Digest, Vec<Digest>) {
    crate::bounded::subtree_path(
        key.leaf,
        height,
        |leaf| wots_leaf(pp, master, &OtsKey { leaf, ..*key }),
        |level, index, left, right| xmss_node(pp, key.layer, key.tree, level, index, left, right),
    )
}
