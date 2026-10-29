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
    height: usize,
    /// Height of the kept subtree; `b = height` keeps the whole tree.
    b: usize,
    /// The first leaf of the kept subtree.
    start: u64,
    /// The kept subtree, level 0 being its `2^b` leaves.
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
        leaves: Vec<Digest>,
        surrogates: Vec<Digest>,
    ) -> Self {
        assert!(b <= height && start.is_multiple_of(1 << b));
        assert_eq!(leaves.len(), 1 << b);
        assert_eq!(surrogates.len(), height - b);
        let mut levels = vec![leaves];
        for level in 1..=b {
            let below = &levels[level - 1];
            let first = start >> level;
            let up = (0..below.len() / 2)
                .map(|j| {
                    xmss_node(
                        pp,
                        layer,
                        tree,
                        level,
                        first + j as u64,
                        &below[2 * j],
                        &below[2 * j + 1],
                    )
                })
                .collect();
            levels.push(up);
        }
        let root = surrogates
            .iter()
            .enumerate()
            .fold(levels[b][0], |node, (t, sibling)| {
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
            height,
            b,
            start,
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

    /// The authentication path of a leaf, which must be kept.
    pub(super) fn path(&self, leaf: u64) -> Vec<Digest> {
        assert!(self.contains(leaf));
        let local = (leaf - self.start) as usize;
        (0..self.height)
            .map(|level| {
                if level < self.b {
                    self.levels[level][(local >> level) ^ 1]
                } else {
                    self.surrogates[level - self.b]
                }
            })
            .collect()
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

/// The whole tree of height `height` that holds a one-time key, built from the master secret.
pub(super) fn layer_tree(pp: &Pp, master: &MasterSecret, key: &OtsKey, height: usize) -> XmssTree {
    let leaves = (0..1u32 << height)
        .map(|leaf| wots_leaf(pp, master, &OtsKey { leaf, ..*key }))
        .collect();
    XmssTree::from_leaves(
        pp,
        key.layer,
        key.tree,
        height,
        height,
        0,
        leaves,
        Vec::new(),
    )
}
