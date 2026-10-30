//! The two-level WOTS forest: the few-time signature under each XMSS leaf.
//!
//! An instance has `COORDS = 12` independent coordinates. A coordinate is a top Merkle tree of
//! height 4 over 16 super-children, hashed up to level 3 only: its two level-3 nodes are not hashed
//! into a root, and the forest key is the twenty-four nodes themselves, which the WOTS+C encoding
//! absorbs. A super-child hashes the two level-2 nodes of each of its two sub-trees; a sub-tree is a
//! Merkle tree of height 3 over 8 children, also hashed up to its two top nodes only. A child is a
//! small WOTS key: 6 chains of length 5 under a leaf hash, signed at a codeword of digit sum 5.

use super::*;

pub(super) const SUPERS: usize = 1 << TOP_HEIGHT;
pub(super) const CHILDREN: usize = 1 << SUB_HEIGHT;

/// The forest key of an instance: the two level-3 nodes of every coordinate's top tree.
pub(super) type ForestKey = [[Digest; 2]; COORDS];

/// What the digest selects in one coordinate: the super-child, and per sub-tree a child and a
/// codeword index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CoordMark {
    pub super_child: usize,
    pub child: [usize; SUBS],
    pub word: [u8; SUBS],
}

/// The opening of one sub-tree: the 6 revealed chain values and the 3 authentication nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SubOpening {
    pub values: [Digest; CHILD_CHAINS],
    pub path: [Digest; SUB_HEIGHT],
}

/// The opening of one coordinate: both sub-trees, then the 4 authentication nodes of the top tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct CoordOpening {
    pub sub: [SubOpening; SUBS],
    pub top: [Digest; TOP_HEIGHT],
}

/// What a signature carries for the forest: `COORDS * 22` values.
pub(super) type ForestOpening = [CoordOpening; COORDS];

/// Values a coordinate's opening carries: per sub-tree 6 chain values and 3 nodes, plus 4 nodes.
pub(super) const VALUES_PER_COORD: usize = SUBS * (CHILD_CHAINS + SUB_HEIGHT) + TOP_HEIGHT;

/// `lut t`: the codeword of table entry `t`, the deficit of each of the 6 chains.
pub(super) fn lut(t: u8) -> [u8; CHILD_CHAINS] {
    codeword_table()[t as usize]
}

/// `c + 16 s + 256 j`, a sub-tree of the instance.
fn sub_slot(c: usize, s: usize, j: usize) -> u32 {
    assert!(c < COORDS && s < SUPERS && j < SUBS);
    (c + 16 * s + 256 * j) as u32
}

/// `c + 16 s + 256 j + 512 a`, a child of the instance.
fn child_slot(c: usize, s: usize, j: usize, a: usize) -> u32 {
    assert!(a < CHILDREN);
    sub_slot(c, s, j) + 512 * a as u32
}

/// `c + 16 s + 256 j + 512 a + 4096 i`, a chain of the instance.
fn chain_slot(c: usize, s: usize, j: usize, a: usize, i: usize) -> u32 {
    assert!(i < CHILD_CHAINS);
    child_slot(c, s, j, a) + 4096 * i as u32
}

/// The base address for deriving the starts of chains `2 t` and `2 t + 1` of a child.
pub(super) fn forest_secret_tweak(
    idx: u64,
    c: usize,
    s: usize,
    j: usize,
    a: usize,
    t: usize,
) -> Tweak {
    debug_assert!(t < CHILD_CHAINS / 2);
    tweak(
        TWEAK_FOREST_PRF,
        child_slot(c, s, j, a) + 4096 * t as u32,
        idx as u32,
    )
}

/// The starts of the 6 chains, derived in pairs with the selected backend.
pub(super) fn child_secrets(
    pp: &Pp,
    master: &MasterSecret,
    idx: u64,
    c: usize,
    s: usize,
    j: usize,
    a: usize,
) -> [Digest; CHILD_CHAINS] {
    let mut starts = [[0u8; N]; CHILD_CHAINS];
    for t in 0..CHILD_CHAINS / 2 {
        let pair = th_pair(pp, &forest_secret_tweak(idx, c, s, j, a, t), master);
        starts[2 * t] = pair[0];
        starts[2 * t + 1] = pair[1];
    }
    starts
}

/// The tweak of the forest chain step that leaves position `from < 4`.
fn fchain_tweak(idx: u64, c: usize, s: usize, j: usize, a: usize, i: usize, from: usize) -> Tweak {
    debug_assert!(from < CHAIN_TOP);
    tweak(TWEAK_FCHAIN, chain_slot(c, s, j, a, i), idx as u32).step(from)
}

/// `steps` chain steps from position `start`.
#[allow(clippy::too_many_arguments)]
pub(super) fn forest_chain(
    pp: &Pp,
    idx: u64,
    c: usize,
    s: usize,
    j: usize,
    a: usize,
    i: usize,
    start: usize,
    steps: usize,
    value: Digest,
) -> Digest {
    debug_assert!(start + steps <= CHAIN_TOP);
    (start..start + steps).fold(value, |current, from| {
        th(pp, &fchain_tweak(idx, c, s, j, a, i, from), &current)
    })
}

/// The leaf of a child: the hash of its 6 chain tops.
pub(super) fn child_leaf(
    pp: &Pp,
    idx: u64,
    c: usize,
    s: usize,
    j: usize,
    a: usize,
    tops: &[Digest; CHILD_CHAINS],
) -> Digest {
    th_digests(
        pp,
        &tweak(TWEAK_CHILD_LEAF, child_slot(c, s, j, a), idx as u32),
        tops,
    )
}

/// A node of a sub-tree: `level` counts from the leaves, so this is the node of level `level + 1`.
fn sub_node(
    pp: &Pp,
    idx: u64,
    c: usize,
    s: usize,
    j: usize,
    level: usize,
    node: usize,
    left: &Digest,
    right: &Digest,
) -> Digest {
    let hi = sub_slot(c, s, j) + 512 * (level as u32 + 1) + 2048 * node as u32;
    th_digests(pp, &tweak(TWEAK_SUB_NODE, hi, idx as u32), &[*left, *right])
}

/// A super-child: the hash of the two level-2 nodes of each of its two sub-trees.
fn super_child(pp: &Pp, idx: u64, c: usize, s: usize, tops: &[[Digest; 2]; SUBS]) -> Digest {
    th_digests(
        pp,
        &tweak(TWEAK_SUPER_CHILD, (c + 16 * s) as u32, idx as u32),
        &[tops[0][0], tops[0][1], tops[1][0], tops[1][1]],
    )
}

/// A node of a top tree, of level `level + 1`.
fn top_node(
    pp: &Pp,
    idx: u64,
    c: usize,
    level: usize,
    node: usize,
    left: &Digest,
    right: &Digest,
) -> Digest {
    let hi = (c + 16 * (level + 1) + 128 * node) as u32;
    th_digests(pp, &tweak(TWEAK_TOP_NODE, hi, idx as u32), &[*left, *right])
}

/// The two top nodes in index order, from the one a fold reached and the last path element.
fn order_tops(bit: bool, current: Digest, sibling: Digest) -> [Digest; 2] {
    if bit {
        [sibling, current]
    } else {
        [current, sibling]
    }
}

fn empty_opening() -> CoordOpening {
    CoordOpening {
        sub: std::array::from_fn(|_| SubOpening {
            values: [[0; N]; CHILD_CHAINS],
            path: [[0; N]; SUB_HEIGHT],
        }),
        top: [[0; N]; TOP_HEIGHT],
    }
}

/// Generates an aligned group of super-children, retaining an opening only when requested.
fn super_children(
    pp: &Pp,
    master: &MasterSecret,
    idx: u64,
    c: usize,
    first: usize,
    count: usize,
    mark: Option<&CoordMark>,
    open: &mut CoordOpening,
) -> [Digest; SUPERS] {
    assert!(first + count <= SUPERS);
    let mut supers = [[0; N]; SUPERS];
    for (local, super_leaf) in supers[..count].iter_mut().enumerate() {
        let s = first + local;
        let mut tops = [[[0; N]; 2]; SUBS];
        for (j, sub_top) in tops.iter_mut().enumerate() {
            let mut leaves = [[0; N]; CHILDREN];
            for (a, leaf) in leaves.iter_mut().enumerate() {
                let secrets = child_secrets(pp, master, idx, c, s, j, a);
                let ends = std::array::from_fn(|i| {
                    forest_chain(pp, idx, c, s, j, a, i, 0, CHAIN_TOP, secrets[i])
                });
                *leaf = child_leaf(pp, idx, c, s, j, a, &ends);
                if let Some(mark) = mark.filter(|mark| s == mark.super_child && a == mark.child[j])
                {
                    let word = lut(mark.word[j]);
                    open.sub[j].values = std::array::from_fn(|i| {
                        forest_chain(
                            pp,
                            idx,
                            c,
                            s,
                            j,
                            a,
                            i,
                            0,
                            CHAIN_TOP - word[i] as usize,
                            secrets[i],
                        )
                    });
                }
            }
            let mut path = [[0; N]; SUB_HEIGHT];
            *sub_top = fold_opening(
                &mut leaves,
                mark.map_or(0, |mark| mark.child[j]),
                &mut path,
                |level, node, left, right| sub_node(pp, idx, c, s, j, level, node, left, right),
            );
            if mark.is_some_and(|mark| s == mark.super_child) {
                open.sub[j].path = path;
            }
        }
        *super_leaf = super_child(pp, idx, c, s, &tops);
    }
    supers
}

/// Appends one level of public coordinate-tree nodes for one instance. No chain secrets are kept.
pub(super) fn precompute_instance(
    pp: &Pp,
    master: &MasterSecret,
    idx: u64,
    level: usize,
    nodes: &mut Vec<Digest>,
) {
    assert!(level < TOP_HEIGHT);
    for c in 0..COORDS {
        let mut supers = super_children(pp, master, idx, c, 0, SUPERS, None, &mut empty_opening());
        let mut width = SUPERS;
        for height in 0..level {
            for j in 0..width / 2 {
                supers[j] = top_node(pp, idx, c, height, j, &supers[2 * j], &supers[2 * j + 1]);
            }
            width /= 2;
        }
        nodes.extend_from_slice(&supers[..width]);
    }
}

/// Builds one coordinate at a time, retaining only its selected opening and two top nodes.
pub(super) fn forest_sign(
    pp: &Pp,
    master: &MasterSecret,
    idx: u64,
    marks: &[CoordMark; COORDS],
) -> (ForestKey, Box<ForestOpening>) {
    forest_sign_precomputed(pp, master, idx, marks, None)
}

/// Cached nodes are generated internally and bound to the signing key by the prepared signer.
pub(super) fn forest_sign_precomputed(
    pp: &Pp,
    master: &MasterSecret,
    idx: u64,
    marks: &[CoordMark; COORDS],
    cached: Option<(usize, &[Digest])>,
) -> (ForestKey, Box<ForestOpening>) {
    if let Some((level, nodes)) = cached {
        assert!(level < TOP_HEIGHT);
        assert_eq!(nodes.len(), COORDS * (SUPERS >> level));
    }
    let mut key = [[[0; N]; 2]; COORDS];
    let mut opening = Vec::with_capacity(COORDS);
    for (c, mark) in marks.iter().enumerate() {
        let mut open = empty_opening();
        let (first, count) = cached.map_or((0, SUPERS), |(level, _)| {
            ((mark.super_child >> level) << level, 1 << level)
        });
        let mut supers = super_children(pp, master, idx, c, first, count, Some(mark), &mut open);
        key[c] = if let Some((level, nodes)) = cached {
            let mut width = count;
            for height in 0..level {
                open.top[height] = supers[((mark.super_child - first) >> height) ^ 1];
                for j in 0..width / 2 {
                    supers[j] = top_node(
                        pp,
                        idx,
                        c,
                        height,
                        (first >> (height + 1)) + j,
                        &supers[2 * j],
                        &supers[2 * j + 1],
                    );
                }
                width /= 2;
            }
            let selected = supers[0];
            let cached_width = SUPERS >> level;
            supers[..cached_width]
                .copy_from_slice(&nodes[c * cached_width..(c + 1) * cached_width]);
            debug_assert_eq!(supers[mark.super_child >> level], selected);
            supers[mark.super_child >> level] = selected;
            fold_opening(
                &mut supers[..cached_width],
                mark.super_child >> level,
                &mut open.top[level..],
                |height, node, left, right| top_node(pp, idx, c, height + level, node, left, right),
            )
        } else {
            fold_opening(
                &mut supers,
                mark.super_child,
                &mut open.top,
                |level, node, left, right| top_node(pp, idx, c, level, node, left, right),
            )
        };
        opening.push(open);
    }
    (
        key,
        opening
            .into_boxed_slice()
            .try_into()
            .expect("one opening per coordinate"),
    )
}

/// Reduces the leaves in place to two top nodes, saving siblings before overwriting each level.
/// The last path entry is the other top node: this construction never hashes the two tops together.
fn fold_opening(
    leaves: &mut [Digest],
    selected: usize,
    path: &mut [Digest],
    node: impl Fn(usize, usize, &Digest, &Digest) -> Digest,
) -> [Digest; 2] {
    debug_assert_eq!(leaves.len(), 1 << path.len());
    debug_assert!(selected < leaves.len());
    let mut width = leaves.len();
    let height = path.len();
    for (level, sibling) in path.iter_mut().enumerate() {
        *sibling = leaves[(selected >> level) ^ 1];
        if level + 1 < height {
            for j in 0..width / 2 {
                leaves[j] = node(level, j, &leaves[2 * j], &leaves[2 * j + 1]);
            }
            width /= 2;
        }
    }
    [leaves[0], leaves[1]]
}

/// `Fts.recover`: the forest key an opening reaches.
pub(super) fn forest_recover(
    pp: &Pp,
    idx: u64,
    marks: &[CoordMark; COORDS],
    opening: &ForestOpening,
) -> ForestKey {
    std::array::from_fn(|c| {
        let (mark, open) = (marks[c], &opening[c]);
        let s = mark.super_child;
        let tops: [[Digest; 2]; SUBS] = std::array::from_fn(|j| {
            let (a, word) = (mark.child[j], lut(mark.word[j]));
            let ends = std::array::from_fn(|i| {
                let deficit = word[i] as usize;
                forest_chain(
                    pp,
                    idx,
                    c,
                    s,
                    j,
                    a,
                    i,
                    CHAIN_TOP - deficit,
                    deficit,
                    open.sub[j].values[i],
                )
            });
            let leaf = child_leaf(pp, idx, c, s, j, a, &ends);
            let node = (0..SUB_HEIGHT - 1).fold(leaf, |current, level| {
                let sibling = open.sub[j].path[level];
                let (left, right) = if (a >> level) & 1 == 1 {
                    (sibling, current)
                } else {
                    (current, sibling)
                };
                sub_node(pp, idx, c, s, j, level, a >> (level + 1), &left, &right)
            });
            order_tops(
                (a >> (SUB_HEIGHT - 1)) & 1 == 1,
                node,
                open.sub[j].path[SUB_HEIGHT - 1],
            )
        });
        let super_node = super_child(pp, idx, c, s, &tops);
        let node = (0..TOP_HEIGHT - 1).fold(super_node, |current, level| {
            let sibling = open.top[level];
            let (left, right) = if (s >> level) & 1 == 1 {
                (sibling, current)
            } else {
                (current, sibling)
            };
            top_node(pp, idx, c, level, s >> (level + 1), &left, &right)
        });
        order_tops(
            (s >> (TOP_HEIGHT - 1)) & 1 == 1,
            node,
            open.top[TOP_HEIGHT - 1],
        )
    })
}

#[cfg(test)]
mod address_tests {
    use super::*;
    #[test]
    fn all_forest_addresses_are_distinct() {
        let mut seen = std::collections::HashSet::new();
        let mut insert = |tw: Tweak| assert!(seen.insert(address(&tw)), "forest address collision");
        for c in 0..COORDS {
            for s in 0..SUPERS {
                insert(tweak(TWEAK_SUPER_CHILD, (c + 16 * s) as u32, 0));
                for j in 0..SUBS {
                    for a in 0..CHILDREN {
                        for t in 0..CHILD_CHAINS / 2 {
                            for side in 0..2 {
                                insert(forest_secret_tweak(0, c, s, j, a, t).step(side));
                            }
                        }
                        insert(tweak(TWEAK_CHILD_LEAF, child_slot(c, s, j, a), 0));
                        for i in 0..CHILD_CHAINS {
                            for step in 0..CHAIN_TOP {
                                insert(fchain_tweak(0, c, s, j, a, i, step));
                            }
                        }
                    }
                    for level in 0..SUB_HEIGHT - 1 {
                        for node in 0..1 << (SUB_HEIGHT - level - 1) {
                            insert(tweak(
                                TWEAK_SUB_NODE,
                                sub_slot(c, s, j) + 512 * (level as u32 + 1) + 2048 * node,
                                0,
                            ));
                        }
                    }
                }
            }
            for level in 0..TOP_HEIGHT - 1 {
                for node in 0..1 << (TOP_HEIGHT - level - 1) {
                    insert(tweak(
                        TWEAK_TOP_NODE,
                        (c + 16 * (level + 1) + 128 * node) as u32,
                        0,
                    ));
                }
            }
        }
    }
}
