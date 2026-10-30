//! Allocation-bounded traversal and packed encoding shared by both parameter families.
//! Callers supply hash/address operations; this module does not define cryptographic transcripts.

pub(crate) fn codeword<const N: usize, const V: usize>(
    digest: &[u8; N],
    target: usize,
) -> Option<[u8; V]> {
    assert!(N.is_multiple_of(8) && V == 4 * N);
    // Every two-bit digit contributes its low bit plus twice its high bit. Most candidates fail;
    // inspect those packed bits before constructing the expanded signature positions.
    let sum: u32 = digest
        .as_chunks::<8>()
        .0
        .iter()
        .map(|bytes| {
            let word = u64::from_le_bytes(*bytes);
            (word & 0x5555_5555_5555_5555).count_ones()
                + 2 * (word & 0xaaaa_aaaa_aaaa_aaaa).count_ones()
        })
        .sum();
    if sum != target as u32 {
        return None;
    }
    Some(std::array::from_fn(|i| {
        (digest[i / 4] >> (2 * (i % 4))) & 3
    }))
}

/// Reduces the leaves in place to two top nodes, saving siblings before overwriting each level.
/// The last path entry is the other top node: this construction never hashes the two tops together.
pub(crate) fn fold_opening<const N: usize>(
    leaves: &mut [[u8; N]],
    selected: usize,
    path: &mut [[u8; N]],
    node: impl Fn(usize, usize, &[u8; N], &[u8; N]) -> [u8; N],
) -> [[u8; N]; 2] {
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

/// The opening of one sub-tree: the 6 revealed chain values and the 3 authentication nodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubOpening<const N: usize> {
    pub values: [[u8; N]; 6],
    pub path: [[u8; N]; 3],
}

/// The opening of one coordinate: both sub-trees, then the 4 authentication nodes of the top tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoordOpening<const N: usize> {
    pub sub: [SubOpening<N>; 2],
    pub top: [[u8; N]; 4],
}

/// Generates a coordinate's small trees without retaining chain starts. Both families have
/// two height-three subtrees per super-child and six four-step chains per child.
#[allow(clippy::too_many_arguments)]
pub(crate) fn super_children<const N: usize>(
    first: usize,
    count: usize,
    mark: Option<(usize, [usize; 2], [u8; 2])>,
    open: &mut CoordOpening<N>,
    word: impl Fn(u8) -> [u8; 6],
    secrets: impl Fn(usize, usize, usize) -> [[u8; N]; 6],
    chain: impl Fn(usize, usize, usize, usize, usize, usize, [u8; N]) -> [u8; N],
    child_leaf: impl Fn(usize, usize, usize, &[[u8; N]; 6]) -> [u8; N],
    sub_node: impl Fn(usize, usize, usize, usize, &[u8; N], &[u8; N]) -> [u8; N],
    super_child: impl Fn(usize, &[[[u8; N]; 2]; 2]) -> [u8; N],
) -> [[u8; N]; 16] {
    assert!(first + count <= 16);
    let mut supers = [[0; N]; 16];
    for (local, super_leaf) in supers[..count].iter_mut().enumerate() {
        let s = first + local;
        let mut tops = [[[0; N]; 2]; 2];
        for (j, sub_top) in tops.iter_mut().enumerate() {
            let mut leaves = [[0; N]; 8];
            for (a, leaf) in leaves.iter_mut().enumerate() {
                let mut ends = secrets(s, j, a);
                if let Some(mark) = mark.filter(|mark| s == mark.0 && a == mark.1[j]) {
                    let word = word(mark.2[j]);
                    for (i, end) in ends.iter_mut().enumerate() {
                        let position = 4 - word[i] as usize;
                        *end = chain(s, j, a, i, 0, position, *end);
                        open.sub[j].values[i] = *end;
                        *end = chain(s, j, a, i, position, 4 - position, *end);
                    }
                } else {
                    for (i, end) in ends.iter_mut().enumerate() {
                        *end = chain(s, j, a, i, 0, 4, *end);
                    }
                }
                *leaf = child_leaf(s, j, a, &ends);
            }
            let mut path = [[0; N]; 3];
            *sub_top = fold_opening(
                &mut leaves,
                mark.map_or(0, |mark| mark.1[j]),
                &mut path,
                |level, node, left, right| sub_node(s, j, level, node, left, right),
            );
            if mark.is_some_and(|mark| s == mark.0) {
                open.sub[j].path = path;
            }
        }
        *super_leaf = super_child(s, &tops);
    }
    supers
}

/// Reduces an aligned subtree to its root and the authentication path of `selected`.
/// Hash callbacks receive global leaf/node indices, including nonzero subtree starts.
pub(crate) fn subtree_path<const N: usize>(
    selected: u32,
    height: usize,
    leaf_node: impl Fn(u32) -> [u8; N],
    hash_node: impl Fn(usize, u64, &[u8; N], &[u8; N]) -> [u8; N],
) -> ([u8; N], Vec<[u8; N]>) {
    assert!(height <= crate::MAX_H);
    let mut left_nodes = [[0; N]; crate::MAX_H];
    let mut path = vec![[0; N]; height];
    let first = selected & !((1 << height) - 1);
    for leaf in first..first + (1u32 << height) {
        let mut node = leaf_node(leaf);
        let mut index = leaf;
        for level in 0..=height {
            if level == height {
                return (node, path);
            }
            if index == (selected >> level) ^ 1 {
                path[level] = node;
            }
            if index & 1 == 0 {
                left_nodes[level] = node;
                break;
            }
            node = hash_node(level + 1, u64::from(index >> 1), &left_nodes[level], &node);
            index >>= 1;
        }
    }
    unreachable!("the final leaf completes the root")
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

/// Builds only retained Merkle levels while streaming the leaves through a bounded frontier.
pub(crate) fn cached_levels<const N: usize>(
    b: usize,
    start: u64,
    cached_from: usize,
    leaves: impl IntoIterator<Item = [u8; N]>,
    hash_node: impl Fn(usize, u64, &[u8; N], &[u8; N]) -> [u8; N],
) -> Vec<Vec<[u8; N]>> {
    assert!(cached_from <= b && b <= crate::MAX_H && start.is_multiple_of(1 << b));
    let mut levels: Vec<_> = (cached_from..=b)
        .map(|level| vec![[0; N]; 1 << (b - level)])
        .collect();
    let mut pending = [[0; N]; crate::MAX_H];
    let mut count = 0;
    for (position, mut node) in leaves.into_iter().enumerate() {
        assert!(position < 1 << b, "too many tree leaves");
        count += 1;
        let mut index = start + position as u64;
        for level in 0..=b {
            if level >= cached_from {
                levels[level - cached_from][position >> level] = node;
            }
            if level == b {
                break;
            }
            if index & 1 == 0 {
                pending[level] = node;
                break;
            }
            node = hash_node(level + 1, index >> 1, &pending[level], &node);
            index >>= 1;
        }
    }
    assert_eq!(count, 1 << b, "not enough tree leaves");
    levels
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference_codewords<const N: usize, const V: usize>(target: usize) {
        // All two-byte patterns at every byte boundary, mixed with nonzero digits elsewhere.
        // This oracle expands digits first, independently of the packed popcount calculation.
        for offset in 0..N - 1 {
            for pair in 0..=u16::MAX {
                let mut digest = [0xaa; N];
                digest[offset..offset + 2].copy_from_slice(&pair.to_le_bytes());
                let digits: [u8; V] = std::array::from_fn(|i| (digest[i / 4] >> (2 * (i % 4))) & 3);
                let sum = digits
                    .iter()
                    .map(|&digit| usize::from(digit))
                    .sum::<usize>();
                assert_eq!(
                    codeword::<N, V>(&digest, target),
                    (sum == target).then_some(digits)
                );
            }
        }
        for sum in [target - 1, target, target + 1] {
            let mut digest = [0; N];
            let mut remaining = sum;
            for i in 0..V {
                let digit = remaining.min(3);
                remaining -= digit;
                digest[i / 4] |= (digit as u8) << (2 * (i % 4));
            }
            assert_eq!(remaining, 0);
            assert_eq!(codeword::<N, V>(&digest, target).is_some(), sum == target);
        }
    }

    #[test]
    fn packed_codewords_match_expanded_oracle_for_both_families() {
        reference_codewords::<16, 64>(128);
        reference_codewords::<24, 96>(182);
    }
}
