//! FORS without a root hash: WOTS+C authenticates the two nodes below each root.
use super::*;

pub(super) type ForsKey = [[Digest; 2]; FORS_TREES];
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ForsOpening {
    pub secret: Digest,
    pub path: [Digest; FORS_HEIGHT],
}

pub(super) fn fors_secret_tweak(instance: u64, tree: usize, pair: usize) -> Tweak {
    assert!(tree < FORS_TREES && pair < (1 << (FORS_HEIGHT - 1)));
    tweak(
        TWEAK_FORS_PRF,
        (tree * (1 << (FORS_HEIGHT - 1)) + pair) as u32,
        instance as u32,
    )
}
pub(super) fn fors_leaf(
    pp: &Pp,
    instance: u64,
    tree: usize,
    leaf: usize,
    secret: &Digest,
) -> Digest {
    assert!(tree < FORS_TREES && leaf < (1 << FORS_HEIGHT));
    th(
        pp,
        &tweak(
            TWEAK_FORS_LEAF,
            ((tree << FORS_HEIGHT) + leaf) as u32,
            instance as u32,
        ),
        secret,
    )
}
pub(super) fn fors_node_tweak(instance: u64, tree: usize, level: usize, node: usize) -> Tweak {
    assert!(
        tree < FORS_TREES && level < FORS_HEIGHT - 1 && node < (1 << (FORS_HEIGHT - level - 1))
    );
    tweak(
        TWEAK_FORS_NODE,
        ((tree << 14) | (level << 10) | node) as u32,
        instance as u32,
    )
}
fn node(
    pp: &Pp,
    instance: u64,
    tree: usize,
    level: usize,
    j: usize,
    left: &Digest,
    right: &Digest,
) -> Digest {
    th_digests(
        pp,
        &fors_node_tweak(instance, tree, level, j),
        &[*left, *right],
    )
}

pub(super) fn fors_sign(
    pp: &Pp,
    seed: &MasterSecret,
    instance: u64,
    marks: &[usize; FORS_TREES],
) -> (ForsKey, Box<[ForsOpening; FORS_TREES]>) {
    let mut key = [[[0; N]; 2]; FORS_TREES];
    let openings = std::array::from_fn(|tree| {
        let mark = marks[tree];
        let mut chosen = [0; N];
        let mut leaves = Vec::with_capacity(1 << FORS_HEIGHT);
        for pair in 0..1 << (FORS_HEIGHT - 1) {
            for (side, secret) in th_pair(pp, &fors_secret_tweak(instance, tree, pair), seed)
                .iter()
                .enumerate()
            {
                let leaf = pair * 2 + side;
                if leaf == mark {
                    chosen = *secret;
                }
                leaves.push(fors_leaf(pp, instance, tree, leaf, secret));
            }
        }
        let mut levels = vec![leaves];
        for level in 0..FORS_HEIGHT - 1 {
            let up = levels[level]
                .chunks_exact(2)
                .enumerate()
                .map(|(j, pair)| node(pp, instance, tree, level, j, &pair[0], &pair[1]))
                .collect();
            levels.push(up);
        }
        key[tree] = [levels[FORS_HEIGHT - 1][0], levels[FORS_HEIGHT - 1][1]];
        ForsOpening {
            secret: chosen,
            path: std::array::from_fn(|level| levels[level][(mark >> level) ^ 1]),
        }
    });
    (key, Box::new(openings))
}

pub(super) fn fors_recover(
    pp: &Pp,
    instance: u64,
    marks: &[usize; FORS_TREES],
    openings: &[ForsOpening; FORS_TREES],
) -> ForsKey {
    std::array::from_fn(|tree| {
        let (mark, open) = (marks[tree], &openings[tree]);
        let mut value = fors_leaf(pp, instance, tree, mark, &open.secret);
        for level in 0..FORS_HEIGHT - 1 {
            let other = open.path[level];
            let (left, right) = if (mark >> level) & 1 == 0 {
                (value, other)
            } else {
                (other, value)
            };
            value = node(
                pp,
                instance,
                tree,
                level,
                mark >> (level + 1),
                &left,
                &right,
            );
        }
        let other = open.path[FORS_HEIGHT - 1];
        if mark >> (FORS_HEIGHT - 1) == 0 {
            [value, other]
        } else {
            [other, value]
        }
    })
}
