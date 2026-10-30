//! WOTS+C: `v = 96` chains of `2^w - 1 = 3` steps, and the target-sum code that replaces the
//! Winternitz checksum. A codeword is 96 chunks summing to `T = 182`; the signer searches the least
//! counter whose encoding is a codeword. The encoding hashes the signed message itself, with the
//! counter last: the forest key at the bottom layer, the root of the tree below at a layer above.
//!
//! A one-time key is named by its layer (from the bottom), its tree in that layer and its leaf in
//! that tree ([`OtsKey`]).

use super::*;

/// The starts of the `v` chains of a one-time key. Backend-specific derivation produces pairs of
/// them: chains `2 t` and `2 t + 1` are the two halves of the hash at address `t`.
pub(super) fn wots_secrets(pp: &Pp, master: &MasterSecret, key: &OtsKey) -> [Digest; V] {
    let mut secrets = [[0u8; N]; V];
    for t in 0..V / 2 {
        let pair = th_pair(pp, &wots_secret_tweak(key, t), master);
        secrets[2 * t] = pair[0];
        secrets[2 * t + 1] = pair[1];
    }
    secrets
}

/// The base address for deriving the starts of chains `2 t` and `2 t + 1`.
pub(super) fn wots_secret_tweak(key: &OtsKey, t: usize) -> Tweak {
    key.tweak(TWEAK_PRF, t as u32)
}

/// The tweak of the step of chain `i` that lands on position `to`, in `1..CHAIN_LEN`.
pub(super) fn chain_tweak(key: &OtsKey, i: usize, to: usize) -> Tweak {
    debug_assert!((1..CHAIN_LEN).contains(&to));
    key.tweak(TWEAK_CHAIN, i as u32).step(to - 1)
}

/// `steps` chain steps of chain `i` from position `start`.
pub(super) fn chain(
    pp: &Pp,
    key: &OtsKey,
    i: usize,
    start: usize,
    steps: usize,
    value: Digest,
) -> Digest {
    debug_assert!(start + steps < CHAIN_LEN);
    (start + 1..=start + steps).fold(value, |current, to| {
        th(pp, &chain_tweak(key, i, to), &current)
    })
}

/// The Merkle leaf of a one-time key: `Th` over its 96 chain ends.
pub(super) fn wots_leaf_hash(pp: &Pp, key: &OtsKey, ends: &[Digest; V]) -> Digest {
    th_digests(pp, &key.tweak(TWEAK_LEAF, 0), ends)
}

/// The encoding hash after its fixed part. Searches reuse this state and hash only the counter
/// and final padding again; the remaining compression count depends on the backend and payload.
pub(super) fn encoding_midstate(pp: &Pp, key: &OtsKey, message: &[u8]) -> Midstate {
    Midstate::new(pp, &key.tweak(TWEAK_ENC, 0), &[message])
}

/// The codeword of counter `c` from the encoding's midstate, or `None` if its digest is not one.
pub(super) fn encode_from(state: &Midstate, c: u32) -> Option<[u8; V]> {
    codeword(&state.finish::<N>(&c.to_le_bytes()))
}

/// `Enc(P, key, message, c)`: `Th(P, A(enc, 0, leaf), message | c)` decoded, or `None` if it is not a
/// codeword.
pub(super) fn encode(pp: &Pp, key: &OtsKey, message: &[u8], c: u32) -> Option<[u8; V]> {
    encode_from(&encoding_midstate(pp, key, message), c)
}

/// The 192 digest bits as 96 chunks of 2 bits, little endian; a codeword if they sum to `T`.
pub(super) fn codeword(digest: &Digest) -> Option<[u8; V]> {
    let x: [u8; V] = core::array::from_fn(|i| (digest[i / 4] >> (2 * (i % 4))) & 3);
    (x.iter().map(|&c| c as usize).sum::<usize>() == TARGET_SUM).then_some(x)
}

/// The least admissible encoding, returning failure if the finite counter space is exhausted.
// Out of line, so its buffers do not share one stack frame with the rest of signing.
#[inline(never)]
pub(super) fn wots_sign_limited(
    pp: &Pp,
    master: &MasterSecret,
    key: &OtsKey,
    message: &[u8],
    limit: u64,
) -> Option<(u32, [Digest; V])> {
    let state = encoding_midstate(pp, key, message);
    let (c, x) = (0..limit.min(MAX_ENCODING_ATTEMPTS))
        .find_map(|c| encode_from(&state, c as u32).map(|x| (c as u32, x)))?;
    let mut signature = wots_secrets(pp, master, key);
    for (i, value) in signature.iter_mut().enumerate() {
        *value = chain(pp, key, i, 0, x[i] as usize, *value);
    }
    Some((c, signature))
}

/// `Ots.leaf`: the leaf a claimed signature recovers, or `None` if the counter is not admissible.
pub(super) fn wots_recover(
    pp: &Pp,
    key: &OtsKey,
    message: &[u8],
    c: u32,
    signature: &[Digest; V],
) -> Option<Digest> {
    let x = encode(pp, key, message, c)?;
    let ends = core::array::from_fn(|i| {
        let start = x[i] as usize;
        chain(pp, key, i, start, CHAIN_LEN - 1 - start, signature[i])
    });
    Some(wots_leaf_hash(pp, key, &ends))
}

/// The chain ends of a one-time key, from the master secret.
pub(super) fn wots_ends(pp: &Pp, master: &MasterSecret, key: &OtsKey) -> [Digest; V] {
    let mut ends = wots_secrets(pp, master, key);
    for (i, value) in ends.iter_mut().enumerate() {
        *value = chain(pp, key, i, 0, CHAIN_LEN - 1, *value);
    }
    ends
}

/// The leaf of a one-time key, from the master secret.
pub(super) fn wots_leaf(pp: &Pp, master: &MasterSecret, key: &OtsKey) -> Digest {
    wots_leaf_hash(pp, key, &wots_ends(pp, master, key))
}
