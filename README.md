# sphincs.art

Exploring leanSphincs: a hash-based stateless signature scheme for Post-Quantum Ethereum.

- [Website](https://sphincs.art/)
- [Note (PDF)](https://github.com/TomWambsgans/sphincs.art/releases/download/doc-latest/leanSPHINCS.pdf)
- [Slides (PDF)](https://github.com/TomWambsgans/sphincs.art/releases/download/doc-latest/slides.pdf): the WOTS forest, and the privacy of a pruned key.
- [Security proofs in Lean 4](formal/sphincs/README.md)

## Experimental 192-bit family

`sphincs::level192` adds a 24-byte family targeting the NIST Category 3 convention,
with SHAKE256 and SHA2 backends, a two-level WOTS forest or FORS, and the existing
heights and pruning choices. **This is an experimental leanSphincs construction,
not standardized SLH-DSA. No full-scheme classical or quantum security proof is
claimed for it. The 128-bit family's Lean proofs do not apply.**

| Parameter | 192 family |
|---|---|
| Hash values / public parameter / randomizer | 24 bytes each |
| Master seed / public key | 32 / 48 bytes |
| WOTS+C | 96 chains of four positions; target sum 182 |
| WOTS forest | 12 coordinates; existing two-level structure and codeword table |
| FORS | 37 trees of height 10; WOTS+C signs the two nodes below each root |
| Total heights | 20, 22, 24, 26, 28 |
| Kept heights | 8, 10, 12, 13, 14, 20, or the full tree |
| Layered splits, top first | 8+6+6, 10+6+6, 10+7+7, 10+8+8, 10+9+9 |

At height 24, forest signatures occupy 9,244 bytes for one pruned/full tree or
13,860 bytes for a layered key. FORS occupies 12,676 or 17,292 bytes respectively.
Pruning changes preparation and grinding costs, not the signature size.

```rust
use sphincs::{Shape, level192::{self, Config, HashFn, Variant}};

// Supply 32 cryptographically random bytes from your application's secure RNG.
fn example(seed: &[u8; 32]) {
    let cfg = Config::new(HashFn::Shake256, 24, Shape::Layered, Variant::Forest);
    let (secret, public) = level192::key_gen(&cfg, seed);
    let signature = level192::sign(&secret, b"raw message bytes").unwrap();
    level192::verify(&cfg, &public, b"raw message bytes", &signature).unwrap();
}
```

The new API accepts raw bytes, without an implicit 32-byte prehash. Key and
signature encodings require the configuration out of band. Parsers reject
incorrect lengths. Signing returns an error if its finite randomizer or WOTS
counter search is exhausted. The API does not enforce a signing-use budget.

### Hash transcripts and separation

Addressed calls hash `"leanSPHINCS-192-v1" || variant || P || address || payload`.
The variant byte is 0 for forest and 1 for FORS. `P` is 24 bytes; the address uses
the existing 16-byte little-endian layout. Configured-seed derivation separately
binds hash, variant, total height, shape, and kept height, so reusing a seed under
another configuration does not share one-time keys. The original 128-bit
construction and its serialized outputs remain unchanged.

SHA2 uses SHA-256 for chain-secret derivation, WOTS/forest chain steps and FORS
leaves, and SHA-512 for encodings, multi-node hashes and the message digest.
SHAKE256 emits the requested output directly. These are maintained RustCrypto
implementations. The primitive choices follow the Category 3 approach in
[FIPS 205, §11](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.205.pdf); the
leanSphincs transcript, WOTS+C and forest are different from that standard.

The message-digest payload is `public_key || LE64(message_length) || message ||
randomizer`. Its 64-byte output is read least-significant-bit first: the low `h`
bits select the instance. Each forest coordinate then uses 4 bits for its
super-child followed by two `(3-bit child, 8-bit codeword)` fields. FORS instead
uses 37 consecutive 10-bit leaf fields. No message padding is inserted before
the randomizer, and arbitrary raw messages are length-delimited.

The deterministic randomizer walk uses HMAC-SHA-512 for SHA2, or SHAKE256 with the
32-byte secret prepended to the addressed, length-delimited message. Its first
48 bytes give a 24-byte start and a 24-byte step; the step's low bit is set.
Attempts add the step modulo 2^192, with at most 2^32 attempts. SHAKE derives
paired chain secrets with 48 output bytes; SHA2 uses distinct step-0/step-1 PRF
addresses, deriving 24 bytes from each SHA-256 call.

Forest addresses reserve four coordinate bits, giving strides 16, 256, 512 and
4096 for super-child, subtree, child and chain. FORS uses separate type bytes
20/21/22 for secret derivation, leaves and nodes. Address uniqueness, overflow
boundaries and digest fields that cross machine words have dedicated tests.

### What the analysis establishes

`scripts/level192.py` computes exact-binomial occupancy rather than a Poisson
approximation. Forest coverage retains the actual codeword multiplicities.
All arithmetic uses 100-digit outward-rounded intervals. Contributions beyond
the conditional-hit tables are enclosed conservatively, and the remaining
occupancy tail has an explicit geometric upper bound. Both sides of every
reported integer lifetime boundary are checked. The reported budget is where
this **cover model** remains at most 2^-192 per fresh digest query; it is not a
proved safe signing limit. Full and layered configurations pass that screen at
2^(h+4) signatures. Pruned budgets are recomputed for each kept height.

Additional attack routes and limitations:

- A 32-byte secret has a generic exhaustive-search space of 256 bits; published
  24-byte nodes expose 192-bit preimage targets. Multi-target reductions and
  adaptive signing effects still need a full security argument.
- The WOTS target is chosen by exact counting: 96 two-bit digits summing to 182
  need about 11,794 encoding attempts on average, versus about 14,670 in the
  original family. Matching an encoding, neighbouring encodings followed by
  chain preimages, and adversarial reuse of few-time instances remain distinct
  routes. Equal target sums rule out a different valid encoding obtained solely
  by advancing exposed WOTS chains: changing any digit then requires decreasing
  another. There are at most 96×95 immediate neighbours obtained by moving one
  unit between two digits; exploiting one also requires reversing a chain.
  The restricted encoding space must be considered together with the work of
  finding an admissible counter, not treated as a uniform 192-bit codeword.
  No adaptive multi-target bound for these combined routes is established here;
  the cover calculation does not bound them.
- Adding a hypothetical 2^-192 hash-search term to a 2^-192 cover term gives the
  repository's 191-bit classical screening convention. This union-bound
  arithmetic is not a reduction proving those hypotheses for this signer.
- Generic quantum preimage search has square-root query scaling (roughly 2^96
  for a 192-bit target); seed search has roughly 2^128 scaling. These are query
  estimates, not AES-equivalent gate costs or a Category 3 proof. Adaptive
  quantum cover/neighbor attacks, multiple keys and quantum-access assumptions
  remain unproved. The website therefore leaves quantum security and proved
  lifetimes unset.

The family keeps a single implementation of WOTS+C, tree construction, signing
and verification for both new few-time variants. It does not add formal proofs,
hardware-wallet support, threshold protocols, or device-rate extrapolations.

### Validation and measurements

```sh
cargo test --locked --workspace
python3 scripts/level192.py --check
python3 -m unittest discover -s scripts -p test_level192.py
cargo run --locked --release -p sphincs --example level192_vectors | python3 scripts/reference192.py
python3 scripts/scheme.py --json > site/data.json
```

The independent Python verifier uses `hashlib`/`hmac`, reconstructs each small
seeded public key and checks both few-time openings, WOTS+C, Merkle paths and
the least randomizer/counter. Rust regression vectors pin the results. Website
data includes all 156 combinations of hash, variant, height and shape/pruning;
operation counts distinguish SHA-256, SHA-512 and Keccak-f.

Normal builds omit diagnostic hash-operation accounting. Enable the `hash-counts`
Cargo feature to expose `level192::hash_counts`; unit tests enable accounting
automatically. The CPU runner enables the feature explicitly so its operation
counts remain available. Timings from that runner include the accounting work.

For CPU timings, first commit the source, then run on an otherwise idle machine:

```sh
python3 scripts/benchmark192.py --output /absolute/path/outside/checkout/benchmark-run
```

The runner compiles before measurement, performs a warm-up and three independent
batches, and records CPU, compiler, flags and source revision. It measures both
new variants across both hashes and every height, layered and with kept height
`max(12, h/2)`, alongside the original 128-bit forest. The original and new hashes
use different implementations, so their ratios are not parameter-only speedups.
Full-tree costs are modeled only. Raw samples and the summary stay outside Git;
measurements belong in the PR discussion, separate from the calculator's counts.

### Memory use

The 192-bit forest signer builds one coordinate at a time and keeps only the
selected opening. Lower hypertree layers retain one pending Merkle node per
height and the selected authentication path, rather than an entire temporary
tree. These changes preserve signature bytes, addresses and hash-operation
counts. The top tree remains cached in the secret key; its memory still grows
with the kept height.

`key_gen_with_cache` accepts `TreeCache::Recompute { levels }` to omit the bottom
tree levels from the cache. Each signature regenerates the aligned subtree of
`2^levels` leaves containing its signing location. Key generation streams leaves
through pending nodes, so the omitted levels are never allocated. The default
`key_gen` retains the full kept subtree. Both policies produce identical public
keys, signature bytes and signing-use limits; this setting is not part of the
configured seed.

For a height-20 SHA2 forest key pruned to height 8, regenerating two levels keeps
3,336 bytes of tree values instead of 12,552. Signing regenerates four WOTS leaves
and three internal nodes: 3,072 additional SHA-256 compressions and 79 additional
SHA-512 compressions. Verification and signature size remain unchanged.

```rust
use sphincs::level192::{self, Config, HashFn, Shape, TreeCache, Variant};

let cfg = Config::new(HashFn::Sha2, 20, Shape::Pruned { b: 8 }, Variant::Forest);
// Supply 32 bytes from the application's secure RNG; do not use this example seed.
let seed = [0u8; 32];
let (secret, public) = level192::key_gen_with_cache(
    &cfg, &seed, TreeCache::Recompute { levels: 2 },
);
```

`Signature::write_to` emits the existing wire format to a `std::io::Write`
destination without allocating another signature buffer. A write failure may
leave a partial signature in the destination. `encoded_len` reports the exact
length; `to_bytes` allocates that length once when an owned byte vector is needed.

Run the allocation regression check with:

```sh
cargo run --locked --release -p sphincs --features hash-counts,forest-precompute --example memory192 -- --check
cargo run --locked --release -p sphincs --features hash-counts,forest-precompute --example memory192 -- --check --cache-levels 2
```

The example covers both hash backends for height-20 forest keys, pruned at kept
height 8 and layered as 8+6+6. It verifies each signature, reports operation counts
and a signature fingerprint, and enforces signing-heap budgets of 24 KiB and
28 KiB respectively. The measured heap includes the retained key and signature.
Stack, static data, allocator overhead and application buffers are excluded;
this is not a total-RAM bound or hardware-wallet qualification. The example's
local timing observations also include allocation instrumentation overhead.
With `--cache-levels`, the heap budget is reduced by the omitted tree values.
The CPU runner accepts `--kept-height 8 --cache-levels 2` for the same configuration.

### Public forest precomputation

Public forest precomputation is **disabled by default**. The crate declares no
default Cargo features. Its preparation API and cache builder are compiled only
with `forest-precompute`, and even an enabled build allocates no public forest
cache through normal `key_gen`, `key_gen_with_cache` or `sign` calls. A caller
must explicitly call `prepare_forest` with a storage budget. Memory-limited
wallets can leave the feature disabled and use the normal API.

For a single-tree forest key, `prepare_forest` optionally generates public
coordinate-tree nodes for every retained signing instance. The returned
`PreparedForest` borrows the exact secret key that generated those nodes and
exposes deterministic signing. Its private cache cannot be imported, modified,
or paired with another key through the API. Parameters, public keys, signatures
and signing-use limits are identical to the normal signer.

For kept height 8, the public-node storage and per-signature work avoided are:

| Coordinate-tree level cached | Public node values | SHA-256 compressions avoided | SHA-512 compressions avoided |
|---|---:|---:|---:|
| 3: two coordinate tops | 144 KiB | 92,160 | 4,500 |
| 2: four nodes | 288 KiB | 138,240 | 6,732 |
| 1: eight nodes | 576 KiB | 161,280 | 7,812 |
| 0: sixteen super-child roots | 1,152 KiB | 172,800 | 8,280 |

These SHA2 deltas apply independently of the retained Merkle-tree cache policy.
Preparing all 256 instances costs 47,185,920 SHA-256 compressions and between
2,260,992 and 2,304,000 SHA-512 compressions. This is additional setup work,
separate from key generation. The normal signer does not prepare or retain this
data automatically.

```rust
// `secret` is a single-tree forest key. The budget covers public node values.
let prepared = level192::prepare_forest(&secret, 0, 2 * 1024 * 1024)
    .expect("configuration and public-cache budget");
let signature = prepared.sign(b"raw message bytes").expect("search exhausted");
```

The cache budget is checked before building any instance; unsupported variants,
layered keys and invalid cache levels are rejected. This implementation holds
the public values in ordinary allocated memory. It does not select PSRAM or
provide an external flash/cache import API. External mutable storage would need
separate authentication before permitting a reused WOTS key to sign a forest
key recovered from it.

The allocation example reports preparation cost, retained public-cache bytes,
and total signing heap separately. With precomputation enabled it exercises
single-tree keys only; other invocations retain the original coverage.
The harness enables cache support to test both paths. Without
`--precompute-level`, `--check` requires zero preparation hash work, zero cache
bytes and no temporary or retained preparation allocations.

```sh
cargo run --locked --release -p sphincs --features hash-counts,forest-precompute --example memory192 -- --check --hash SHA2 --cache-levels 2 --precompute-level 3
cargo run --locked --release -p sphincs --features hash-counts,forest-precompute --example memory192 -- --check --hash SHA2 --cache-levels 2 --precompute-level 0
```

## Credits

- [leanVM](https://github.com/leanEthereum/leanVM): the `sphincs` crate and the Lean security proof are adapted from it.
- Conduition: [hypertree pruning](https://conduition.io/cryptography/hypertree-pruning/).
- Jonas Nick: the WOTS forest, from his
  [sig.golf submission](https://github.com/Layr-Labs/sig.golf/commit/3321b777a511a6b454aad7ab721e8ab1af21c4d0).
- [Riva Labs](https://www.riva.xyz/): preparing FTS instances before the message, for hardware wallets
  and threshold signing.
