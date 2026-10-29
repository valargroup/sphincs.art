#!/usr/bin/env python3
"""Independent hashlib verifier and seeded public-key oracle for the 192-bit public test vectors.

Read JSON lines produced by `cargo run --release -p sphincs --example level192_vectors` on stdin.
Rebuild the 256-leaf pruned public key from the documented disposable seed, recover the forest or
FORS and each WOTS signature, and verify deterministic grinding independently using Python ints.
`--hash-vectors` emits the small hash-transcript fixtures; no secret user inputs are accepted.
"""
import argparse
import hashlib
import hmac
import itertools
import json
import sys

DOMAIN = b"leanSPHINCS-192-v1"
N = 24


def address(kind, hi, lo, step=0, layer=0, tree=0):
    return (lo.to_bytes(4, "little") + hi.to_bytes(3, "little") + bytes([kind + 32*step, layer])
            + tree.to_bytes(4, "little") + bytes(3))


class Reference:
    def __init__(self, hash_name, variant, public_param):
        self.hash = hash_name
        self.variant = variant
        self.variant_id = int(variant == "fors")
        self.prefix = DOMAIN + bytes([self.variant_id]) + public_param

    def raw(self, data, small=False, length=24):
        if self.hash == "SHAKE256":
            return hashlib.shake_256(data).digest(length)
        return (hashlib.sha256(data) if small else hashlib.sha512(data)).digest()[:length]

    def hash_at(self, kind, hi, lo, data, *, step=0, layer=0, tree=0, length=24):
        return self.raw(self.prefix + address(kind, hi, lo, step, layer, tree) + data,
                        small=kind in (0, 1, 14, 15, 20, 21), length=length)

    def pair(self, kind, hi, lo, seed):
        if self.hash == "SHAKE256":
            out = self.hash_at(kind, hi, lo, seed, length=48)
            return out[:24], out[24:]
        return tuple(self.hash_at(kind, hi, lo, seed, step=side) for side in (0, 1))

    def walk(self, seed, message):
        transcript = self.prefix + address(7, 0, 0) + len(message).to_bytes(8, "little") + message
        out = (self.raw(seed + transcript, length=48) if self.hash == "SHAKE256"
               else hmac.digest(seed, transcript, "sha512")[:48])
        return int.from_bytes(out[:24], "little"), int.from_bytes(out[24:], "little") | 1

    def digest(self, pk, message, rho):
        return self.hash_at(12, 0, 0, pk + len(message).to_bytes(8, "little") + message + rho, length=64)

    def wots_leaf(self, seed, leaf):
        ends = []
        for pair in range(48):
            for side, secret in enumerate(self.pair(0, pair, leaf, seed)):
                value = secret
                for step in range(3):
                    value = self.hash_at(1, 2*pair+side, leaf, value, step=step)
                ends.append(value)
        return self.hash_at(2, 0, leaf, b"".join(ends))

    def public_key(self, seed):
        start = (int.from_bytes(self.prefix[-24:-16], "little") & ((1 << 12)-1)) << 8
        level = [self.wots_leaf(seed, start+j) for j in range(256)]
        for height in range(1, 9):
            level = [self.hash_at(3, height, (start >> height)+j, level[2*j] + level[2*j+1])
                     for j in range(len(level)//2)]
        value = level[0]
        for height in range(8, 20):
            sibling = self.hash_at(13, height, 0, seed)
            payload = sibling + value if (start >> height) & 1 else value + sibling
            value = self.hash_at(3, height+1, start >> (height+1), payload)
        return value + self.prefix[-24:]


def read_bits(data, offset, width):
    return (int.from_bytes(data, "little") >> offset) & ((1 << width)-1)


def ordered(index, value, sibling):
    return (sibling, value) if index & 1 else (value, sibling)


def verify_vector(row):
    hash_name, variant = row["hash"], row["variant"]
    pk, message, signature = (bytes.fromhex(row[k]) for k in ("public_key", "message", "signature"))
    ref = Reference(hash_name, variant, pk[24:])
    seed_input = DOMAIN + b" configured seed" + bytes([int(hash_name == "SHA2"), ref.variant_id, 20, 0, 8]) + bytes([3])*32
    seed = ref.raw(seed_input, length=32)
    zero = Reference(hash_name, variant, bytes(24))
    assert zero.hash_at(5, 0, 0, seed) == pk[24:]
    assert ref.public_key(seed) == pk, "seeded public key mismatch"
    assert hashlib.sha512(signature).hexdigest() == row["signature_sha512"]
    at = 0

    def take(size=24):
        nonlocal at
        result = signature[at:at+size]
        assert len(result) == size
        at += size
        return result

    rho = take()
    digest = ref.digest(pk, message, rho)
    index = read_bits(digest, 0, 20)
    kept = int.from_bytes(pk[24:32], "little") & ((1 << 12)-1)
    assert index >> 8 == kept
    base, step = ref.walk(seed, message)
    attempt = ((int.from_bytes(rho, "little")-base) * pow(step, -1, 1 << 192)) % (1 << 192)
    assert attempt < 1 << 32
    for i in range(attempt):
        rejected = ((base+i*step) % (1 << 192)).to_bytes(24, "little")
        assert read_bits(ref.digest(pk, message, rejected), 0, 20) >> 8 != kept
    roots = []
    if variant == "fors":
        for tree in range(37):
            leaf = read_bits(digest, 20+tree*10, 10)
            value = ref.hash_at(21, (tree << 10)+leaf, index, take())
            path = [take() for _ in range(10)]
            for level in range(9):
                left, right = ordered(leaf >> level, value, path[level])
                value = ref.hash_at(22, (tree << 14) | (level << 10) | (leaf >> (level+1)), index, left+right)
            roots.extend(ordered(leaf >> 9, value, path[9]))
    else:
        words = sorted((w for w in itertools.product(range(5), repeat=6) if sum(w) == 5),
                       key=lambda w: (-sum(d*d for d in w), w))
        for coordinate in range(12):
            offset = 20+26*coordinate
            super_child = read_bits(digest, offset, 4)
            sub_roots = []
            for sub in range(2):
                child = read_bits(digest, offset+4+11*sub, 3)
                word = words[read_bits(digest, offset+7+11*sub, 8) % 214]
                ends = []
                for chain in range(6):
                    value = take()
                    for step in range(4-word[chain], 4):
                        value = ref.hash_at(15, coordinate+16*super_child+256*sub+512*child+4096*chain,
                                            index, value, step=step)
                    ends.append(value)
                path = [take() for _ in range(3)]
                value = ref.hash_at(16, coordinate+16*super_child+256*sub+512*child, index, b"".join(ends))
                for level in range(2):
                    left, right = ordered(child >> level, value, path[level])
                    value = ref.hash_at(17, coordinate+16*super_child+256*sub+512*(level+1)+2048*(child >> (level+1)), index, left+right)
                sub_roots.extend(ordered(child >> 2, value, path[2]))
            value = ref.hash_at(18, coordinate+16*super_child, index, b"".join(sub_roots))
            path = [take() for _ in range(4)]
            for level in range(3):
                left, right = ordered(super_child >> level, value, path[level])
                value = ref.hash_at(19, coordinate+16*(level+1)+128*(super_child >> (level+1)), index, left+right)
            roots.extend(ordered(super_child >> 3, value, path[3]))
    payload = b"".join(roots)
    counter_bytes = take(4)
    counter = int.from_bytes(counter_bytes, "little")
    digest = ref.hash_at(4, 0, index, payload+counter_bytes)
    digits = [read_bits(digest, 2*i, 2) for i in range(96)]
    assert sum(digits) == 182
    for c in range(counter):
        earlier = ref.hash_at(4, 0, index, payload+c.to_bytes(4, "little"))
        assert sum(read_bits(earlier, 2*i, 2) for i in range(96)) != 182
    ends = []
    for chain, digit in enumerate(digits):
        value = take()
        for step in range(digit, 3):
            value = ref.hash_at(1, chain, index, value, step=step)
        ends.append(value)
    value = ref.hash_at(2, 0, index, b"".join(ends))
    for level in range(20):
        left, right = ordered(index >> level, value, take())
        value = ref.hash_at(3, level+1, index >> (level+1), left+right)
    assert value == pk[:24], "signature root mismatch"
    assert at == len(signature)
    return f"{hash_name} {variant} {pk.hex()} {row['signature_sha512']}"


def hash_vectors():
    print("# Independent Python hashlib/hmac fixtures; regenerate with scripts/reference192.py --hash-vectors.")
    for name in ("SHAKE256", "SHA2"):
        ref = Reference(name, "forest", bytes([3])*24)
        cases = {
            "chain": ref.hash_at(1, 7, 11, bytes([9])*24, step=2, layer=1, tree=3),
            "node": ref.hash_at(3, 2, 3, bytes([4])*24 + bytes([5])*24),
            "pair": b"".join(ref.pair(0, 3, 7, bytes([11])*32)),
        }
        message = b"raw message\0bytes"
        data = ref.prefix + address(7, 0, 0) + len(message).to_bytes(8, "little") + message
        cases["randomizer"] = (ref.raw(bytes([13])*32+data, length=48) if name == "SHAKE256"
                               else hmac.digest(bytes([13])*32, data, "sha512")[:48])
        for label, value in cases.items():
            print(name, label, value.hex())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--hash-vectors", action="store_true")
    args = parser.parse_args(argv)
    if args.hash_vectors:
        hash_vectors()
        return
    seen = set()
    for line in sys.stdin:
        row = json.loads(line)
        identity = row["hash"], row["variant"]
        assert identity not in seen
        seen.add(identity)
        print(verify_vector(row))
    assert seen == {(h, v) for h in ("SHAKE256", "SHA2") for v in ("forest", "fors")}


if __name__ == "__main__":
    main()
