#!/usr/bin/env python3
"""Reproducible 192-bit cost tables and cover-model lifetime screening.

No dependencies beyond Python's standard library. `--json` writes the website's experimental
family to stdout; `--check` checks the screening threshold and numeric error enclosure.
The cover model is not a reduction, a quantum proof, or a certified safe signing limit.
"""
import argparse
from decimal import Decimal, localcontext, ROUND_CEILING, ROUND_FLOOR
from functools import lru_cache
from math import comb
from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "formal/sphincs/scripts"))
import forest_table

N, V, TARGET = 24, 96, 182
COORDS, FORS_K, FORS_A = 12, 37, 10
HEIGHTS = (20, 22, 24, 26, 28)
PRUNED = (8, 10, 12, 13, 14, 20)
LAYERS = {20: (8, 6, 6), 22: (10, 6, 6), 24: (10, 7, 7), 26: (10, 8, 8), 28: (10, 9, 9)}
PREFIX = len(b"leanSPHINCS-192-v1") + 1 + 24 + 16
PRECISION, MAX_HITS, MAX_CHILD_HITS = 100, 320, 96


def rounded(mode, operation):
    with localcontext() as ctx:
        ctx.prec, ctx.rounding = PRECISION, mode
        return operation()


class Interval:
    """Nonnegative intervals with outward-rounded arithmetic; every tail is retained."""
    def __init__(self, lo, hi=None):
        self.lo = Decimal(lo)
        self.hi = Decimal(lo if hi is None else hi)

    def __add__(self, other):
        return Interval(rounded(ROUND_FLOOR, lambda: self.lo + other.lo),
                        rounded(ROUND_CEILING, lambda: self.hi + other.hi))

    def __mul__(self, other):
        return Interval(rounded(ROUND_FLOOR, lambda: self.lo * other.lo),
                        rounded(ROUND_CEILING, lambda: self.hi * other.hi))

    def __truediv__(self, other):
        assert other.lo > 0
        return Interval(rounded(ROUND_FLOOR, lambda: self.lo / other.hi),
                        rounded(ROUND_CEILING, lambda: self.hi / other.lo))

    def __pow__(self, n):
        assert n >= 0
        return Interval(rounded(ROUND_FLOOR, lambda: self.lo ** n),
                        rounded(ROUND_CEILING, lambda: self.hi ** n))


@lru_cache(maxsize=1)
def conditional_cover():
    """Coverage conditional on r previous signatures at one instance, r=0..MAX_HITS.

    The forest's repeated table entries keep their actual multiplicities. Above MAX_CHILD_HITS
    the monotone child-cover probability is enclosed by [f(MAX_CHILD_HITS), 1].
    """
    numerators, _ = forest_table.f_tabs(U=MAX_CHILD_HITS)
    f = [Interval(n) / Interval(256 ** (r + 1)) for r, n in enumerate(numerators)]
    mu = []
    for r in range(MAX_HITS + 1):
        total = Interval(0)
        for u in range(r + 1):
            covered = f[u] if u <= MAX_CHILD_HITS else Interval(f[-1].lo, 1)
            total += Interval(comb(r, u) * 7 ** (r-u)) * covered
        mu.append(total / Interval(8 ** r))
    forest, fors = [], []
    for r in range(MAX_HITS + 1):
        total = Interval(0)
        for u in range(r + 1):
            total += Interval(comb(r, u) * 15 ** (r-u)) * (mu[u] ** 2)
        forest.append((total / Interval(16 ** r)) ** COORDS)
        fors.append((Interval(1024 ** r - 1023 ** r) / Interval(1024 ** r)) ** FORS_K)
    return {"forest": forest, "fors": fors}


def cover_probability(variant, h, b, signatures):
    """Exact binomial occupancy, enclosed numerically, plus an explicit geometric tail bound."""
    assert 0 <= b <= h and signatures >= 0
    table = conditional_cover()[variant]
    denominator = 1 << b
    probability = (Interval(denominator-1) / Interval(denominator)) ** signatures
    total = probability * table[0]
    stop = min(MAX_HITS, signatures)
    for r in range(1, stop + 1):
        probability *= Interval(signatures-r+1) / Interval(r * (denominator-1))
        total += probability * table[r]
    if stop < signatures:
        next_probability = probability * Interval(signatures-stop) / Interval((stop+1)*(denominator-1))
        ratio = Interval(signatures-stop-1) / Interval((stop+2)*(denominator-1))
        if ratio.hi >= 1:
            return Interval(0, 1)
        divisor = Interval(rounded(ROUND_FLOOR, lambda: 1-ratio.hi),
                           rounded(ROUND_CEILING, lambda: 1-ratio.lo))
        tail = next_probability / divisor
        total += Interval(0, tail.hi)
    return total / Interval(1 << (h-b))


@lru_cache(maxsize=None)
def cover_limit(variant, h, b):
    """Last integer budget whose cover probability is at most 2^-192.

    Combining that term with a hypothetical 2^-192 hash-search term yields 191 bits by a union
    bound. That arithmetic alone proves neither term for the adaptive full scheme.
    """
    threshold = Interval(1) / Interval(1 << 192)
    lo, hi = 0, 128 << b
    assert cover_probability(variant, h, b, hi).hi > threshold.lo
    while lo + 1 < hi:
        middle = (lo+hi)//2
        if cover_probability(variant, h, b, middle).hi <= threshold.lo:
            lo = middle
        else:
            hi = middle
    accepted = cover_probability(variant, h, b, lo)
    rejected = cover_probability(variant, h, b, lo+1)
    assert accepted.hi <= threshold.lo
    assert rejected.lo > threshold.hi, "increase precision or tail cutoff to resolve the boundary"
    return lo


def vector(sha256=0, sha512=0, keccak=0):
    return {"sha256": sha256, "sha512": sha512, "keccak": keccak}


def plus(*values):
    return {key: sum(v[key] for v in values) for key in vector()}


def times(value, count):
    return {key: n * count for key, n in value.items()}


def cost(hash_name, small, payload, output=24, addressed=True):
    length = payload + (PREFIX if addressed else 0)
    if hash_name == "SHAKE256":
        return vector(keccak=length//136 + 1 + (output-1)//136)
    if small:
        return vector(sha256=(length+9+63)//64)
    return vector(sha512=(length+17+127)//128)


def verify_cost(hash_name, variant, h, shape, message_bytes=32):
    c = lambda small, size, n=1: times(cost(hash_name, small, size), n)
    result = cost(hash_name, False, 48+8+message_bytes+24, output=64)
    if variant == "forest":
        result = plus(result, c(True, 24, 12*2*5), c(False, 6*24, 12*2),
                      c(False, 2*24, 12*(2*2+3)), c(False, 4*24, 12))
        roots = 24
    else:
        result = plus(result, c(True, 24, 37), c(False, 48, 37*9))
        roots = 74
    layers = tuple(reversed(LAYERS[h])) if shape == "layered" else (h,)
    for layer, height in enumerate(layers):
        result = plus(result, c(False, (roots*24 if layer == 0 else 24)+4),
                      c(True, 24, 96*3-182), c(False, 96*24), c(False, 48, height))
    return result


def keygen_cost(hash_name, variant, h, shape, b):
    """Count full keygen, including configured seed and public-parameter derivation."""
    top = LAYERS[h][0] if shape == "layered" else h
    kept = top if shape == "layered" else b
    derive = cost(hash_name, True, 32, output=48 if hash_name == "SHAKE256" else 24)
    if hash_name == "SHA2":
        derive = times(derive, 2)
    leaf = plus(times(derive, 48), times(cost(hash_name, True, 24), 288), cost(hash_name, False, 96*24))
    node = cost(hash_name, False, 48)
    return plus(cost(hash_name, False, len(b"leanSPHINCS-192-v1 configured seed")+5+32, output=32, addressed=False),
                cost(hash_name, False, 32), times(leaf, 1 << kept), times(node, (1 << kept)-1),
                times(plus(cost(hash_name, False, 32), node), top-kept))


def signature_size(variant, h, shape):
    opening = 12*22 if variant == "forest" else 37*11
    layers = 3 if shape == "layered" else 1
    return 24 + opening*24 + layers*(4+96*24) + h*24


def site_data():
    configs = []
    for h in HEIGHTS:
        shapes = [("pruned", b) for b in (*PRUNED, h) if b < h] + [("pruned", h), ("layered", h)]
        for shape, b in shapes:
            for variant in ("forest", "fors"):
                limit = cover_limit(variant, h, b)
                for hash_name in ("SHAKE256", "SHA2"):
                    configs.append(dict(hash=hash_name, variant=variant, h=h, shape=shape, b=b,
                                        layers=list(LAYERS[h] if shape == "layered" else (h,)),
                                        size=signature_size(variant, h, shape), public_key_bytes=48,
                                        verify=verify_cost(hash_name, variant, h, shape),
                                        keygen=keygen_cost(hash_name, variant, h, shape, b),
                                        cover_model_signatures=limit, proven_lifetime=None,
                                        quantum_security_bits=None, measured_cpu=None, device_seconds=None))
    return {"status": "experimental", "message_bytes": 32, "cover_threshold_bits": 192,
            "classical_screening_convention_bits": 191, "precision_digits": PRECISION,
            "max_hits": MAX_HITS, "max_child_hits": MAX_CHILD_HITS, "configs": configs}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    data = site_data()
    if args.check:
        for variant in ("forest", "fors"):
            for h in HEIGHTS:
                assert cover_limit(variant, h, h) >= 1 << (h+4)
        assert len(data["configs"]) == 156
        print("All 78 variant/shape lifetime boundaries are enclosed; full/layered targets pass the cover screen.")
    elif args.json:
        print(json.dumps(data, indent=1))
    else:
        print("Experimental cover-model limits only; whole-scheme and quantum security remain unproved.")
        for row in data["configs"]:
            if row["hash"] == "SHAKE256":
                print(row["variant"], row["h"], row["shape"], row["b"], row["cover_model_signatures"], row["size"])


if __name__ == "__main__":
    main()
