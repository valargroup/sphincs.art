#!/usr/bin/env python3
"""Run the sequential Rust CPU matrix, retaining raw measurements and provenance outside Git.

Builds first; the timed process starts only after compilation finishes. The output directory holds
metadata.json, samples.jsonl and summary.md. No hardware-wallet rates are inferred from CPU timing.
"""
import argparse
from collections import defaultdict
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import time

import level192

ROOT = Path(__file__).resolve().parents[1]


def read_command(argv):
    return subprocess.check_output(argv, cwd=ROOT, text=True, timeout=30).strip()


def summarize(rows):
    groups = defaultdict(list)
    for row in rows:
        key = tuple(row[k] for k in ("family", "hash", "variant", "h", "shape", "b"))
        groups[key].append(row)
    output = ["Timings are median [minimum–maximum], milliseconds. Signing includes every sampled message.",
              "128 and 192 use different hash implementations and constructions; ratios are not parameter-only speedups.",
              "", "| Family / hash / variant | h / shape / b | Key generation | Signing | Verification | Bytes | Batches |",
              "|---|---|---:|---:|---:|---:|---:|"]
    def cell(values):
        values = [v / 1_000_000 for v in values]
        return f"{statistics.median(values):.3f} [{min(values):.3f}–{max(values):.3f}]"
    for key, samples in sorted(groups.items()):
        family, hash_name, variant, h, shape, b = key
        output.append(f"| {family} / {hash_name} / {variant} | {h} / {shape} / {b} | "
                      f"{cell([s['keygen_ns'] for s in samples])} | "
                      f"{cell([n for s in samples for n in s['sign_ns']])} | "
                      f"{cell([s['verify_ns'] for s in samples])} | {samples[0]['signature_bytes']} | {len(samples)} |")
    return "\n".join(output) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--families", default="128,192")
    parser.add_argument("--hashes", default="Keccak-256,BLAKE2s,SHA-256,SHAKE256,SHA2")
    parser.add_argument("--heights", default="20,22,24,26,28")
    parser.add_argument("--shapes", default="pruned,layered")
    parser.add_argument("--variants", default="forest,fors")
    parser.add_argument("--kept-height", type=int, default=0,
                        help="override the pruned kept height; zero uses max(12, h/2)")
    parser.add_argument("--cache-levels", type=int, default=0,
                        help="192-bit tree levels regenerated during signing instead of retained")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--messages", type=int, default=3)
    parser.add_argument("--verify-iters", type=int, default=1000)
    args = parser.parse_args(argv)
    assert args.runs >= 3 and args.messages >= 1 and args.verify_iters >= 1
    if args.cache_levels < 0 or (args.cache_levels and args.families != "192"):
        parser.error("cache levels require family 192 and a nonnegative count")
    destination = args.output.expanduser().resolve()
    if destination.is_relative_to(ROOT):
        parser.error("raw benchmark output must be outside the checkout")
    if destination.exists():
        parser.error("output directory already exists; preserve the previous run")
    dirty = read_command(["git", "status", "--porcelain"])
    if dirty:
        parser.error("commit the benchmarked source first so measurements identify an immutable revision")
    destination.mkdir(parents=True)
    commit = read_command(["git", "rev-parse", "HEAD"])
    cpu = read_command(["sysctl", "-n", "machdep.cpu.brand_string"]) if platform.system() == "Darwin" else platform.processor()
    metadata = dict(commit=commit, dirty=False, compiler=read_command(["rustc", "--version", "--verbose"]),
                    cargo=read_command(["cargo", "--version"]), os=platform.platform(), cpu=cpu,
                    cargo_config=(ROOT / ".cargo/config.toml").read_text(),
                    cargo_manifest=(ROOT / "Cargo.toml").read_text(),
                    flag_overrides={key: os.environ.get(key) for key in
                                    ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_PROFILE_RELEASE_OPT_LEVEL",
                                     "CARGO_PROFILE_RELEASE_LTO", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS")},
                    arguments={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
                    threads=1, warmup_batches=1, message_bytes=32, status="building")
    def save():
        (destination / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
    save()
    try:
        build = subprocess.run(["cargo", "build", "--locked", "--release", "-p", "sphincs", "--bench", "configurations", "--message-format=json"],
                               cwd=ROOT, text=True, stdout=subprocess.PIPE, check=True, timeout=600)
        artifacts = [json.loads(line) for line in build.stdout.splitlines() if line.startswith("{")]
        binaries = [a["executable"] for a in artifacts if a.get("reason") == "compiler-artifact" and a.get("target", {}).get("name") == "configurations" and a.get("executable")]
        assert len(set(binaries)) == 1
        command = [binaries[0]]
        for key in ("families", "hashes", "heights", "shapes", "variants", "runs", "messages", "verify_iters", "kept_height", "cache_levels"):
            command += ["--" + key.replace("_", "-"), str(getattr(args, key))]
        metadata.update(status="running", started_utc=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        load_average_start=list(os.getloadavg()), logical_cpus=os.cpu_count())
        save()
        started = time.monotonic()
        with (destination / "samples.jsonl").open("w") as output:
            subprocess.run(command, cwd=ROOT, stdout=output, check=True, timeout=7200)
        metadata["elapsed_seconds"] = time.monotonic()-started
        metadata["load_average_end"] = list(os.getloadavg())
        assert read_command(["git", "rev-parse", "HEAD"]) == commit and not read_command(["git", "status", "--porcelain"]), "source changed during measurement"
        rows = [json.loads(line) for line in (destination / "samples.jsonl").read_text().splitlines()]
        expected = set()
        for family in args.families.split(","):
            hashes = ("Keccak-256", "BLAKE2s", "SHA-256") if family == "128" else ("SHAKE256", "SHA2")
            for hash_name in hashes:
                if hash_name not in args.hashes.split(","):
                    continue
                for variant in (("forest",) if family == "128" else ("forest", "fors")):
                    if variant in args.variants.split(","):
                        for h in map(int, args.heights.split(",")):
                            for shape in args.shapes.split(","):
                                for run in range(1, args.runs+1):
                                    expected.add((int(family), hash_name, variant, h, shape, run))
        actual = [tuple(r[k] for k in ("family", "hash", "variant", "h", "shape", "run")) for r in rows]
        assert len(actual) == len(set(actual)) and set(actual) == expected and expected, "incomplete matrix"
        for row in rows:
            if row["family"] == 192:
                hash_name, variant, h, shape = (row[k] for k in ("hash", "variant", "h", "shape"))
                assert row["signature_bytes"] == level192.signature_size(variant, h, shape)
                assert row["keygen_counts"] == level192.keygen_cost(hash_name, variant, h, shape, row["b"])
                assert row["verify_counts"] == level192.verify_cost(hash_name, variant, h, shape, row["message_bytes"])
        metadata.update(status="complete", samples=len(rows))
        (destination / "summary.md").write_text(summarize(rows))
    except BaseException as exc:
        metadata.update(status="failed", error=type(exc).__name__)
        raise
    finally:
        save()
    print(f"Completed {len(rows)} batches at {commit}; results: {destination}")


if __name__ == "__main__":
    main()
