//! Deterministic public test vectors for the independent Python verifier. Never use these seeds.
use sha2::{Digest, Sha512};
use sphincs::{Shape, level192::*};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() {
    for hash in HashFn::ALL {
        for variant in Variant::ALL {
            let cfg = Config::new(hash, 20, Shape::Pruned { b: 8 }, variant);
            let (sk, pk) = key_gen(&cfg, &[3; 32]);
            let message = b"independent 192-bit reference\0message";
            let sig = sign(&sk, message).unwrap();
            let bytes = sig.to_bytes();
            println!(
                "{{\"hash\":\"{}\",\"variant\":\"{}\",\"public_key\":\"{}\",\"message\":\"{}\",\"signature\":\"{}\",\"signature_sha512\":\"{}\"}}",
                hash.name(),
                variant.name(),
                hex(&pk.to_bytes()),
                hex(message),
                hex(&bytes),
                hex(&Sha512::digest(&bytes))
            );
        }
    }
}
