# Test vectors for the Windows minisign verifier

Used by `../Test-Verifier.ps1` to test the C# BLAKE2b-512 and Ed25519 code embedded in `packaging/windows/install.ps1`.

| File | Source | License |
|---|---|---|
| `ed25519_test.json` | Project Wycheproof, `testvectors_v1/ed25519_test.json` from https://github.com/C2SP/wycheproof (fetched 2026-10-01, unmodified) | Apache-2.0 |
| `blake2b_kat.json` | BLAKE2 reference KAT, the 256 unkeyed `blake2b` entries (inputs of 0 to 255 bytes) from `testvectors/blake2-kat.json` in https://github.com/BLAKE2/BLAKE2 | CC0-1.0 |
| `blake2b_long.json` | RFC 7693 Appendix A ("abc"), plus multi-block inputs (1 MiB to 5 MiB) hashed with coreutils `b2sum -l 512` and cross-checked against Python `hashlib.blake2b` | — |

Do not edit the vector files by hand; re-fetch them from the source.
