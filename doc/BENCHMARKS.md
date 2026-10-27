# Benchmarks

Measured with `benchmark/main.dart` on 2026-10-27, Apple M-series (arm64),
macOS 26, Dart SDK 3.13.5, post_quantum_crypto 1.0.0 with the default
`standardCryptoBackend`. Single-threaded; mean per operation. Expect large
variation across devices; mobile and low-end hardware will be slower.

| Operation | VM (AOT `dart compile exe`) | JavaScript (dart2js -O2, node 26) | WebAssembly (dart2wasm -O2, node 26) |
|---|---:|---:|---:|
| AES-256-GCM, 1 MiB | 47.7 ms (21.0 MiB/s) | 38.9 ms (25.7 MiB/s) | 40.6 ms (24.6 MiB/s) |
| ChaCha20-Poly1305, 1 MiB | 24.0 ms (41.6 MiB/s) | 19.7 ms (50.8 MiB/s) | 23.5 ms (42.5 MiB/s) |
| SHA-384, 1 MiB | 2.6 ms (382 MiB/s) | 32.1 ms (31.1 MiB/s) | 22.7 ms (44.1 MiB/s) |
| ML-KEM-768 keygen | 0.35 ms | 0.71 ms | 0.41 ms |
| ML-KEM-768 envelope encrypt (32 B) | 0.87 ms | 2.15 ms | 1.38 ms |
| ML-KEM-768 envelope decrypt (32 B) | 0.88 ms | 2.05 ms | 1.30 ms |
| ML-KEM-1024 envelope encrypt | 1.08 ms | 2.59 ms | 1.63 ms |
| X-Wing keygen | 0.65 ms | 1.77 ms | 0.61 ms |
| X-Wing envelope encrypt | 1.48 ms | 4.30 ms | 1.79 ms |
| X-Wing envelope decrypt | 1.19 ms | 3.14 ms | 1.51 ms |
| ML-DSA-65 keygen | 1.18 ms | 1.98 ms | 1.33 ms |
| ML-DSA-65 sign (1 KiB) | 3.20 ms | 8.17 ms | 3.36 ms |
| ML-DSA-65 verify | 0.96 ms | 2.09 ms | 1.14 ms |
| ML-DSA-87 sign | 4.00 ms | 11.3 ms | 4.19 ms |
| Envelope encrypt, 8 MiB | 406 ms (19.7 MiB/s) | 300 ms (26.7 MiB/s) | 368 ms (21.8 MiB/s) |
| Argon2id 19 MiB, t=2, p=1 | 67 ms | 2577 ms | 1967 ms |

Streaming file encryption (`tool/memory_probe.dart`, AOT, 64 KiB chunks):
about **19 MiB/s** encrypt and decrypt. Peak RSS was **53 MiB for both a
64 MiB and a 512 MiB file**, so memory does not grow with file size.

Notes:

- The symmetric layer is the throughput bottleneck: pure-Dart AES-GCM is
  ~20–25 MiB/s on every target. ChaCha20-Poly1305 is about twice as fast.
  A native backend (`CryptoBackend` with a platform `SymmetricProvider`) is
  the way to go faster.
- PointyCastle's own AES-GCM measured **1.8 MiB/s** on the VM, which is why
  the default backend takes AES-GCM and SHA-2 from package:cryptography
  (`pointyCastleCryptoBackend` keeps the all-PointyCastle variant).
- Argon2id is slow on the web targets; the default 64 MiB / t=3 export takes
  several seconds there.
- The SLH-DSA "s" parameter sets sign in seconds in pure Dart; prefer the "f"
  sets or ML-DSA where signing speed matters.
