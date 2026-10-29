# Security model, guarantees and limitations

## Review status

- **No independent cryptographic review** of this package's design or code
  has been performed. The formats are custom (built from standardized parts)
  and should be reviewed before high-assurance use.
- The underlying primitives are validated here against official
  known-answer vectors (NIST ACVP for ML-KEM/ML-DSA/SLH-DSA, the X-Wing and
  HPKE-PQ drafts, Wycheproof for AES-GCM/ChaCha20-Poly1305/HKDF/HMAC/X25519,
  RFC 9106 for Argon2id), against Wycheproof's ML-KEM and ML-DSA edge cases
  (malformed and out-of-range keys, ciphertexts and signatures), against the
  example keys of RFC 9881 (ML-DSA) and RFC 9935 (ML-KEM), including their
  deliberately inconsistent keys, and against OpenSSL 3.6 for ML-KEM, ML-DSA
  and SLH-DSA. That is **algorithm conformance evidence**, not a FIPS 140 /
  CMVP module validation, and none of the dependencies is FIPS-validated
  either.
- Imported **expanded private keys are checked for consistency**: ML-KEM
  keys by the FIPS 203 hash check and a pairwise-consistency test (an
  encapsulation must decapsulate); ML-DSA keys by recomputing
  `t = A·s1 + s2` (FIPS 204), which checks the s1/s2 ranges and `t0` and
  derives the public key; SLH-DSA keys by recomputing `PK.root` from
  `SK.seed` and `PK.seed` (FIPS 205 Algorithm 18). For the SLH-DSA "s"
  parameter sets this costs a key generation, 1–2 s in pure Dart, on every
  import and every key-store load. Loading a key record (`decodeKey`,
  `importPrivateKeyWithPassword`, `KeyStore.get`) can skip it with
  `verifySlhDsaKey: false`; an inconsistent key then loads and produces
  only signatures that fail verification. PKCS#8 and raw imports are always
  checked.

## What the primitives provide

| Feature | Confidentiality | Integrity | Origin authentication |
|---|---|---|---|
| Envelope / stream encryption | ✔ (recipients only) | ✔ (any change is detected) | ✘: anyone with a recipient's public key can create a valid envelope |
| Authenticated context (AAD) | ✘ (stored in clear) | ✔ | ✘ |
| Signatures | ✘ | ✔ | ✔ for the holder of the private key |
| Hybrid key establishment | ✔ session key | — | ✘: unauthenticated |
| Password encryption | ✔ (password-bounded) | ✔ | ✘ |

- **Confidentiality** ≠ **authenticity**: to know *who* sent an envelope,
  sign it (for example sign the envelope bytes or include a signed artifact).
- **A valid signature ≠ a trusted signer.** Verification proves that the
  holder of a key signed the bytes. Whether that key belongs to whom you think,
  is authorized and is still valid is a trust decision (`TrustStore`, key
  metadata, your PKI).
- **Public keys must be authentic.** Encrypting to an attacker's key gives the
  attacker the data. Distribute and pin keys through a trusted channel.

## Design choices

- Recipient key wrapping is HPKE (RFC 9180) base mode with ML-KEM / X-Wing,
  HKDF-SHA-384 and AES-256-GCM. The KEM shared secret is never used directly
  as an AEAD key.
- Every envelope and stream uses a fresh random 256-bit DEK, so AEAD nonces
  are never reused under a key: one random nonce per envelope DEK; a counter
  nonce per stream key; one nonce per HPKE context.
- **Key commitment** (format 2). Envelopes, streams and password objects
  derive their payload key together with a stored 32-byte commitment that is
  checked before the AEAD opens (doc/FORMATS.md, "Key commitment"). A
  malicious sender cannot make one multi-recipient envelope or stream
  decrypt to different plaintexts for different recipients ("invisible
  salamanders"), and a password object opens under at most one password (no
  partitioning oracles). Signing an envelope therefore also pins the one
  plaintext every recipient sees. Format 1 (package 1.x) lacked this and is
  not read.
- Decryption errors are uniform (`DecryptionFailedException`) after parsing,
  and ML-KEM implicit rejection is preserved, to avoid decryption and
  decapsulation oracles. Two distinctions are visible and are not secret:
  `KeyNotFoundException` (the envelope lists public key ids) and
  `ContextMismatchException` (the context is stored in clear).
- No plaintext is released by one-shot decryption before authentication.
  Streaming decryption releases each chunk after it authenticates; the whole
  stream is only known to be complete at the end (see `decryptFile` for
  publish-after-verify).
- No fallback: there is no classical-only mode and no weaker random source.
  `Random.secure()` failure raises `SecureRandomUnavailableException`.
- All parsers are strict and bounded; hostile length fields cannot trigger
  large allocations, and Argon2id parameters are bounded before use.
- Deterministic randomness exists only under `test/` and is injected through
  a `@visibleForTesting` constructor.
- Signed objects sign a domain-prefixed encoding
  (`post_quantum_crypto/v1/detached-signature\0`,
  `post_quantum_crypto/v1/manifest\0`). Raw `sign` refuses messages that
  start with those prefixes, so a key that also raw-signs messages chosen by
  others cannot be made to produce a detached signature or manifest.
- Canonical maps, manifest paths and key metadata decode UTF-8 losslessly: a
  leading U+FEFF is kept, so distinct encodings never decode to the same
  string (and a map can never carry two entries under one key).

## X-Wing / hybrid assumptions

X-Wing's combined secret is secure if **either** ML-KEM-768 (lattice, MLWE)
**or** X25519 (classical ECDH, broken by a large quantum computer) is secure,
under the assumptions of draft-connolly-cfrg-xwing-kem (SHA3-256 as a random
oracle/PRF). The hybrid API is a KEM-based **unauthenticated** key
establishment, not TLS and not an AKE; the transcript binding only ensures
both sides agree on the labels they supplied.

## Limitations

- **Side channels.** Dart does not guarantee constant-time execution on the
  VM, JavaScript or WebAssembly. Code avoids obvious data-dependent branches
  (and pqcrypto selects implicit-rejection results branchlessly), but no
  constant-time or side-channel-resistance claim is made.
- **Memory hygiene is best-effort.** `destroy()` and internal zeroization
  overwrite buffers, but the garbage collector, isolates (`runInBackground`
  copies data), JavaScript engines and the OS may keep other copies. Strings
  (passwords) cannot be zeroized at all.
- **Storage.** `FileKeyStorage` is ordinary file storage in an owner-only
  directory (`chmod 700`, files `chmod 600`); it is not hardware-backed. Implement `KeyStorage` over a platform keystore
  for stronger protection.
- **Revocation.** Removing a recipient (rewrap) or revoking a key does not
  revoke access to data or keys an attacker already copied.
- **Endpoints.** Post-quantum algorithms do not protect against compromised
  endpoints, stolen keys, malicious applications or implementation bugs.
- **Web performance.** Argon2id is slow on dart2js (about 2.6 s for
  19 MiB / t=2 in node); prefer dart2wasm or a native backend in browsers.

## Reporting vulnerabilities

Please report security issues privately through GitHub security advisories
on <https://github.com/Colossus-Services/post_quantum_crypto/security>.
