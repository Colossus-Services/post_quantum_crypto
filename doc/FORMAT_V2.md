# Wire format 2: key commitment (plan for 2.0.0)

Status: **accepted plan**, implemented on the `format-v2` branch.

## Problem

In format 1, each recipient unwraps the data key (DEK) independently, and
AES-GCM and ChaCha20-Poly1305 do not commit to their key. A malicious
**sender** can wrap DEK₁ for Alice and DEK₂ for Bob and craft one
ciphertext and tag that authenticates under both keys ("invisible
salamanders"): Alice decrypts M₁, Bob decrypts M₂, and neither sees an
error. Signing the envelope does not help, because the signature covers the
ambiguous bytes.

Password objects have the related partitioning-oracle weakness: a
ciphertext valid under many keys lets one decryption attempt test many
password guesses.

| Object | Affected |
|---|---|
| Envelope (0x01), stream (0x03) | yes: multi-recipient ambiguity |
| Password-protected key (0x08), password-encrypted data (0x09) | yes: partitioning oracles |
| Signatures, signed artifact, manifest, key record, hybrid message | no (no AEAD payload) |

## Design

### Committing key derivation

```text
H0         = SHA-384(all object bytes before the commitment field)
PRK        = HKDF-Extract(salt = "post_quantum_crypto/v2/<purpose>", ikm = DEK)
payloadKey = HKDF-Expand(PRK, "payload-key" || H0, Nk)
commitment = HKDF-Expand(PRK, "commitment"  || H0, 32)
```

HKDF is HKDF-SHA-384 and `<purpose>` is `envelope`, `stream` or
`password`. The 32-byte `commitment` is stored in the object and covered by
all authenticated data after it. Decryption unwraps the DEK, recomputes the
commitment, compares it in constant time and only then opens the AEAD.
Every failure still raises the single `DecryptionFailedException`.

**Guarantee.** Two recipients seeing different plaintexts requires
DEK₁ ≠ DEK₂ with equal 256-bit HKDF outputs (≈2¹²⁸ work). Because `H0`
covers context, recipients and parameters, the commitment binds the key
*and* the header. With a unique payload key, AEAD decryption is
deterministic, so the plaintext is unique.

**Why this construction.** CTX or a committing AEAD would require
recomputing GCM/Poly1305 tags or a new primitive, which the swappable
`AeadCipher` provider interface cannot offer. The HKDF construction works
with any AEAD and uses primitives the package already has (as in AWS
Encryption SDK v2 and Bellare–Hoang's committing transforms). Cost: 32
bytes and one HKDF-Expand per object; no per-chunk cost.

### Layouts

**Envelope v2**

```text
header (version 2) | u16 kdfId | u16 aeadId | canonical map context
    headerHash = SHA-384(so far)            (HPKE aad of each wrap; unchanged)
u16 recipientCount, recipient records
    H0 = SHA-384(so far)
32  commitment                              new
12  payloadNonce
    payloadAad = SHA-384(so far)
bytes32 ciphertext || tag                   AEAD(payloadKey, payloadNonce, plaintext, payloadAad)
```

**Stream v2**: as format 1, plus `32 commitment` after the recipient
records. `streamKey = HKDF-Expand(PRK, "stream-key" || salt || H0, Nk)`;
chunk AAD is `headerHash` over the full header, commitment included. Nonce
prefix, counter and final flag are unchanged.

**Password objects v2**: PRK is the Argon2id output; `32 commitment`
precedes the nonce; the payload key is derived as above.

**Unchanged**: HPKE wrapping (labels move to `/v2/`), key identifiers (no
stored key changes identity), canonical maps, signatures, key encodings.

### Versioning: per object type

Only 0x01, 0x03, 0x08 and 0x09 are written as version 2. Signatures,
manifests, key records and hybrid messages remain version 1, so 1.x
verifiers keep accepting signatures produced by 2.x.

### Legacy objects

- Readers keep the version-1 decryption paths; writers never produce
  version 1.
- `SecurityPolicy.acceptLegacyFormats` defaults to **false**: a version-1
  envelope, stream or password object raises `UnsupportedFormatException`
  unless the policy opts in. `SecurityPolicy.strict` keeps it false.
- Migration uses existing APIs: `rewrapEnvelope`, `changeKeyPassword`, and
  `decryptStream` piped into `encryptStream`, run under a policy with
  `acceptLegacyFormats: true`.
- New read-only `formatVersion` on `EncryptedEnvelope` and `StreamHeader`.

### Also in 2.0

`TrustStore` takes an optional clock, so `evaluate` agrees with a policy
clock without passing `at:` on every call.

## Implementation steps

1. Per-type current versions; `readHeader` returns the version and applies
   the legacy policy.
2. Commitment helper (`lib/src/encryption/commitment.dart`).
3. Envelope v2 writer and reader; v1 reader behind the policy. Rewrap,
   add and remove recipients emit v2.
4. Stream v2 (header size bound grows by 32).
5. Password objects v2.
6. Policy default and `strict`.
7. Vectors: `post_quantum_crypto_v2.json`; keep `v1.json` and test 2.x
   decrypts it under the legacy policy; update the browser subset.
8. Attack regression test: a real two-key AES-GCM collision as a v1
   two-recipient envelope decrypts differently per recipient under the
   legacy path; the v2 equivalent fails.
9. Fuzz the v2 parsers.
10. Docs: FORMATS.md (v2, v1 appendix), SECURITY.md, README migration,
    CHANGELOG.
11. Release 2.0.0.

## Acceptance criteria

- The salamander test is rejected by v2.
- v1 vectors decrypt under the legacy policy; v2 vectors reproduce byte for
  byte.
- Fuzz suite clean; coverage ≥ 97%.
