# Wire format 2: key commitment (2.0.0)

Status: **released in 2.0.0**. The normative specification is
[FORMATS.md](FORMATS.md); this page records why format 2 exists and the
decisions behind it.

## Problem

In format 1, each recipient unwraps the data key (DEK) independently, and
AES-GCM and ChaCha20-Poly1305 do not commit to their key. A malicious
**sender** can wrap DEK₁ for Alice and DEK₂ for Bob and craft one
ciphertext and tag that authenticates under both ("invisible salamanders"):
Alice decrypts M₁, Bob decrypts M₂, and neither sees an error. Signing the
envelope does not help, because the signature covers the ambiguous bytes.

Password objects had the related partitioning-oracle weakness: a ciphertext
valid under many keys lets one decryption attempt test many password
guesses.

| Object | Affected in format 1 |
|---|---|
| Envelope (0x01), stream (0x03) | yes: multi-recipient ambiguity |
| Password-protected key (0x08), password-encrypted data (0x09) | yes: partitioning oracles |
| Signatures, signed artifact, manifest, key record, hybrid message | no (no AEAD payload) |

## Design

### Committing key derivation

```text
h0         = SHA-384(all object bytes before the commitment field)
PRK        = HKDF-Extract(salt = "post_quantum_crypto/v2/<purpose>", ikm = secret)
payloadKey = HKDF-Expand(PRK, "payload-key" || h0, Nk)
commitment = HKDF-Expand(PRK, "commitment"  || h0, 32)
```

`secret` is the DEK (envelopes, streams) or a 32-byte Argon2id output
(password objects). The commitment is stored in the object and covered by
all authenticated data after it; decryption checks it in constant time
before opening the AEAD, and every failure is the single
`DecryptionFailedException`.

**Guarantee.** Two recipients seeing different plaintexts requires
DEK₁ ≠ DEK₂ with equal 256-bit HKDF outputs (≈2¹²⁸ work). Because `h0`
covers context, recipients and parameters, the commitment binds the key and
the header. With a unique payload key, AEAD decryption is deterministic, so
the plaintext is unique. `test/unit/key_commitment_test.dart` builds a real
two-key AES-GCM collision and shows the commitment rejecting it.

**Why this construction.** CTX or a committing AEAD would require
recomputing GCM/Poly1305 tags or a new primitive, which the swappable
`AeadCipher` provider interface cannot offer. The HKDF construction works
with any AEAD and uses primitives the package already has (as in AWS
Encryption SDK v2 and Bellare–Hoang's committing transforms). Cost: 32
bytes and one HKDF-Expand per object; no per-chunk cost.

### Layout changes from format 1

- Envelope: `32 commitment` before the payload nonce; the payload is sealed
  with the derived payload key instead of the DEK.
- Stream: `32 commitment` after the recipient records; the stream key is the
  derived payload key. The 32-byte `salt` field is gone: it only fed the
  format 1 stream-key derivation, and the DEK is fresh per stream anyway.
- Password objects: `32 commitment` before the nonce; Argon2id outputs 32
  bytes that feed the derivation.
- Every object type carries version 2 in the common header, including types
  whose layout did not change.
- Unchanged: HPKE wrapping, key identifiers, canonical maps, signature and
  key encodings.

## Decisions

- **No legacy reading.** The package is new; format 1 objects are rejected
  with `UnsupportedFormatException` and there is no migration path.
- **One version for all object types**, so every object of a release has
  the same version and the rules stay simple.
- **Prepared for future versions**: `readHeader` returns the version, a
  `legacyFormatVersions` set (empty) and `SecurityPolicy.acceptLegacyFormats`
  let a later release read version 2 behind an opt-in, and parsed objects
  expose `formatVersion`. See "Format evolution" in FORMATS.md.
- **Strict UTF-8 everywhere**: strings with unpaired surrogates are rejected,
  passwords included.
- **`TrustStore` clock**: `TrustStore.withClock` and
  `PostQuantumCryptoEngine.createTrustStore` make `evaluate` agree with a
  policy clock.
