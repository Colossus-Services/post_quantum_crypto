# quantum_crypto wire formats (version 1)

All objects are **binary**; that is the canonical representation. Hex and
Base64URL (`TextEncoding`) are lossless wrappers for textual transport.

Conventions:

- Integers are unsigned big-endian: `u8`, `u16`, `u32`, `u64` (u64 values are
  limited to < 2^53 so they behave identically on the VM and JavaScript).
- `bytes8` / `bytes16` / `bytes32` are a u8/u16/u32 length followed by that many
  bytes. Fixed-length fields have no prefix.
- Every length is checked against a limit **and** against the remaining input
  before any slice or allocation (see `ResourceLimits`).
- Parsers are strict: unknown versions, object types, algorithm identifiers,
  flags or trailing bytes are rejected. There are no optional or unknown
  fields; a future change bumps the format version.
- **Canonical map** (authenticated context, signed metadata): `u16 count`, then
  per entry, sorted strictly ascending by UTF-8 key bytes:
  `bytes8 key || bytes32 value` (UTF-8). Keys are non-empty and unique; any
  other ordering is rejected, so each map has exactly one encoding.

## Common header

```text
"QCRY" (51 43 52 59) | u8 version = 0x01 | u8 objectType
```

| Type | Object |
|---|---|
| 0x01 | Encrypted envelope (single and multi-recipient) |
| 0x03 | Encrypted stream |
| 0x04 | Signed artifact |
| 0x05 | Detached signature |
| 0x06 | Signed manifest |
| 0x07 | Key record |
| 0x08 | Password-protected key |
| 0x09 | Password-encrypted data |
| 0x0a | Hybrid key-establishment message |

## Algorithm identifiers

KEM, KDF and AEAD identifiers are the IANA HPKE registry values:

| KEM | id | | KDF | id | | AEAD | id |
|---|---|---|---|---|---|---|---|
| ML-KEM-512 | 0x0040 | | HKDF-SHA-256 | 0x0001 | | AES-256-GCM | 0x0002 |
| ML-KEM-768 | 0x0041 | | HKDF-SHA-384 | 0x0002 | | ChaCha20-Poly1305 | 0x0003 |
| ML-KEM-1024 | 0x0042 | | HKDF-SHA-512 | 0x0003 | | | |
| X-Wing | 0x647a | | | | | | |

Signature identifiers are package-specific: ML-DSA-44/65/87 =
0x0101/0x0102/0x0103; SLH-DSA-SHAKE-128s/128f/192s/192f/256s/256f =
0x0201…0x0206.

## Key identifier

```text
KeyId = SHA-256("quantum_crypto/v1/key-id" || 0x00 || kind || u16 alg || publicKey)
kind = 0x01 encryption, 0x02 signing
```

## Recipient record (envelopes and streams)

```text
u16 kemId | 32 keyId | enc (KEM ciphertext; length implied by kemId) | wrappedDek (32 + 16)
```

`wrappedDek` is the output of **HPKE (RFC 9180) mode_base single-shot Seal**
with suite (kemId, HKDF-SHA-384, aeadId):

```text
(enc, ss) = KEM.Encap(pkR)                       ML-KEM-768 per draft-ietf-hpke-pq
ctx       = KeySchedule(mode_base, ss, info)
info      = "quantum_crypto/v1/<purpose>/wrap" || u16 kemId || keyId
            purpose ∈ {envelope, stream}
wrapped   = ctx.Seal(aad = headerHash, DEK)
```

The HPKE implementation is verified against the draft-ietf-hpke-pq test
vectors (ML-KEM-512/768/1024 and X-Wing).

## Envelope (0x01)

```text
header
u16 kdfId (0x0002)
u16 aeadId
canonical map  context
    headerHash = SHA-384(all bytes so far)
u16 recipientCount (1..maxRecipients), recipient records (unique keyIds)
12  payloadNonce
    payloadAad = SHA-384(all bytes so far)
bytes32 ciphertext || tag          AEAD(DEK, payloadNonce, plaintext, payloadAad)
```

- The DEK is 32 fresh random bytes per envelope; it encrypts exactly one
  payload, so the random 96-bit nonce is used once under that key.
- The payload AAD covers the context and **every recipient entry**: adding,
  removing, substituting or reordering recipients breaks authentication.
- Decryption: parse → policy checks → required-context check → select the
  record whose keyId matches → decapsulate → HPKE Open → payload Open. All
  authentication failures raise the same `DecryptionFailedException`.

## Stream (0x03)

```text
header
u16 kdfId | u16 aeadId
u32 chunkSize                (plaintext bytes per chunk; 256 B – 16 MiB)
32  salt
7   noncePrefix
canonical map  context
    wrapHash   = SHA-384(all bytes so far)        (HPKE aad of each wrap)
u16 recipientCount, recipient records
    headerHash = SHA-384(entire header)
chunk_0 || chunk_1 || … || chunk_n               no framing
```

```text
streamKey = HKDF-Expand(HKDF-Extract(salt, DEK),
                        "quantum_crypto/v1/stream/key" || headerHash, Nk)
nonce_i   = noncePrefix || u32 i || u8 final      (final = 1 only for chunk_n)
chunk_i   = AEAD(streamKey, nonce_i, plaintext_i, aad = headerHash)
```

Every chunk except the last carries exactly `chunkSize` plaintext bytes; the
last carries 0..chunkSize (an empty stream has one empty final chunk). The
counter detects reordering, duplication and removal; the final flag detects
truncation and appended data. A stream holds at most 2^32 chunks; every
stream has a fresh DEK and therefore a fresh key.

## Detached signature (0x05)

```text
header
u16 sigAlg | 32 signerKeyId | bytes8 context (≤ 255)
canonical map  metadata
u8 digestAlg (0x02 = SHA-384) | 48 digest | u64 contentLength
    signedBytes = "quantum_crypto/v1/detached-signature\0" || all bytes so far
bytes32 signature            = ML-DSA/SLH-DSA.Sign(sk, signedBytes, ctx = context)
```

## Signed artifact (0x04)

```text
header | bytes32 detachedSignature | u64 contentLength | content
```

## Signed manifest (0x06)

```text
header
u16 sigAlg | 32 signerKeyId | bytes8 context | canonical map metadata
u8 digestAlg (0x02) | u32 entryCount
entries, strictly ascending by UTF-8 path: bytes16 path | u64 size | 48 sha384
    signedBytes = "quantum_crypto/v1/manifest\0" || all bytes so far
bytes32 signature
```

Paths are relative and `/`-separated; absolute paths, drive letters, `..`,
`.`, empty segments, backslashes and NUL are rejected.

## Key record (0x07)

```text
header
u8 kind (1 enc-public, 2 enc-private, 3 sig-public, 4 sig-private)
u16 algorithmId
bytes32 publicKey
[private only] u8 form (1 seed, 2 expanded) | bytes32 privateMaterial
metadata
```

Metadata: `u8 flags` (bit0 createdAt, bit1 expiresAt, bit2 revoked,
bit3 replaces), then the present fields: `u64 createdMs`, `u64 expiresMs`,
`u64 revokedMs || bytes16 reason`, then `u8 usageMask` (encrypt 1, decrypt 2,
sign 4, verify 8; 0 = unrestricted), `bytes16 label`, `[32 replacesKeyId]`.

On import, a private key is re-derived from its material and must reproduce
the stored public key.

Seed forms: ML-KEM `d || z` (64 bytes), X-Wing 32 bytes, ML-DSA `ξ`
(32 bytes); SLH-DSA has no separate seed and stores its full secret key.

## Password-protected key (0x08) and password-encrypted data (0x09)

```text
header
u8 kdf = 0x01 (Argon2id v0x13)
u32 memoryKiB | u32 iterations | u8 parallelism
16 salt
u16 aeadId
canonical map  context
12 nonce
    aad = all bytes so far
bytes32 ciphertext || tag     AEAD(Argon2id(password, salt, m, t, p, Nk), nonce, payload, aad)
```

For 0x08 the payload is a key record. Argon2id parameters are checked against
`PasswordPolicy` before any memory is allocated.

## Hybrid key-establishment message (0x0a)

```text
header | u16 kemId (must be hybrid: 0x647a) | 32 responderKeyId | enc
key = HKDF-SHA-384(salt = "", ikm = ss,
        info = "quantum_crypto/v1/hybrid-key" || u16 kemId || responderKeyId ||
               SHA-384(enc) || SHA-384(transcript), L)
transcript = bytes16 protocol || bytes16 initiatorId || bytes16 responderId ||
             canonical map extra
```

## Standardized key encodings

| Algorithm | Public | Private (PKCS#8 `privateKey` OCTET STRING contents) |
|---|---|---|
| ML-KEM-512/768/1024 | SPKI, OID 2.16.840.1.101.3.4.4.1/2/3 | `[0] seed` (64) / `OCTET STRING expandedKey` / `SEQUENCE {seed, expandedKey}` |
| ML-DSA-44/65/87 | SPKI, OID 2.16.840.1.101.3.4.3.17/18/19 (RFC 9881) | same CHOICE with a 32-byte seed |
| SLH-DSA-SHAKE-* | SPKI, OID 2.16.840.1.101.3.4.3.26–31 (RFC 9909) | raw secret key |
| X-Wing | package key record only | package key record only |

Interoperability with OpenSSL 3.5+ for all three standardized families is
covered by `test/interop/openssl_test.dart`.

## Published test vectors

[`test/vectors/quantum_crypto_v1.json`](../test/vectors/quantum_crypto_v1.json)
contains, for the formats above, deterministic example objects together with
the key seeds needed to open them: an envelope with ML-KEM-768 and X-Wing
recipients, a ChaCha20-Poly1305 envelope, a stream with 256-byte chunks, raw
and detached ML-DSA-65 signatures, a signed manifest, a hybrid message with
its session key, a key record and a password-protected key. An independent
implementation of this specification should decrypt and verify all of them.
`format_vectors_test.dart` checks that this package still reproduces them
byte for byte; any difference is a format change.
