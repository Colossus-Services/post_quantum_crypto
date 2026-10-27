/// Per-recipient wrapping of a data-encryption key with HPKE (RFC 9180,
/// mode_base, single-shot).
///
/// For each recipient: `(enc, ss) = KEM.Encap(pkR)`, then an HPKE context is
/// derived with HKDF-SHA-384 from `ss` and
/// `info = "post_quantum_crypto/v<version>/<purpose>/wrap" || u16 kemId || keyId`
/// (`<version>` is the object's format version), and the
/// DEK is sealed with `aad = headerHash`. The KEM shared secret is therefore
/// never used directly as an AEAD key, the wrapping key is unique per
/// encapsulation (so its single nonce is never reused), and the wrap is bound
/// to the recipient, the algorithm suite and the authenticated header.
library;

import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../algorithms/algorithms.dart';
import '../context.dart';
import '../encoding/bytes.dart';
import '../encoding/canonical.dart';
import '../errors.dart';
import '../hpke/hpke.dart';
import '../keys/key_metadata.dart';
import '../keys/keys.dart';

/// Length of a data-encryption key.
const int dekLength = 32;

/// A recipient entry: who it is for and the wrapped DEK.
@internal
final class RecipientRecord {
  final KemAlgorithm kem;
  final KeyId keyId;
  final Bytes enc;
  final Bytes wrappedKey;

  RecipientRecord(this.kem, this.keyId, this.enc, this.wrappedKey);

  static int wrappedLength(AeadAlgorithm aead) => dekLength + aead.tagLength;

  void write(ByteWriter w) {
    w
      ..u16(kem.id)
      ..fixed(keyId.bytes, KeyId.length)
      ..fixed(enc, kem.ciphertextLength)
      ..raw(wrappedKey);
  }

  /// Reads one record. The encapsulation length is implied by the KEM id,
  /// so there is no attacker-chosen length field here.
  static RecipientRecord read(ByteReader r, AeadAlgorithm aead) {
    final kem = KemAlgorithm.fromId(r.u16());
    final keyId = KeyId(r.fixed(KeyId.length));
    final enc = r.fixed(kem.ciphertextLength);
    final wrapped = r.fixed(wrappedLength(aead));
    return RecipientRecord(kem, keyId, enc, wrapped);
  }
}

/// Writes `u16 count || records`.
@internal
void writeRecipients(ByteWriter w, List<RecipientRecord> records) {
  w.u16(records.length);
  for (final r in records) {
    r.write(w);
  }
}

/// Reads `u16 count || records`, rejecting empty, oversized and duplicate
/// recipient sets.
@internal
List<RecipientRecord> readRecipients(
  ByteReader r,
  AeadAlgorithm aead,
  int maxRecipients,
) {
  final count = r.u16();
  if (count == 0) {
    throw const MalformedDataException('No recipients');
  }
  if (count > maxRecipients) {
    throw const ResourceLimitExceededException('Too many recipients');
  }
  final records = <RecipientRecord>[];
  final seen = <KeyId>{};
  for (var i = 0; i < count; i++) {
    final rec = RecipientRecord.read(r, aead);
    if (!seen.add(rec.keyId)) {
      throw const MalformedDataException('Duplicate recipient key id');
    }
    records.add(rec);
  }
  return List.unmodifiable(records);
}

/// Validates a recipient list for encryption: non-empty, bounded, unique,
/// permitted by policy and usable for encryption.
@internal
void checkRecipientsForEncryption(
  CryptoContext ctx,
  List<EncryptionPublicKey> recipients,
) {
  if (recipients.isEmpty) {
    throw const InvalidInputException('At least one recipient is required');
  }
  if (recipients.length > ctx.policy.limits.maxRecipients) {
    throw const ResourceLimitExceededException('Too many recipients');
  }
  final seen = <KeyId>{};
  for (final r in recipients) {
    if (!seen.add(r.keyId)) {
      throw const InvalidInputException('Duplicate recipient');
    }
    ctx.policy.checkKem(r.algorithm);
    ctx.policy.checkKeyMetadata(r.metadata, KeyUsage.encrypt);
  }
}

/// Selects the record addressed to [key] and applies the decryption-side
/// policy checks. Record key ids are unique (enforced by [readRecipients]).
@internal
RecipientRecord selectRecipient(
  CryptoContext ctx,
  List<RecipientRecord> records,
  EncryptionPrivateKey key,
) {
  for (final r in records) {
    if (r.keyId == key.keyId) {
      if (r.kem != key.algorithm) throw const DecryptionFailedException();
      ctx.policy.checkKem(r.kem);
      ctx.policy.checkKeyMetadata(key.metadata, KeyUsage.decrypt);
      return r;
    }
  }
  throw const KeyNotFoundException('No recipient entry for this key');
}

/// Fails unless every entry of [required] is present in [actual] with the
/// same value. Context is public, so this check reveals nothing secret.
@internal
void checkRequiredContext(
  Map<String, String> actual,
  Map<String, String>? required,
) {
  if (required == null) return;
  for (final e in required.entries) {
    if (actual[e.key] != e.value) {
      throw ContextMismatchException(
        'Authenticated context does not match for "${e.key}"',
      );
    }
  }
}

/// HPKE-based DEK wrapping.
@internal
final class KeyWrapper {
  final CryptoContext _ctx;
  final String _purpose;

  KeyWrapper(this._ctx, this._purpose);

  HpkeSuite _suite(KemAlgorithm kem, AeadAlgorithm aead) => HpkeSuite(
    kemId: kem.id,
    kdfId: KdfAlgorithm.hkdfSha384.id,
    aeadId: aead.id,
    kdf: _ctx.hkdfSha384,
    aead: _ctx.aead(aead),
  );

  /// The HPKE info string; its label carries the object's format [version].
  Uint8List _info(int version, KemAlgorithm kem, KeyId keyId) =>
      (ByteWriter()
            ..raw(utf8Bytes('post_quantum_crypto/v$version/$_purpose/wrap'))
            ..u16(kem.id)
            ..raw(keyId.bytes))
          .toBytes();

  /// Wraps [dek] for [recipient] in an object of the current format version.
  RecipientRecord wrap(
    EncryptionPublicKey recipient,
    Uint8List dek,
    Uint8List headerHash,
    AeadAlgorithm aead,
  ) {
    final kem = recipient.algorithm;
    final rnd = _ctx.randomBytes(kem.encapsulationRandomLength);
    final encap = _ctx.kem(kem).encapsulate(recipient.bytes, rnd);
    zeroize(rnd);
    final hpke = _suite(kem, aead).keySchedule(
      encap.sharedSecret,
      _info(formatVersion2, kem, recipient.keyId),
    );
    zeroize(encap.sharedSecret);
    try {
      return RecipientRecord(
        kem,
        recipient.keyId,
        encap.ciphertext,
        hpke.seal(headerHash, dek),
      );
    } finally {
      hpke.destroy();
    }
  }

  /// Returns the DEK, or `null` when the record does not authenticate.
  /// [version] is the format version of the object holding [record].
  Uint8List? unwrap(
    RecipientRecord record,
    EncryptionPrivateKey key,
    Uint8List headerHash,
    AeadAlgorithm aead,
    int version,
  ) {
    // Outside the try: a destroyed key is a caller error, not a decryption
    // failure.
    final secret = key.secret;
    final Uint8List ss;
    try {
      ss = _ctx.kem(record.kem).decapsulate(secret, record.enc);
    } on PostQuantumCryptoException {
      return null;
    }
    final hpke = _suite(
      record.kem,
      aead,
    ).keySchedule(ss, _info(version, record.kem, record.keyId));
    zeroize(ss);
    try {
      return hpke.open(headerHash, record.wrappedKey);
    } finally {
      hpke.destroy();
    }
  }
}
