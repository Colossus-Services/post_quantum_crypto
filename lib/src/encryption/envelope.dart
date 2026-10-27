/// Authenticated, versioned envelope encryption (single and multiple
/// recipients share one format).
///
/// Layout (all integers big-endian; see doc/FORMATS.md):
///
/// ```text
/// "QCRY" u8 version=1 u8 type=0x01
/// u16 kdfId          (0x0002 = HKDF-SHA-384)
/// u16 aeadId         (0x0002 = AES-256-GCM, 0x0003 = ChaCha20-Poly1305)
/// context            canonical map (authenticated, not secret)
///   ── headerHash = SHA-384(all bytes so far)
/// u16 recipientCount, then per recipient:
///   u16 kemId | 32 keyId | enc (KEM ciphertext) | wrappedDek (32 + 16)
/// 12  payloadNonce
///   ── payloadAad = SHA-384(all bytes so far)
/// u32 ciphertextLength | ciphertext || tag
/// ```
///
/// The payload AAD covers the whole header including every recipient entry,
/// so adding, removing, substituting or reordering recipients, or editing the
/// context, makes the payload fail authentication.
library;

import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../algorithms/algorithms.dart';
import '../context.dart';
import '../encoding/bytes.dart';
import '../encoding/canonical.dart';
import '../errors.dart';
import '../keys/key_metadata.dart';
import '../keys/keys.dart';
import 'key_wrapping.dart';

/// Public description of one envelope recipient.
final class EnvelopeRecipient {
  final KemAlgorithm algorithm;
  final KeyId keyId;

  const EnvelopeRecipient(this.algorithm, this.keyId);

  @override
  String toString() =>
      'EnvelopeRecipient(${algorithm.standardName}, ${keyId.fingerprint})';
}

/// A parsed, structurally validated encrypted envelope. Immutable.
///
/// Parsing checks structure only; authenticity is established by decryption.
final class EncryptedEnvelope {
  final Bytes _bytes;

  /// The AEAD protecting the payload and the wrapped keys.
  final AeadAlgorithm aead;

  /// The KDF used for key wrapping (always HKDF-SHA-384 in version 1).
  final KdfAlgorithm kdf;

  /// The authenticated application context. Not secret, and not proof of
  /// who created the envelope.
  final Map<String, String> context;

  @internal
  final List<RecipientRecord> records;

  @internal
  final Bytes nonce;

  @internal
  final Bytes ciphertext;

  @internal
  final Bytes headerHash;

  @internal
  final Bytes payloadAad;

  EncryptedEnvelope._(
    this._bytes,
    this.aead,
    this.kdf,
    this.context,
    this.records,
    this.nonce,
    this.ciphertext,
    this.headerHash,
    this.payloadAad,
  );

  /// The recipients able to decrypt this envelope.
  List<EnvelopeRecipient> get recipients => [
    for (final r in records) EnvelopeRecipient(r.kem, r.keyId),
  ];

  /// Plaintext length in bytes.
  int get payloadLength => ciphertext.length - aead.tagLength;

  /// The canonical binary serialization (a copy).
  Bytes toBytes() => Uint8List.fromList(_bytes);

  /// Parses [bytes]. Throws [MalformedDataException],
  /// [UnsupportedFormatException], [UnsupportedAlgorithmException] or
  /// [ResourceLimitExceededException]; never allocates more than
  /// [CryptoContext]'s limits allow.
  @internal
  static EncryptedEnvelope parse(CryptoContext ctx, Uint8List bytes) =>
      parseStrict(() {
        final data = Uint8List.fromList(bytes);
        final r = ByteReader(data);
        readHeader(r, ObjectType.envelope);
        final kdf = KdfAlgorithm.fromId(r.u16());
        if (kdf != KdfAlgorithm.hkdfSha384) {
          throw const UnsupportedAlgorithmException('Unsupported KDF');
        }
        final aead = AeadAlgorithm.fromId(r.u16());
        final context = CanonicalMap.read(r, ctx.mapLimits);
        final headerHash = ctx.sha384(Uint8List.sublistView(data, 0, r.offset));
        final records = readRecipients(
          r,
          aead,
          ctx.policy.limits.maxRecipients,
        );
        final nonce = r.fixed(aead.nonceLength);
        final payloadAad = ctx.sha384(Uint8List.sublistView(data, 0, r.offset));
        final ct = r.bytes32(
          max: ctx.policy.limits.maxEnvelopePayloadBytes + aead.tagLength,
        );
        if (ct.length < aead.tagLength) {
          throw const MalformedDataException('Ciphertext shorter than tag');
        }
        r.expectEnd();
        return EncryptedEnvelope._(
          data,
          aead,
          kdf,
          context,
          records,
          nonce,
          ct,
          headerHash,
          payloadAad,
        );
      });
}

/// Encrypt/decrypt/rewrap for envelopes. Internal; reached through the
/// engine.
@internal
final class EnvelopeService {
  final CryptoContext _ctx;
  final KeyWrapper _wrapper;

  EnvelopeService(this._ctx) : _wrapper = KeyWrapper(_ctx, 'envelope');

  EncryptedEnvelope encrypt(
    Uint8List plaintext,
    List<EncryptionPublicKey> recipients,
    Map<String, String> context,
    AeadAlgorithm aeadAlg,
  ) {
    _ctx.policy.checkAead(aeadAlg);
    checkRecipientsForEncryption(_ctx, recipients);
    if (plaintext.length > _ctx.policy.limits.maxEnvelopePayloadBytes) {
      throw const ResourceLimitExceededException(
        'Plaintext exceeds the envelope size limit; use streaming',
      );
    }

    final w = ByteWriter();
    writeHeader(w, ObjectType.envelope);
    w
      ..u16(KdfAlgorithm.hkdfSha384.id)
      ..u16(aeadAlg.id);
    CanonicalMap.write(w, context, _ctx.mapLimits);
    final headerHash = _ctx.sha384(w.toBytes());

    final dek = _ctx.randomBytes(dekLength);
    try {
      final records = [
        for (final r in recipients) _wrapper.wrap(r, dek, headerHash, aeadAlg),
      ];
      writeRecipients(w, records);
      final nonce = _ctx.randomBytes(aeadAlg.nonceLength);
      w.raw(nonce);
      final payloadAad = _ctx.sha384(w.toBytes());
      final ct = _ctx.aead(aeadAlg).seal(dek, nonce, plaintext, payloadAad);
      w.bytes32(ct);
    } finally {
      zeroize(dek);
    }
    // Validate what we produced before handing it out.
    return EncryptedEnvelope.parse(_ctx, w.toBytes());
  }

  Uint8List decrypt(
    EncryptedEnvelope envelope,
    EncryptionPrivateKey key,
    Map<String, String>? requiredContext,
  ) {
    _ctx.policy.checkAead(envelope.aead);
    checkRequiredContext(envelope.context, requiredContext);
    final record = _findRecord(envelope.records, key);
    _ctx.policy.checkKem(record.kem);
    _ctx.policy.checkKeyMetadata(key.metadata, KeyUsage.decrypt);

    final dek = _wrapper.unwrap(
      record,
      key,
      envelope.headerHash,
      envelope.aead,
    );
    if (dek == null) throw const DecryptionFailedException();
    try {
      final pt = _ctx
          .aead(envelope.aead)
          .open(dek, envelope.nonce, envelope.ciphertext, envelope.payloadAad);
      if (pt == null) throw const DecryptionFailedException();
      return pt;
    } finally {
      zeroize(dek);
    }
  }

  /// Decrypts with [key] and re-encrypts the plaintext to [recipients] under
  /// a fresh DEK, fresh nonces and fresh encapsulations. The context and AEAD
  /// are preserved unless overridden.
  EncryptedEnvelope rewrap(
    EncryptedEnvelope envelope,
    EncryptionPrivateKey key,
    List<EncryptionPublicKey> recipients, {
    Map<String, String>? requiredContext,
  }) {
    final pt = decrypt(envelope, key, requiredContext);
    try {
      return encrypt(pt, recipients, envelope.context, envelope.aead);
    } finally {
      zeroize(pt);
    }
  }

  static RecipientRecord _findRecord(
    List<RecipientRecord> records,
    EncryptionPrivateKey key,
  ) {
    for (final r in records) {
      if (r.keyId == key.keyId) {
        if (r.kem != key.algorithm) throw const DecryptionFailedException();
        return r;
      }
    }
    throw const KeyNotFoundException('No recipient entry for this key');
  }
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
