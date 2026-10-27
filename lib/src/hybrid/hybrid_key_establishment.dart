/// Hybrid key establishment with X-Wing (ML-KEM-768 + X25519).
///
/// The initiator encapsulates to the responder's X-Wing public key and both
/// sides derive a session key:
///
/// ```text
/// ss  = X-Wing.Encaps / Decaps   (SHA3-256 combiner of both shared secrets)
/// key = HKDF-SHA-384(salt = "", ikm = ss,
///         info = "post_quantum_crypto/v1/hybrid-key" || u16 kemId ||
///                responderKeyId || SHA-384(enc) || SHA-384(transcript), L)
/// ```
///
/// The session key is secret as long as **either** ML-KEM-768 or X25519
/// holds (X-Wing's combiner). It is bound to the protocol label, both peer
/// identities and any extra transcript data, so the two sides only agree if
/// they agree on all of them.
///
/// This is an **unauthenticated** KEM-based key establishment. It is not TLS,
/// not an authenticated key exchange, and does not authenticate either peer:
/// the initiator must obtain the responder's public key through a trusted
/// channel (or a signature), and the responder learns nothing about who the
/// initiator is.
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

/// Data both sides must agree on for the derived keys to match.
final class HybridTranscript {
  /// Application protocol label, e.g. `"myapp/sync/v2"`.
  final String protocol;

  /// Identity of the initiator, as the application names it.
  final String initiatorId;

  /// Identity of the responder.
  final String responderId;

  /// Additional data to bind (session ids, negotiated parameters, ...).
  final Map<String, String> extra;

  const HybridTranscript({
    required this.protocol,
    required this.initiatorId,
    required this.responderId,
    this.extra = const {},
  });

  @internal
  Uint8List encode(CryptoContext ctx) {
    if (protocol.isEmpty) {
      throw const InvalidInputException('Transcript protocol is required');
    }
    final w = ByteWriter()
      ..bytes16(utf8Bytes(protocol))
      ..bytes16(utf8Bytes(initiatorId))
      ..bytes16(utf8Bytes(responderId));
    CanonicalMap.write(w, extra, ctx.mapLimits);
    return w.toBytes();
  }
}

/// The initiator's output: the message to send and the derived key.
final class HybridKeyEstablishment {
  /// Serialized message (object type 0x0a) for the responder.
  final Bytes message;

  /// The derived session key. Treat as secret.
  final Bytes sessionKey;

  HybridKeyEstablishment._(this.message, this.sessionKey);
}

@internal
final class HybridKeyService {
  final CryptoContext _ctx;

  HybridKeyService(this._ctx);

  static final Uint8List _label = utf8Bytes(
    'post_quantum_crypto/v1/hybrid-key',
  );

  void _checkHybrid(KemAlgorithm kem) {
    // Downgrade protection: this API only ever runs a hybrid KEM.
    if (!kem.isHybrid) {
      throw const PolicyViolationException(
        'Hybrid key establishment requires a hybrid KEM',
      );
    }
    _ctx.policy.checkKem(kem);
  }

  static void _checkLength(int length) {
    if (length < 16 || length > 255 * 48) {
      throw const InvalidInputException('Session key length out of range');
    }
  }

  Uint8List _derive(
    KemAlgorithm kem,
    KeyId responder,
    Uint8List enc,
    Uint8List ss,
    HybridTranscript transcript,
    int length,
  ) {
    final kdf = _ctx.hkdfSha384;
    final prk = kdf.extract(null, ss);
    final info =
        (ByteWriter()
              ..raw(_label)
              ..u16(kem.id)
              ..raw(responder.bytes)
              ..raw(_ctx.sha384(enc))
              ..raw(_ctx.sha384(transcript.encode(_ctx))))
            .toBytes();
    try {
      return kdf.expand(prk, info, length);
    } finally {
      zeroize(prk);
    }
  }

  HybridKeyEstablishment initiate(
    EncryptionPublicKey responder,
    HybridTranscript transcript,
    int length,
  ) {
    _checkHybrid(responder.algorithm);
    _checkLength(length);
    _ctx.policy.checkKeyMetadata(responder.metadata, KeyUsage.encrypt);
    final kem = responder.algorithm;
    final rnd = _ctx.randomBytes(kem.encapsulationRandomLength);
    final encap = _ctx.kem(kem).encapsulate(responder.bytes, rnd);
    zeroize(rnd);
    try {
      final key = _derive(
        kem,
        responder.keyId,
        encap.ciphertext,
        encap.sharedSecret,
        transcript,
        length,
      );
      final w = ByteWriter();
      writeHeader(w, ObjectType.hybridKeyMessage);
      w
        ..u16(kem.id)
        ..raw(responder.keyId.bytes)
        ..raw(encap.ciphertext);
      return HybridKeyEstablishment._(w.toBytes(), key);
    } finally {
      zeroize(encap.sharedSecret);
    }
  }

  Uint8List accept(
    Uint8List message,
    EncryptionPrivateKey responder,
    HybridTranscript transcript,
    int length,
  ) {
    _checkLength(length);
    final (kem, keyId, enc) = parseStrict(() {
      final r = ByteReader(message);
      readHeader(r, ObjectType.hybridKeyMessage);
      final kem = KemAlgorithm.fromId(r.u16());
      _checkHybrid(kem);
      final keyId = KeyId(r.fixed(KeyId.length));
      final enc = r.fixed(kem.ciphertextLength);
      r.expectEnd();
      return (kem, keyId, enc);
    });
    if (kem != responder.algorithm || keyId != responder.keyId) {
      throw const KeyNotFoundException('Message is not for this key');
    }
    _ctx.policy.checkKeyMetadata(responder.metadata, KeyUsage.decrypt);
    final ss = _ctx.kem(kem).decapsulate(responder.secret, enc);
    try {
      return _derive(kem, keyId, enc, ss, transcript, length);
    } finally {
      zeroize(ss);
    }
  }
}
