/// Committing key derivation for format version 2 (doc/FORMAT_V2.md).
///
/// ```text
/// PRK        = HKDF-Extract(salt = "post_quantum_crypto/v2/<purpose>", ikm = secret)
/// payloadKey = HKDF-Expand(PRK, "payload-key" || h0, Nk)
/// commitment = HKDF-Expand(PRK, "commitment"  || h0, 32)
/// ```
///
/// `h0` is the SHA-384 of every object byte before the commitment field.
/// Storing the commitment and checking it before opening the AEAD makes the
/// object decrypt under at most one key: two different secrets yielding the
/// same commitment is an HKDF-SHA-384 collision.
library;

import 'dart:typed_data';

import 'package:meta/meta.dart';

import '../context.dart';
import '../encoding/bytes.dart';

/// Length of a stored key commitment.
const int commitmentLength = 32;

/// A derived payload key and its commitment.
@internal
final class CommittedKey {
  final Uint8List key;
  final Uint8List commitment;

  CommittedKey._(this.key, this.commitment);

  /// Derives the payload key ([keyLength] bytes) and the commitment for
  /// [secret], bound to [purpose] and the header digest [h0].
  factory CommittedKey.derive(
    CryptoContext ctx,
    String purpose,
    Uint8List secret,
    Uint8List h0,
    int keyLength,
  ) {
    final kdf = ctx.hkdfSha384;
    final prk = kdf.extract(
      utf8Bytes('post_quantum_crypto/v2/$purpose'),
      secret,
    );
    try {
      return CommittedKey._(
        kdf.expand(prk, concatBytes([_keyLabel, h0]), keyLength),
        kdf.expand(prk, concatBytes([_commitmentLabel, h0]), commitmentLength),
      );
    } finally {
      zeroize(prk);
    }
  }

  static final Uint8List _keyLabel = utf8Bytes('payload-key');
  static final Uint8List _commitmentLabel = utf8Bytes('commitment');

  /// Whether [stored] equals this commitment (constant time).
  bool matches(List<int> stored) => constantTimeEquals(commitment, stored);

  void destroy() => zeroize(key);
}
