/// HPKE (RFC 9180) key schedule and AEAD context, mode_base.
///
/// The KEM step is performed separately by a [KemScheme]; this file covers
/// what follows it: `KeySchedule`, `Seal`/`Open` with the sequence-number
/// nonce, and `Export`. It is generic over the KDF and AEAD so it can be
/// checked against the published HPKE test vectors.
library;

import 'dart:typed_data';

import '../encoding/bytes.dart';
import '../errors.dart';
import '../providers/primitives.dart';

final Uint8List _hpkeV1 = utf8Bytes('HPKE-v1');
final Uint8List _hpke = utf8Bytes('HPKE');

const int _modeBase = 0x00;

/// An HPKE ciphersuite: KEM, KDF and AEAD identifiers plus implementations.
final class HpkeSuite {
  final int kemId;
  final int kdfId;
  final int aeadId;
  final Kdf kdf;
  final AeadCipher aead;

  HpkeSuite({
    required this.kemId,
    required this.kdfId,
    required this.aeadId,
    required this.kdf,
    required this.aead,
  });

  /// `suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) ||
  /// I2OSP(aead_id, 2)`.
  Uint8List get suiteId => concatBytes([
    _hpke,
    [kemId >> 8, kemId & 0xff],
    [kdfId >> 8, kdfId & 0xff],
    [aeadId >> 8, aeadId & 0xff],
  ]);

  Uint8List labeledExtract(Uint8List? salt, String label, Uint8List ikm) =>
      kdf.extract(salt, concatBytes([_hpkeV1, suiteId, utf8Bytes(label), ikm]));

  Uint8List labeledExpand(
    Uint8List prk,
    String label,
    Uint8List info,
    int length,
  ) => kdf.expand(
    prk,
    concatBytes([
      [length >> 8, length & 0xff],
      _hpkeV1,
      suiteId,
      utf8Bytes(label),
      info,
    ]),
    length,
  );

  /// `KeySchedule(mode_base, shared_secret, info, "", "")`.
  HpkeContext keySchedule(Uint8List sharedSecret, Uint8List info) {
    final empty = Uint8List(0);
    final pskIdHash = labeledExtract(empty, 'psk_id_hash', empty);
    final infoHash = labeledExtract(empty, 'info_hash', info);
    final context = concatBytes([
      [_modeBase],
      pskIdHash,
      infoHash,
    ]);
    final secret = labeledExtract(sharedSecret, 'secret', empty);
    try {
      return HpkeContext._(
        this,
        labeledExpand(secret, 'key', context, aead.keyLength),
        labeledExpand(secret, 'base_nonce', context, aead.nonceLength),
        labeledExpand(secret, 'exp', context, kdf.algorithm.hashLength),
      );
    } finally {
      zeroize(secret);
    }
  }
}

/// An HPKE encryption context (sender or recipient side).
final class HpkeContext {
  final HpkeSuite _suite;
  final Uint8List key;
  final Uint8List baseNonce;
  final Uint8List exporterSecret;
  int _seq = 0;

  HpkeContext._(this._suite, this.key, this.baseNonce, this.exporterSecret);

  /// The next sequence number.
  int get sequence => _seq;

  Uint8List _nonce() {
    final nonce = Uint8List.fromList(baseNonce);
    var s = _seq;
    for (var i = nonce.length - 1; i >= 0 && s > 0; i--) {
      nonce[i] ^= s & 0xff;
      s >>= 8;
    }
    return nonce;
  }

  Uint8List seal(Uint8List aad, Uint8List plaintext) {
    final ct = _suite.aead.seal(key, _nonce(), plaintext, aad);
    _seq++;
    return ct;
  }

  /// Returns `null` when authentication fails.
  Uint8List? open(Uint8List aad, Uint8List ciphertext) {
    final pt = _suite.aead.open(key, _nonce(), ciphertext, aad);
    if (pt != null) _seq++;
    return pt;
  }

  Uint8List export(Uint8List exporterContext, int length) =>
      _suite.labeledExpand(exporterSecret, 'sec', exporterContext, length);

  /// Clears the context keys (best-effort).
  void destroy() {
    zeroize(key);
    zeroize(baseNonce);
    zeroize(exporterSecret);
  }
}

/// Validates an HPKE info/aad length bound before use.
void checkHpkeLength(Uint8List value) {
  if (value.length > 0xffff) {
    throw const ResourceLimitExceededException('HPKE input too long');
  }
}
