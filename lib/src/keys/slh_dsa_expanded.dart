/// Validation of SLH-DSA private keys (FIPS 205).
///
/// An SLH-DSA secret key is `SK.seed || SK.prf || PK.seed || PK.root` (n
/// bytes each) and its public key is `PK.seed || PK.root`. `PK.root`, the
/// root of the top XMSS tree, is fully determined by `SK.seed` and
/// `PK.seed`. Recomputing it with FIPS 205 Algorithm 18
/// (`slh_keygen_internal`) and comparing detects a corrupted or
/// inconsistent key, which the signing primitive would otherwise accept
/// and use to produce only signatures that fail verification.
///
/// Algorithm 18 is implemented in pqcrypto but, in pqcrypto 0.4.3, only as
/// the non-exported `SlhDsaInternal`. Until it is public
/// (https://github.com/turkananation/pqcrypto/pull/69) it is imported from
/// pqcrypto's `src/`, which is why pubspec.yaml pins pqcrypto to 0.4.3.x.
library;

import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:pqcrypto/pqcrypto.dart' show SlhDsaParams;
// pqcrypto 0.4.3 does not export Algorithm 18; see the library comment.
// ignore: implementation_imports
import 'package:pqcrypto/src/algos/slhdsa/slhdsa.dart' show SlhDsaInternal;

import '../algorithms/algorithms.dart';
import '../encoding/bytes.dart';
import '../errors.dart';

/// Returns the public key `PK.seed || PK.root` of the SLH-DSA secret key
/// [sk] after checking that its `PK.root` matches `SK.seed` and `PK.seed`.
/// Throws [InvalidKeyException] otherwise. [sk] has the length of
/// [algorithm]'s secret key (checked by the caller).
@internal
Uint8List slhDsaPublicKeyFromSecretKey(
  SignatureAlgorithm algorithm,
  Uint8List sk,
) {
  final params = switch (algorithm) {
    SignatureAlgorithm.slhDsaShake128s => SlhDsaParams.shake128s,
    SignatureAlgorithm.slhDsaShake128f => SlhDsaParams.shake128f,
    SignatureAlgorithm.slhDsaShake192s => SlhDsaParams.shake192s,
    SignatureAlgorithm.slhDsaShake192f => SlhDsaParams.shake192f,
    SignatureAlgorithm.slhDsaShake256s => SlhDsaParams.shake256s,
    SignatureAlgorithm.slhDsaShake256f => SlhDsaParams.shake256f,
    _ => throw ArgumentError.value(algorithm, 'algorithm', 'not SLH-DSA'),
  };
  final n = params.n;
  final (publicKey, recomputed) = SlhDsaInternal.generateKeyPairSeeded(
    params,
    Uint8List.sublistView(sk, 0, n),
    Uint8List.sublistView(sk, n, 2 * n),
    Uint8List.sublistView(sk, 2 * n, 3 * n),
  );
  try {
    if (!constantTimeEquals(
      Uint8List.sublistView(recomputed, 3 * n),
      Uint8List.sublistView(sk, 3 * n),
    )) {
      throw const InvalidKeyException(
        'SLH-DSA secret key is inconsistent: PK.root does not match '
        'SK.seed and PK.seed',
      );
    }
    return publicKey;
  } finally {
    zeroize(recomputed);
  }
}
