/// Validation of ML-DSA expanded private keys (FIPS 204).
///
/// An expanded private key is `rho || K || tr || s1 || s2 || t0`. Its public
/// key `rho || t1` is fully determined by it: `t = NTT⁻¹(Â ∘ NTT(s1)) + s2`
/// and `(t1, t0) = Power2Round(t)`, with `Â = ExpandA(rho)`. Recomputing `t`
/// checks that the key is internally consistent (s1 and s2 in range, `t0`
/// matching, RFC 9881 Appendix C.4) and yields the public key, so an
/// expanded key can be imported on its own. The signing primitive does none
/// of this: skDecode accepts any bytes, and a key with a wrong `t0` still
/// produces signatures that verify.
library;

import 'dart:typed_data';

import 'package:meta/meta.dart';
import 'package:pqcrypto/pqcrypto.dart' show Shake128;

import '../algorithms/algorithms.dart';
import '../errors.dart';

const int _q = 8380417;
const int _n = 256;
const int _d = 13;

/// `256⁻¹ mod q` (FIPS 204 Algorithm 42).
const int _nInverse = 8347681;

/// `zetas[k] = 1753^brv8(k) mod q` (FIPS 204 Appendix B).
final List<int> _zetas = List<int>.generate(_n, (k) {
  var brv = 0;
  for (var i = 0; i < 8; i++) {
    brv |= ((k >> i) & 1) << (7 - i);
  }
  return _powMod(1753, brv);
});

int _powMod(int base, int exponent) {
  var result = 1;
  var b = base % _q;
  var e = exponent;
  while (e > 0) {
    if (e & 1 == 1) result = result * b % _q;
    b = b * b % _q;
    e >>= 1;
  }
  return result;
}

/// Returns the public key `rho || t1` of the ML-DSA expanded private key
/// [sk], after checking that s1 and s2 are in range and that `t0` matches.
/// Throws [InvalidKeyException] otherwise. [sk] has the length of
/// [algorithm]'s secret key (checked by the caller).
@internal
Uint8List mlDsaPublicKeyFromExpanded(
  SignatureAlgorithm algorithm,
  Uint8List sk,
) {
  final (k, l, eta) = switch (algorithm) {
    SignatureAlgorithm.mlDsa44 => (4, 4, 2),
    SignatureAlgorithm.mlDsa65 => (6, 5, 4),
    SignatureAlgorithm.mlDsa87 => (8, 7, 2),
    _ => throw ArgumentError.value(algorithm, 'algorithm', 'not ML-DSA'),
  };
  final etaBits = eta == 2 ? 3 : 4;
  final etaPolyBytes = 32 * etaBits;
  const t0PolyBytes = 32 * _d;

  // skEncode (Algorithm 24): rho(32) || K(32) || tr(64) || s1 || s2 || t0.
  var offset = 128;
  List<int> secretPoly() {
    final packed = _unpack(sk, offset, etaBits);
    offset += etaPolyBytes;
    for (final v in packed) {
      // Packed as eta − c; anything above 2·eta is outside [−eta, eta].
      if (v > 2 * eta) {
        throw const InvalidKeyException(
          'ML-DSA secret key has s1 or s2 out of range',
        );
      }
    }
    return [for (final v in packed) (eta - v) % _q];
  }

  final s1 = [for (var i = 0; i < l; i++) secretPoly()..ntt()];
  final s2 = [for (var i = 0; i < k; i++) secretPoly()];

  final rho = Uint8List.sublistView(sk, 0, 32);
  final pk = BytesBuilder(copy: false)..add(rho);
  var t0Offset = offset;
  for (var r = 0; r < k; r++) {
    // t[r] = NTT⁻¹(Σ_s Â[r][s] ∘ NTT(s1[s])) + s2[r]
    final acc = List<int>.filled(_n, 0);
    for (var s = 0; s < l; s++) {
      final a = _rejNttPoly(rho, s, r);
      final b = s1[s];
      for (var i = 0; i < _n; i++) {
        acc[i] = (acc[i] + a[i] * b[i]) % _q;
      }
    }
    acc.invNtt();
    final t0Packed = _unpack(sk, t0Offset, _d);
    t0Offset += t0PolyBytes;
    final t1 = List<int>.filled(_n, 0);
    for (var i = 0; i < _n; i++) {
      final t = (acc[i] + s2[r][i]) % _q;
      // Power2Round (Algorithm 35): t0 = t mod± 2^d, t1 = (t − t0) / 2^d.
      var t0 = t % (1 << _d);
      if (t0 > 1 << (_d - 1)) t0 -= 1 << _d;
      // t0 is stored packed as 2^(d−1) − t0.
      if ((1 << (_d - 1)) - t0Packed[i] != t0) {
        throw const InvalidKeyException(
          'ML-DSA secret key is inconsistent: t0 does not match s1 and s2',
        );
      }
      t1[i] = (t - t0) >> _d;
    }
    // pkEncode (Algorithm 22): t1 coefficients packed in 10 bits.
    pk.add(_pack(t1, 10));
  }
  return pk.toBytes();
}

/// Â[r][s] = RejNTTPoly(rho || s || r) (Algorithms 30 and 32).
List<int> _rejNttPoly(Uint8List rho, int s, int r) {
  final seed = Uint8List(34)
    ..setAll(0, rho)
    ..[32] = s
    ..[33] = r;
  // SHAKE128 output is prefix-consistent, so a longer squeeze only extends
  // the stream; 5 blocks almost always suffice (rejection rate ≈ 0.1%).
  for (var length = 5 * 168; ; length *= 2) {
    final stream = Shake128.shake(seed, length);
    final out = <int>[];
    for (var i = 0; i + 3 <= stream.length && out.length < _n; i += 3) {
      final z =
          stream[i] | (stream[i + 1] << 8) | ((stream[i + 2] & 0x7f) << 16);
      if (z < _q) out.add(z);
    }
    if (out.length == _n) return out;
  }
}

/// The 256 [bits]-bit little-endian coefficients packed at [offset].
List<int> _unpack(Uint8List data, int offset, int bits) {
  final mask = (1 << bits) - 1;
  return List<int>.generate(_n, (i) {
    final bit = i * bits;
    final byte = offset + (bit >> 3);
    var word = data[byte];
    if (byte + 1 < data.length) word |= data[byte + 1] << 8;
    if (byte + 2 < data.length) word |= data[byte + 2] << 16;
    return (word >> (bit & 7)) & mask;
  });
}

/// Packs 256 [bits]-bit coefficients little-endian (SimpleBitPack).
Uint8List _pack(List<int> coefficients, int bits) {
  final out = Uint8List(32 * bits);
  for (var i = 0; i < _n; i++) {
    final bit = i * bits;
    final value = coefficients[i] << (bit & 7);
    for (var j = 0; j * 8 < bits + (bit & 7); j++) {
      out[(bit >> 3) + j] |= (value >> (8 * j)) & 0xff;
    }
  }
  return out;
}

extension on List<int> {
  /// NTT (FIPS 204 Algorithm 41), in place.
  void ntt() {
    var m = 0;
    for (var len = 128; len >= 1; len >>= 1) {
      for (var start = 0; start < _n; start += 2 * len) {
        final z = _zetas[++m];
        for (var j = start; j < start + len; j++) {
          final t = z * this[j + len] % _q;
          this[j + len] = (this[j] - t) % _q;
          this[j] = (this[j] + t) % _q;
        }
      }
    }
  }

  /// Inverse NTT (FIPS 204 Algorithm 42), in place.
  void invNtt() {
    var m = _n;
    for (var len = 1; len < _n; len <<= 1) {
      for (var start = 0; start < _n; start += 2 * len) {
        final z = _q - _zetas[--m];
        for (var j = start; j < start + len; j++) {
          final t = this[j];
          this[j] = (t + this[j + len]) % _q;
          this[j + len] = z * ((t - this[j + len]) % _q) % _q;
        }
      }
    }
    for (var j = 0; j < _n; j++) {
      this[j] = _nInverse * this[j] % _q;
    }
  }
}
