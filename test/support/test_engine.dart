import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';

/// A deterministic, seeded byte source **for tests only**.
///
/// Lives under `test/` so production code cannot import it; it is plugged in
/// through the `@visibleForTesting` engine constructor.
final class DeterministicRandom implements SecureRandomSource {
  final Uint8List _seed;
  int _counter = 0;

  DeterministicRandom(int seed)
    : _seed = Uint8List.fromList([
        seed & 0xff,
        (seed >> 8) & 0xff,
        (seed >> 16) & 0xff,
        (seed >> 24) & 0xff,
      ]);

  @override
  Uint8List nextBytes(int length) {
    final out = Uint8List(length);
    var offset = 0;
    while (offset < length) {
      final block = standardCryptoBackend.keccak.shake256([
        ..._seed,
        (_counter >> 24) & 0xff,
        (_counter >> 16) & 0xff,
        (_counter >> 8) & 0xff,
        _counter & 0xff,
      ], 64);
      _counter++;
      final n = (length - offset) < 64 ? length - offset : 64;
      out.setRange(offset, offset + n, block);
      offset += n;
    }
    return out;
  }
}

/// A production engine (system CSPRNG).
final PostQuantumCryptoEngine engine = PostQuantumCryptoEngine();

/// A deterministic engine for reproducible tests.
PostQuantumCryptoEngine deterministicEngine([
  int seed = 1,
  SecurityPolicy policy = SecurityPolicy.standard,
]) => PostQuantumCryptoEngine.withRandomSourceForTesting(
  DeterministicRandom(seed),
  policy: policy,
);

Uint8List bytesOf(String s) => Uint8List.fromList(s.codeUnits);

/// Returns a copy of [data] with bit [bit] of byte [index] flipped.
Uint8List flip(Uint8List data, int index, [int bit = 0]) =>
    Uint8List.fromList(data)..[index] ^= 1 << bit;
