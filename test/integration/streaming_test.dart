import 'dart:async';
import 'dart:typed_data';

import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

const _chunk = 1024;

Uint8List _data(int n) =>
    Uint8List.fromList(List.generate(n, (i) => (i * 31 + 7) & 0xff));

Future<Uint8List> _collect(Stream<List<int>> s) async {
  final b = BytesBuilder();
  await s.forEach(b.add);
  return b.toBytes();
}

/// Feeds [bytes] as a stream of irregular slices.
Stream<List<int>> _slices(Uint8List bytes, [int step = 777]) async* {
  for (var i = 0; i < bytes.length; i += step) {
    yield bytes.sublist(i, i + step > bytes.length ? bytes.length : i + step);
  }
}

void main() {
  late EncryptionKeyPair alice;
  late EncryptionKeyPair bob;

  setUpAll(() {
    alice = engine.generateEncryptionKeyPair();
    bob = engine.generateEncryptionKeyPair(algorithm: KemAlgorithm.xWing);
  });

  Future<List<Uint8List>> encryptParts(
    Uint8List pt, {
    Map<String, String> context = const {},
  }) => engine
      .encryptStream(
        _slices(pt),
        recipients: [alice.publicKey, bob.publicKey],
        chunkSize: _chunk,
        context: context,
      )
      .toList();

  Future<Uint8List> decrypt(List<int> ct, [EncryptionKeyPair? kp]) => _collect(
    engine.decryptStream(
      _slices(Uint8List.fromList(ct), 1000),
      privateKey: (kp ?? alice).privateKey,
    ),
  );

  Uint8List join(List<Uint8List> parts) =>
      Uint8List.fromList(parts.expand((p) => p).toList());

  group('round trip', () {
    for (final n in [
      0,
      1,
      _chunk - 1,
      _chunk,
      _chunk + 1,
      3 * _chunk,
      10 * _chunk + 5,
    ]) {
      test('$n bytes', () async {
        final pt = _data(n);
        final parts = await encryptParts(pt);
        // header + ceil(n / chunk) chunks; an empty stream still has one
        // (empty) final chunk.
        expect(parts.length, 1 + (n == 0 ? 1 : (n + _chunk - 1) ~/ _chunk));
        final ct = join(parts);
        expect(await decrypt(ct), pt);
        expect(await decrypt(ct, bob), pt);
      });
    }

    test('progress reporting and context', () async {
      final pt = _data(5 * _chunk + 3);
      final progress = <int>[];
      final ct = await _collect(
        engine.encryptStream(
          Stream.value(pt),
          recipients: [alice.publicKey],
          chunkSize: _chunk,
          context: {'file': 'a.bin'},
          onProgress: progress.add,
        ),
      );
      expect(progress.last, pt.length);
      final dprog = <int>[];
      final out = await _collect(
        engine.decryptStream(
          Stream.value(ct),
          privateKey: alice.privateKey,
          requiredContext: {'file': 'a.bin'},
          onProgress: dprog.add,
        ),
      );
      expect(out, pt);
      expect(dprog.last, pt.length);
      await expectLater(
        _collect(
          engine.decryptStream(
            Stream.value(ct),
            privateKey: alice.privateKey,
            requiredContext: {'file': 'b.bin'},
          ),
        ),
        throwsA(isA<ContextMismatchException>()),
      );
    });

    test('cancellation', () async {
      final token = CancellationToken();
      final s = engine.encryptStream(
        _slices(_data(20 * _chunk), _chunk),
        recipients: [alice.publicKey],
        chunkSize: _chunk,
        cancel: token,
        onProgress: (n) {
          if (n >= 3 * _chunk) token.cancel();
        },
      );
      await expectLater(
        _collect(s),
        throwsA(isA<OperationCancelledException>()),
      );
    });
  });

  group('attacks on the chunk sequence', () {
    late List<Uint8List> parts;
    final pt = _data(4 * _chunk + 100);

    setUpAll(() async {
      parts = await encryptParts(pt);
      expect(parts, hasLength(6)); // header + 5 chunks
    });

    Future<void> rejects(List<Uint8List> modified) => expectLater(
      decrypt(join(modified)),
      throwsA(isA<DecryptionFailedException>()),
    );

    test(
      'reordered chunks',
      () => rejects([parts[0], parts[2], parts[1], ...parts.skip(3)]),
    );

    test(
      'duplicated chunk',
      () => rejects([...parts.take(3), parts[2], ...parts.skip(3)]),
    );

    test('removed chunk', () => rejects([...parts.take(2), ...parts.skip(3)]));

    test(
      'truncated at a chunk boundary (missing final chunk)',
      () => rejects(parts.take(5).toList()),
    );

    test('truncated inside a chunk', () async {
      final ct = join(parts);
      await expectLater(
        decrypt(ct.sublist(0, ct.length - 50)),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test(
      'appended data after the final chunk',
      () => rejects([...parts, Uint8List(20)]),
    );

    test(
      'appended full chunk from another position',
      () => rejects([...parts, parts[2]]),
    );

    test('modified chunk byte', () {
      final m = [...parts];
      m[3] = flip(m[3], 5);
      return rejects(m);
    });

    test('chunk from another stream', () async {
      final other = await encryptParts(pt);
      return rejects([parts[0], parts[1], other[2], ...parts.skip(3)]);
    });

    test('header only', () async {
      await expectLater(
        decrypt(parts[0]),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('truncated header', () async {
      await expectLater(
        decrypt(parts[0].sublist(0, 40)),
        throwsA(isA<MalformedDataException>()),
      );
    });

    test('tampered header (chunk size)', () async {
      final h = Uint8List.fromList(parts[0]);
      h[13] ^= 0x01; // low byte of chunkSize
      await expectLater(
        decrypt(join([h, ...parts.skip(1)])),
        throwsA(isA<PostQuantumCryptoException>()),
      );
    });

    test('non-recipient key', () async {
      final eve = engine.generateEncryptionKeyPair();
      await expectLater(
        decrypt(join(parts), eve),
        throwsA(isA<KeyNotFoundException>()),
      );
    });
  });

  group('limits', () {
    test('chunk size bounds', () {
      expect(
        () => engine
            .encryptStream(
              Stream.value(_data(1)),
              recipients: [alice.publicKey],
              chunkSize: 16,
            )
            .toList(),
        throwsA(isA<ResourceLimitExceededException>()),
      );
    });

    test('hostile chunk size in a header is rejected', () async {
      final parts = await encryptParts(_data(10));
      final h = Uint8List.fromList(parts[0])
        ..setRange(10, 14, [0xff, 0xff, 0xff, 0xff]);
      await expectLater(
        decrypt(join([h, ...parts.skip(1)])),
        throwsA(isA<ResourceLimitExceededException>()),
      );
    });
  });
}
