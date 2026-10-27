/// Key commitment versus a real "invisible salamanders" attack.
///
/// A malicious sender wraps a different data key for each of two recipients
/// and crafts one AES-GCM ciphertext and tag valid under both payload keys
/// (a GHASH linear solve; Dodis et al., CRYPTO 2018; Len et al., USENIX
/// Security 2021). Without a commitment (format 1, package 1.x) both
/// recipients would decrypt the same envelope bytes, without error, to
/// different plaintexts. The stored commitment matches only one data key,
/// so the other recipient's decryption fails, although the AEAD tag is
/// valid for both.
library;

import 'dart:typed_data';

import 'package:pointycastle/api.dart' show KeyParameter;
import 'package:pointycastle/block/aes.dart';
import 'package:post_quantum_crypto/post_quantum_crypto.dart';
import 'package:post_quantum_crypto/src/context.dart';
import 'package:post_quantum_crypto/src/encoding/bytes.dart';
import 'package:post_quantum_crypto/src/encryption/commitment.dart';
import 'package:post_quantum_crypto/src/hpke/hpke.dart';
import 'package:post_quantum_crypto/src/kem/kem_scheme.dart';
import 'package:test/test.dart';

import '../support/test_engine.dart';

// --- GF(2^128) in GCM bit order (NIST SP 800-38D) ---------------------------

final _r = BigInt.from(0xe1) << 120;
final _one = BigInt.one << 127; // x^0 is the most significant bit
final _byte = BigInt.from(0xff);

BigInt _toField(List<int> block) =>
    block.fold(BigInt.zero, (a, b) => (a << 8) | BigInt.from(b));

Uint8List _toBlock(BigInt x) => Uint8List.fromList([
  for (var i = 0; i < 16; i++) ((x >> (8 * (15 - i))) & _byte).toInt(),
]);

BigInt _mul(BigInt x, BigInt y) {
  var z = BigInt.zero;
  var v = y;
  for (var i = 0; i < 128; i++) {
    if ((x >> (127 - i)) & BigInt.one == BigInt.one) z ^= v;
    final carry = v & BigInt.one == BigInt.one;
    v >>= 1;
    if (carry) v ^= _r;
  }
  return z;
}

BigInt _pow(BigInt x, BigInt e) {
  var result = _one;
  var base = x;
  while (e > BigInt.zero) {
    if (e & BigInt.one == BigInt.one) result = _mul(result, base);
    base = _mul(base, base);
    e >>= 1;
  }
  return result;
}

BigInt _inv(BigInt x) => _pow(x, (BigInt.one << 128) - BigInt.two);

Uint8List _aes(Uint8List key, Uint8List block) {
  final out = Uint8List(16);
  (AESEngine()..init(true, KeyParameter(key))).processBlock(block, 0, out, 0);
  return out;
}

/// 16-byte blocks of [data], the last one zero-padded.
List<BigInt> _blocks(Uint8List data) => [
  for (var i = 0; i < data.length; i += 16)
    _toField(
      Uint8List(16)..setAll(
        0,
        data.sublist(i, i + 16 > data.length ? data.length : i + 16),
      ),
    ),
];

/// An AES-256-GCM `ciphertext || tag` that authenticates under both [k1] and
/// [k2] with [nonce] and [aad]. Two ciphertext blocks: the first is solved
/// for, the second is arbitrary.
Uint8List _collidingCiphertext(
  Uint8List k1,
  Uint8List k2,
  Uint8List nonce,
  Uint8List aad,
) {
  final h1 = _toField(_aes(k1, Uint8List(16)));
  final h2 = _toField(_aes(k2, Uint8List(16)));
  final j0 = Uint8List(16)
    ..setAll(0, nonce)
    ..[15] = 1;
  final p1 = _toField(_aes(k1, j0));
  final p2 = _toField(_aes(k2, j0));

  final fixedBlock = _toField(List.filled(16, 0x42));
  const ctLength = 32;
  final length = _toField(
    (ByteWriter()
          ..u64(aad.length * 8)
          ..u64(ctLength * 8))
        .toBytes(),
  );
  // GHASH = Σ X_i · H^(n−i+1) over A blocks, C blocks, length block.
  final xs = [..._blocks(aad), BigInt.zero, fixedBlock, length];
  final freeIndex = _blocks(aad).length;
  final n = xs.length;
  BigInt ghash(BigInt h) {
    var y = BigInt.zero;
    for (final x in xs) {
      y = _mul(y ^ x, h);
    }
    return y;
  }

  final e = BigInt.from(n - freeIndex);
  final coefficient = _pow(h1, e) ^ _pow(h2, e);
  final free = _mul(ghash(h1) ^ ghash(h2) ^ p1 ^ p2, _inv(coefficient));
  xs[freeIndex] = free;
  final tag = ghash(h1) ^ p1;
  expect(tag, ghash(h2) ^ p2, reason: 'tags collide');
  return Uint8List.fromList([
    ..._toBlock(free),
    ..._toBlock(fixedBlock),
    ..._toBlock(tag),
  ]);
}

// --- A malicious sender -------------------------------------------------------

/// An envelope for [alice] and [bob] in which each one's wrapped data key
/// differs and the payload authenticates under both resulting payload keys.
/// The commitment is Alice's.
Uint8List _salamander(EncryptionKeyPair alice, EncryptionKeyPair bob) {
  final backend = standardCryptoBackend;
  final ctx = CryptoContext(
    backend,
    SecurityPolicy.standard,
    DeterministicRandom(7),
  );
  const aead = AeadAlgorithm.aes256Gcm;
  final deks = [ctx.randomBytes(32), ctx.randomBytes(32)];

  final w = ByteWriter()
    ..raw(utf8Bytes('PQCR'))
    ..u8(2) // format version
    ..u8(0x01) // envelope
    ..u16(KdfAlgorithm.hkdfSha384.id)
    ..u16(aead.id)
    ..u16(0); // empty context
  final headerHash = ctx.sha384(w.toBytes());
  w.u16(2);
  for (final (i, kp) in [alice, bob].indexed) {
    final kem = kp.publicKey.algorithm;
    final encap = kemSchemeFor(
      kem,
      backend,
    ).encapsulate(kp.publicKey.bytes, ctx.randomBytes(32));
    final info =
        (ByteWriter()
              ..raw(utf8Bytes('post_quantum_crypto/v1/envelope/wrap'))
              ..u16(kem.id)
              ..raw(kp.keyId.bytes))
            .toBytes();
    final hpke = HpkeSuite(
      kemId: kem.id,
      kdfId: KdfAlgorithm.hkdfSha384.id,
      aeadId: aead.id,
      kdf: ctx.hkdfSha384,
      aead: ctx.aead(aead),
    ).keySchedule(encap.sharedSecret, info);
    w
      ..u16(kem.id)
      ..raw(kp.keyId.bytes)
      ..raw(encap.ciphertext)
      ..raw(hpke.seal(headerHash, deks[i]));
  }

  final h0 = ctx.sha384(w.toBytes());
  final committed = [
    for (final dek in deks)
      CommittedKey.derive(ctx, 'envelope', dek, h0, aead.keyLength),
  ];
  w.raw(committed[0].commitment);
  final payloadKeys = [for (final c in committed) c.key];
  final nonce = ctx.randomBytes(12);
  w.raw(nonce);
  final payloadAad = ctx.sha384(w.toBytes());
  final ct = _collidingCiphertext(
    payloadKeys[0],
    payloadKeys[1],
    nonce,
    payloadAad,
  );
  // The ciphertext really is valid under both payload keys.
  for (final k in payloadKeys) {
    expect(ctx.aead(aead).open(k, nonce, ct, payloadAad), isNotNull);
  }
  w.bytes32(ct);
  return w.toBytes();
}

void main() {
  final alice = engine.generateEncryptionKeyPair();
  final bob = engine.generateEncryptionKeyPair();

  test('the commitment rejects the second data key', () {
    final envelope = _salamander(alice, bob);
    // Alice holds the committed data key and decrypts.
    expect(
      engine.decryptBytes(envelope, privateKey: alice.privateKey),
      hasLength(32),
    );
    // Bob's tag is valid (checked in _salamander), but his data key does
    // not match the commitment.
    expect(
      () => engine.decryptBytes(envelope, privateKey: bob.privateKey),
      throwsA(isA<DecryptionFailedException>()),
    );
  });

  group('a modified commitment fails decryption', () {
    test('stream', () async {
      final parts = await engine
          .encryptStream(
            Stream.value(bytesOf('stream payload')),
            recipients: [alice.publicKey],
          )
          .toList();
      final header = parts.first;
      // The commitment is the last 32 bytes of the header.
      final tampered = [flip(header, header.length - 1), ...parts.skip(1)];
      await expectLater(
        engine
            .decryptStream(
              Stream.fromIterable(tampered),
              privateKey: alice.privateKey,
            )
            .drain<void>(),
        throwsA(isA<DecryptionFailedException>()),
      );
    });

    test('password-encrypted data', () {
      const password = 'commitment test password';
      final sealed = engine.encryptWithPassword(
        bytesOf('m'),
        password,
        parameters: const Argon2idParameters(
          memoryKiB: 8 * 1024,
          iterations: 1,
          parallelism: 1,
        ),
      );
      // ... | 32 commitment | 12 nonce | u32 length | 17 ciphertext+tag.
      final commitmentByte = sealed.length - 17 - 4 - 12 - 1;
      expect(
        () =>
            engine.decryptWithPassword(flip(sealed, commitmentByte), password),
        throwsA(isA<DecryptionFailedException>()),
      );
      expect(engine.decryptWithPassword(sealed, password), bytesOf('m'));
    });
  });
}
